// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to, __u32 len) = (void *)BPF_FUNC_skb_load_bytes;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)BPF_FUNC_get_current_cgroup_id;
static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)BPF_FUNC_probe_read_user;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)BPF_FUNC_ringbuf_reserve;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)BPF_FUNC_ringbuf_submit;

char __license[] SEC("license") = "GPL";

enum direction {
	DIRECTION_INGRESS = 1,
	DIRECTION_EGRESS = 2,
};

enum event_kind {
	EVENT_PACKET = 1,
	EVENT_CONNECT = 2,
	EVENT_TRANSIT = 3,
};

enum capture_mode {
	CAPTURE_POD = 0,
	CAPTURE_TRANSIT = 1,
	CAPTURE_POD_FILTERED = 2,
};

enum encapsulation {
	ENCAPSULATION_NATIVE = 1,
	ENCAPSULATION_VXLAN = 2,
};

/* Field order and widths define the ring-buffer ABI consumed by bpf2go's
 * generated bpfEvent. */
struct event {
	__u64 monotonic_ns;
	__u64 sequence;
	__u64 lost;
	__u64 cgroup_id;
	__u32 ifindex;
	__u32 packet_length;
	__u32 tcp_sequence;
	__u32 tcp_ack;
	__u16 src_port;
	__u16 dst_port;
	__u8 family;
	__u8 protocol;
	__u8 direction;
	__u8 tcp_flags;
	__u8 kind;
	__u8 src_addr[16];
	__u8 dst_addr[16];
	__u32 tunnel_id;
	__u16 outer_src_port;
	__u16 outer_dst_port;
	__u8 outer_family;
	__u8 encapsulation;
	__u8 outer_src_addr[16];
	__u8 outer_dst_addr[16];
};

struct event *unused_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} sequences SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} losses SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, __u8);
} target_cgroups SEC(".maps");

struct address_key {
	__u8 family;
	__u8 addr[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct address_key);
	__type(value, __u8);
} flow_addresses SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} capture_modes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct event);
} scratch_events SEC(".maps");

struct eth_header {
	__u8 dst[6];
	__u8 src[6];
	__be16 protocol;
};

struct vlan_header {
	__be16 tci;
	__be16 encapsulated_protocol;
};

struct ipv4_header {
	__u8 version_ihl;
	__u8 tos;
	__be16 total_length;
	__be16 id;
	__be16 fragment_offset;
	__u8 ttl;
	__u8 protocol;
	__be16 checksum;
	__u8 src[4];
	__u8 dst[4];
};

struct ipv6_header {
	__be32 version_flow;
	__be16 payload_length;
	__u8 next_header;
	__u8 hop_limit;
	__u8 src[16];
	__u8 dst[16];
};

struct ports {
	__be16 src;
	__be16 dst;
};

struct tcp_header {
	__be16 src;
	__be16 dst;
	__be32 sequence;
	__be32 ack;
	__u8 data_offset;
	__u8 flags;
};

struct vxlan_header {
	__u8 flags;
	__u8 reserved1[3];
	__u8 vni[3];
	__u8 reserved2;
};

struct sockaddr_header {
	__u16 family;
	__u16 port;
};

struct sockaddr_in6_event {
	__u16 family;
	__be16 port;
	__be32 flowinfo;
	__u8 addr[16];
	__u32 scope_id;
};

static __always_inline __u16 swap16(__u16 value)
{
	return __builtin_bswap16(value);
}

static __always_inline __u32 swap32(__u32 value)
{
	return __builtin_bswap32(value);
}

static __always_inline void copy_addr(__u8 dst[16], const __u8 *src, int length)
{
#pragma unroll
	for (int i = 0; i < 16; i++)
		dst[i] = i < length ? src[i] : 0;
}

static __always_inline void submit(struct event *temporary)
{
	/* Sequence numbers advance for every attempted event; reservation
	 * failures increment cumulative loss instead. */
	__u32 zero = 0;
	__u64 *sequence = bpf_map_lookup_elem(&sequences, &zero);
	__u64 *lost = bpf_map_lookup_elem(&losses, &zero);
	if (sequence)
		temporary->sequence = __sync_fetch_and_add(sequence, 1) + 1;
	if (lost)
		temporary->lost = *lost;

	struct event *output = bpf_ringbuf_reserve(&events, sizeof(*output), 0);
	if (!output) {
		if (lost)
			__sync_fetch_and_add(lost, 1);
		return;
	}
	*output = *temporary;
	bpf_ringbuf_submit(output, 0);
}

static __always_inline int selected_address(__u8 family, __u8 addr[16])
{
	struct address_key key = {.family = family};
	copy_addr(key.addr, addr, 16);
	return bpf_map_lookup_elem(&flow_addresses, &key) != 0;
}

static __always_inline int selected_flow(struct event *event)
{
	/* This is an endpoint-pair allowlist: both flow addresses must be configured. */
	return selected_address(event->family, event->src_addr) &&
	       selected_address(event->family, event->dst_addr);
}

static __always_inline int parse_transport(struct __sk_buff *skb, __u32 offset,
					   struct event *event)
{
	if (event->protocol == IPPROTO_TCP) {
		struct tcp_header tcp = {};
		if (bpf_skb_load_bytes(skb, offset, &tcp, sizeof(tcp)) < 0)
			return -1;
		event->src_port = swap16(tcp.src);
		event->dst_port = swap16(tcp.dst);
		event->tcp_sequence = swap32(tcp.sequence);
		event->tcp_ack = swap32(tcp.ack);
		event->tcp_flags = tcp.flags;
	} else if (event->protocol == IPPROTO_UDP) {
		struct ports udp = {};
		if (bpf_skb_load_bytes(skb, offset, &udp, sizeof(udp)) < 0)
			return -1;
		event->src_port = swap16(udp.src);
		event->dst_port = swap16(udp.dst);
	} else {
		return -1;
	}
	return 0;
}

static __always_inline int parse_ip(struct __sk_buff *skb, __u32 offset,
				    __u16 protocol, struct event *event,
				    __u32 *transport_offset)
{
	/* Transport must follow the base IP header; non-initial fragments and
	 * IPv6 extension chains are unsupported. */
	if (protocol == ETH_P_IP) {
		struct ipv4_header ip = {};
		if (bpf_skb_load_bytes(skb, offset, &ip, sizeof(ip)) < 0)
			return -1;
		__u32 header_length = (ip.version_ihl & 0x0f) * 4;
		if (header_length < sizeof(ip) ||
		    (swap16(ip.fragment_offset) & 0x1fff) != 0)
			return -1;
		event->family = 4;
		event->protocol = ip.protocol;
		copy_addr(event->src_addr, ip.src, 4);
		copy_addr(event->dst_addr, ip.dst, 4);
		*transport_offset = offset + header_length;
		return 0;
	}
	if (protocol == ETH_P_IPV6) {
		struct ipv6_header ip = {};
		if (bpf_skb_load_bytes(skb, offset, &ip, sizeof(ip)) < 0)
			return -1;
		event->family = 6;
		event->protocol = ip.next_header;
		copy_addr(event->src_addr, ip.src, 16);
		copy_addr(event->dst_addr, ip.dst, 16);
		*transport_offset = offset + sizeof(ip);
		return 0;
	}
	return -1;
}

static __always_inline int emit_transit(struct __sk_buff *skb, __u8 direction)
{
	struct eth_header ethernet = {};
	if (bpf_skb_load_bytes(skb, 0, &ethernet, sizeof(ethernet)) < 0)
		return TC_ACT_UNSPEC;
	__u32 offset = sizeof(ethernet);
	__u16 protocol = swap16(ethernet.protocol);
	if (protocol == ETH_P_8021Q || protocol == ETH_P_8021AD) {
		struct vlan_header vlan = {};
		if (bpf_skb_load_bytes(skb, offset, &vlan, sizeof(vlan)) < 0)
			return TC_ACT_UNSPEC;
		protocol = swap16(vlan.encapsulated_protocol);
		offset += sizeof(vlan);
	}

	__u32 outer_key = 0;
	struct event *outer = bpf_map_lookup_elem(&scratch_events, &outer_key);
	if (!outer)
		return TC_ACT_UNSPEC;
	*outer = (struct event){};
	__u32 transport_offset = 0;
	if (parse_ip(skb, offset, protocol, outer, &transport_offset) < 0)
		return TC_ACT_UNSPEC;

	if (outer->protocol == IPPROTO_UDP) {
		struct ports udp = {};
		if (bpf_skb_load_bytes(skb, transport_offset, &udp, sizeof(udp)) < 0)
			return TC_ACT_UNSPEC;
		__u16 src_port = swap16(udp.src);
		__u16 dst_port = swap16(udp.dst);
		/* Common VXLAN ports are only candidates; require the I flag and
		 * selected inner flow before emitting. */
		if (src_port == 8472 || dst_port == 8472 ||
		    src_port == 4789 || dst_port == 4789) {
			struct vxlan_header vxlan = {};
			__u32 vxlan_offset = transport_offset + 8;
			if (bpf_skb_load_bytes(skb, vxlan_offset, &vxlan, sizeof(vxlan)) < 0 ||
			    (vxlan.flags & 0x08) == 0)
				return TC_ACT_UNSPEC;
			struct eth_header inner_eth = {};
			__u32 inner_offset = vxlan_offset + sizeof(vxlan);
			if (bpf_skb_load_bytes(skb, inner_offset, &inner_eth, sizeof(inner_eth)) < 0)
				return TC_ACT_UNSPEC;
			inner_offset += sizeof(inner_eth);
			__u16 inner_protocol = swap16(inner_eth.protocol);
			if (inner_protocol == ETH_P_8021Q || inner_protocol == ETH_P_8021AD) {
				struct vlan_header vlan = {};
				if (bpf_skb_load_bytes(skb, inner_offset, &vlan, sizeof(vlan)) < 0)
					return TC_ACT_UNSPEC;
				inner_protocol = swap16(vlan.encapsulated_protocol);
				inner_offset += sizeof(vlan);
			}
			__u32 event_key = 1;
			struct event *event = bpf_map_lookup_elem(&scratch_events, &event_key);
			if (!event)
				return TC_ACT_UNSPEC;
			*event = (struct event){};
			__u32 inner_transport = 0;
			if (parse_ip(skb, inner_offset, inner_protocol, event, &inner_transport) < 0 ||
			    parse_transport(skb, inner_transport, event) < 0 ||
			    !selected_flow(event))
				return TC_ACT_UNSPEC;
			event->kind = EVENT_TRANSIT;
			event->monotonic_ns = bpf_ktime_get_ns();
			event->ifindex = skb->ifindex;
			event->packet_length = skb->len;
			event->direction = direction;
			event->encapsulation = ENCAPSULATION_VXLAN;
			event->outer_family = outer->family;
			copy_addr(event->outer_src_addr, outer->src_addr, 16);
			copy_addr(event->outer_dst_addr, outer->dst_addr, 16);
			event->outer_src_port = src_port;
			event->outer_dst_port = dst_port;
			event->tunnel_id = ((__u32)vxlan.vni[0] << 16) |
					  ((__u32)vxlan.vni[1] << 8) |
					  vxlan.vni[2];
			submit(event);
			return TC_ACT_UNSPEC;
		}
	}

	if (parse_transport(skb, transport_offset, outer) < 0 ||
	    !selected_flow(outer))
		return TC_ACT_UNSPEC;
	outer->kind = EVENT_TRANSIT;
	outer->monotonic_ns = bpf_ktime_get_ns();
	outer->ifindex = skb->ifindex;
	outer->packet_length = skb->len;
	outer->direction = direction;
	outer->encapsulation = ENCAPSULATION_NATIVE;
	submit(outer);
	return TC_ACT_UNSPEC;
}

static __always_inline int emit(struct __sk_buff *skb, __u8 direction)
{
	__u32 zero = 0;
	__u8 *mode = bpf_map_lookup_elem(&capture_modes, &zero);
	if (mode && *mode == CAPTURE_TRANSIT)
		return emit_transit(skb, direction);

	struct eth_header ethernet = {};
	if (bpf_skb_load_bytes(skb, 0, &ethernet, sizeof(ethernet)) < 0)
		return TC_ACT_UNSPEC;

	__u32 offset = sizeof(ethernet);
	__u16 protocol = swap16(ethernet.protocol);
	if (protocol == ETH_P_8021Q || protocol == ETH_P_8021AD) {
		struct vlan_header vlan = {};
		if (bpf_skb_load_bytes(skb, offset, &vlan, sizeof(vlan)) < 0)
			return TC_ACT_UNSPEC;
		protocol = swap16(vlan.encapsulated_protocol);
		offset += sizeof(vlan);
	}

	__u32 event_key = 0;
	struct event *temporary = bpf_map_lookup_elem(&scratch_events, &event_key);
	if (!temporary)
		return TC_ACT_UNSPEC;
	*temporary = (struct event){};
	temporary->monotonic_ns = bpf_ktime_get_ns();
	temporary->kind = EVENT_PACKET;
	temporary->ifindex = skb->ifindex;
	temporary->packet_length = skb->len;
	temporary->direction = direction;

	if (protocol == ETH_P_IP) {
		struct ipv4_header ip = {};
		if (bpf_skb_load_bytes(skb, offset, &ip, sizeof(ip)) < 0)
			return TC_ACT_UNSPEC;
		__u32 header_length = (ip.version_ihl & 0x0f) * 4;
		if (header_length < sizeof(ip))
			return TC_ACT_UNSPEC;
		/* Non-first fragments do not contain a transport header. */
		if ((swap16(ip.fragment_offset) & 0x1fff) != 0)
			return TC_ACT_UNSPEC;
		temporary->family = 4;
		temporary->protocol = ip.protocol;
		copy_addr(temporary->src_addr, ip.src, 4);
		copy_addr(temporary->dst_addr, ip.dst, 4);
		offset += header_length;
	} else if (protocol == ETH_P_IPV6) {
		struct ipv6_header ip = {};
		if (bpf_skb_load_bytes(skb, offset, &ip, sizeof(ip)) < 0)
			return TC_ACT_UNSPEC;
		temporary->family = 6;
		temporary->protocol = ip.next_header;
		copy_addr(temporary->src_addr, ip.src, 16);
		copy_addr(temporary->dst_addr, ip.dst, 16);
		offset += sizeof(ip);
	} else {
		return TC_ACT_UNSPEC;
	}

	if (temporary->protocol == IPPROTO_TCP || temporary->protocol == IPPROTO_UDP) {
		if (parse_transport(skb, offset, temporary) < 0)
			return TC_ACT_UNSPEC;
	} else if (temporary->protocol != IPPROTO_ICMP && temporary->protocol != IPPROTO_ICMPV6) {
		return TC_ACT_UNSPEC;
	}
	if (mode && *mode == CAPTURE_POD_FILTERED && !selected_flow(temporary))
		return TC_ACT_UNSPEC;

	submit(temporary);
	return TC_ACT_UNSPEC;
}

SEC("tc")
int observe_ingress(struct __sk_buff *skb)
{
	return emit(skb, DIRECTION_INGRESS);
}

SEC("tc")
int observe_egress(struct __sk_buff *skb)
{
	return emit(skb, DIRECTION_EGRESS);
}

SEC("fentry/__sys_connect")
int observe_connect(__u64 *ctx)
{
	__u64 cgroup_id = bpf_get_current_cgroup_id();
	__u8 *enabled = bpf_map_lookup_elem(&target_cgroups, &cgroup_id);
	if (!enabled)
		return 0;

	const void *address = (const void *)ctx[1];
	struct sockaddr_header header = {};
	if (bpf_probe_read_user(&header, sizeof(header), address) < 0)
		return 0;

	__u32 event_key = 0;
	struct event *temporary = bpf_map_lookup_elem(&scratch_events, &event_key);
	if (!temporary)
		return 0;
	*temporary = (struct event){};
	temporary->kind = EVENT_CONNECT;
	temporary->monotonic_ns = bpf_ktime_get_ns();
	temporary->cgroup_id = cgroup_id;
	if (header.family == 2) {
		struct {
			__u16 family;
			__be16 port;
			__u8 addr[4];
			__u8 padding[8];
		} ipv4 = {};
		if (bpf_probe_read_user(&ipv4, sizeof(ipv4), address) < 0)
			return 0;
		temporary->family = 4;
		temporary->dst_port = swap16(ipv4.port);
		copy_addr(temporary->dst_addr, ipv4.addr, 4);
	} else if (header.family == 10) {
		struct sockaddr_in6_event ipv6 = {};
		if (bpf_probe_read_user(&ipv6, sizeof(ipv6), address) < 0)
			return 0;
		temporary->family = 6;
		temporary->dst_port = swap16(ipv6.port);
		copy_addr(temporary->dst_addr, ipv6.addr, 16);
	} else {
		return 0;
	}
	submit(temporary);
	return 0;
}
