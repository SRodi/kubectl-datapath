package model

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

const SchemaVersion = 1

type Confidence string

const (
	ConfidenceExact        Confidence = "exact"
	ConfidenceCorrelated   Confidence = "correlated"
	ConfidenceRelated      Confidence = "related"
	ConfidenceUnattributed Confidence = "unattributed"
)

type Kind string

const (
	KindPacket       Kind = "packet"
	KindTransit      Kind = "transit"
	KindConnect      Kind = "connect"
	KindTraceContext Kind = "trace_context"
	KindDropEvidence Kind = "drop_evidence"
	KindStatus       Kind = "status"
)

type Encapsulation string

const (
	EncapsulationNative Encapsulation = "native"
	EncapsulationVXLAN  Encapsulation = "vxlan"
)

type EndpointKind string

const (
	EndpointPod     EndpointKind = "Pod"
	EndpointService EndpointKind = "Service"
	EndpointIP      EndpointKind = "IP"
)

type Endpoint struct {
	Kind      EndpointKind `json:"kind"`
	Namespace string       `json:"namespace,omitempty"`
	Name      string       `json:"name,omitempty"`
	Node      string       `json:"node,omitempty"`
	Address   netip.Addr   `json:"address,omitempty"`
	Port      uint16       `json:"port,omitempty"`
	PortName  string       `json:"port_name,omitempty"`
}

func (e Endpoint) DisplayName() string {
	if e.Name == "" {
		return e.Address.String()
	}
	if e.Namespace == "" {
		return e.Name
	}
	return e.Name + "." + e.Namespace
}

type TraceMode string

const (
	TraceModePod     TraceMode = "pod"
	TraceModeService TraceMode = "service"
)

type TraceContext struct {
	Source               Endpoint            `json:"source"`
	Mode                 TraceMode           `json:"mode,omitempty"`
	Destination          *Endpoint           `json:"destination,omitempty"`
	Service              *Endpoint           `json:"service,omitempty"`
	Frontends            []Endpoint          `json:"frontends,omitempty"`
	Backends             []Endpoint          `json:"backends,omitempty"`
	InstrumentedBackends []Endpoint          `json:"instrumented_backends,omitempty"`
	BackendCoverageKnown bool                `json:"backend_coverage_known,omitempty"`
	DNSService           *Endpoint           `json:"dns_service,omitempty"`
	DNSFrontends         []Endpoint          `json:"dns_frontends,omitempty"`
	DNSBackends          []Endpoint          `json:"dns_backends,omitempty"`
	NodeTransit          *NodeTransitContext `json:"node_transit,omitempty"`
	Policies             []PolicyContext     `json:"policies,omitempty"`
}

type NodeTransitContext struct {
	SourceNode       string   `json:"source_node"`
	DestinationNodes []string `json:"destination_nodes"`
	Unavailable      []string `json:"unavailable,omitempty"`
}

type PolicyContext struct {
	Namespace string   `json:"namespace"`
	Name      string   `json:"name"`
	Scope     string   `json:"scope"`
	Pods      []string `json:"pods,omitempty"`
	DenyAll   bool     `json:"deny_all,omitempty"`
}

type Direction string

const (
	DirectionIngress Direction = "ingress"
	DirectionEgress  Direction = "egress"
	DirectionUnknown Direction = "unknown"
)

type Observation struct {
	SchemaVersion int           `json:"schema_version"`
	Kind          Kind          `json:"kind"`
	SessionID     string        `json:"session_id,omitempty"`
	AttachmentID  string        `json:"attachment_id,omitempty"`
	Side          string        `json:"side,omitempty"`
	Node          string        `json:"node,omitempty"`
	Point         string        `json:"point,omitempty"`
	Direction     Direction     `json:"direction,omitempty"`
	MonotonicNS   uint64        `json:"monotonic_ns,omitempty"`
	WallTime      time.Time     `json:"wall_time,omitempty"`
	Sequence      uint64        `json:"sequence,omitempty"`
	Lost          uint64        `json:"lost,omitempty"`
	Family        uint8         `json:"family,omitempty"`
	Protocol      uint8         `json:"protocol,omitempty"`
	SrcAddr       netip.Addr    `json:"src_addr,omitempty"`
	DstAddr       netip.Addr    `json:"dst_addr,omitempty"`
	SrcPort       uint16        `json:"src_port,omitempty"`
	DstPort       uint16        `json:"dst_port,omitempty"`
	PacketLength  uint32        `json:"packet_length,omitempty"`
	TCPFlags      uint8         `json:"tcp_flags,omitempty"`
	TCPSequence   uint32        `json:"tcp_sequence,omitempty"`
	TCPAck        uint32        `json:"tcp_ack,omitempty"`
	Encapsulation Encapsulation `json:"encapsulation,omitempty"`
	TunnelID      uint32        `json:"tunnel_id,omitempty"`
	OuterFamily   uint8         `json:"outer_family,omitempty"`
	OuterSrcAddr  netip.Addr    `json:"outer_src_addr,omitempty"`
	OuterDstAddr  netip.Addr    `json:"outer_dst_addr,omitempty"`
	OuterSrcPort  uint16        `json:"outer_src_port,omitempty"`
	OuterDstPort  uint16        `json:"outer_dst_port,omitempty"`
	NetnsCookie   uint64        `json:"netns_cookie,omitempty"`
	CgroupID      uint64        `json:"cgroup_id,omitempty"`
	CgroupIDs     []uint64      `json:"cgroup_ids,omitempty"`
	Hooks         []string      `json:"hooks,omitempty"`
	Interface     string        `json:"interface,omitempty"`
	InterfaceIdx  uint32        `json:"interface_index,omitempty"`
	Confidence    Confidence    `json:"confidence,omitempty"`
	Evidence      []string      `json:"evidence,omitempty"`
	SrcEndpoint   *Endpoint     `json:"src_endpoint,omitempty"`
	DstEndpoint   *Endpoint     `json:"dst_endpoint,omitempty"`
	Trace         *TraceContext `json:"trace,omitempty"`
	SrcLabel      string        `json:"src_label,omitempty"`
	DstLabel      string        `json:"dst_label,omitempty"`
	Message       string        `json:"message,omitempty"`
}

func (o Observation) Validate() error {
	if o.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema version %d", o.SchemaVersion)
	}
	switch o.Kind {
	case KindPacket, KindTransit, KindConnect, KindTraceContext, KindDropEvidence, KindStatus:
	default:
		return fmt.Errorf("unsupported observation kind %q", o.Kind)
	}
	if (o.Kind == KindPacket || o.Kind == KindTransit) && (!o.SrcAddr.IsValid() || !o.DstAddr.IsValid()) {
		return fmt.Errorf("%s observation requires valid source and destination addresses", o.Kind)
	}
	if o.Kind == KindConnect && !o.DstAddr.IsValid() {
		return fmt.Errorf("connect observation requires a valid destination address")
	}
	if o.Kind == KindTraceContext && o.Trace == nil {
		return fmt.Errorf("trace context observation requires trace metadata")
	}
	return nil
}

func Decode(data []byte) (Observation, error) {
	var observation Observation
	if err := json.Unmarshal(data, &observation); err != nil {
		return Observation{}, fmt.Errorf("decode observation: %w", err)
	}
	if err := observation.Validate(); err != nil {
		return Observation{}, err
	}
	return observation, nil
}

func ProtocolName(protocol uint8) string {
	switch protocol {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 58:
		return "ICMPv6"
	default:
		return fmt.Sprintf("IP/%d", protocol)
	}
}

func TCPFlagsName(flags uint8) string {
	var names []string
	if flags&0x01 != 0 {
		names = append(names, "FIN")
	}
	if flags&0x02 != 0 {
		names = append(names, "SYN")
	}
	if flags&0x04 != 0 {
		names = append(names, "RST")
	}
	if flags&0x08 != 0 {
		names = append(names, "PSH")
	}
	if flags&0x10 != 0 {
		names = append(names, "ACK")
	}
	if len(names) == 0 {
		return fmt.Sprintf("flags=0x%02x", flags)
	}
	return strings.Join(names, "-")
}

func (o Observation) PacketName() string {
	if o.Protocol == 6 {
		return TCPFlagsName(o.TCPFlags)
	}
	return ProtocolName(o.Protocol)
}
