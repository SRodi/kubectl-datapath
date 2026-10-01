package model

import (
	"encoding/json"
	"net/netip"
	"testing"
)

func TestObservationRoundTripPreservesIPv6AndCookie(t *testing.T) {
	want := Observation{
		SchemaVersion: SchemaVersion,
		Kind:          KindPacket,
		SrcAddr:       netip.MustParseAddr("2001:db8::1"),
		DstAddr:       netip.MustParseAddr("2001:db8::2"),
		Protocol:      6,
		NetnsCookie:   1<<48 + 7,
		TransportLost: 3,
		Confidence:    ConfidenceExact,
	}
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.SrcAddr != want.SrcAddr || got.DstAddr != want.DstAddr ||
		got.NetnsCookie != want.NetnsCookie || got.TransportLost != want.TransportLost {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
}

func TestTCPFlagsNameIncludesPayloadRelevantFlags(t *testing.T) {
	if got := TCPFlagsName(0x18); got != "PSH-ACK" {
		t.Fatalf("flags = %q", got)
	}
}

func TestObservationRoundTripPreservesVXLANTransit(t *testing.T) {
	want := Observation{
		SchemaVersion: SchemaVersion,
		Kind:          KindTransit,
		SrcAddr:       netip.MustParseAddr("10.244.0.5"),
		DstAddr:       netip.MustParseAddr("10.244.1.8"),
		Protocol:      17,
		Encapsulation: EncapsulationVXLAN,
		TunnelID:      1,
		OuterFamily:   4,
		OuterSrcAddr:  netip.MustParseAddr("172.18.0.2"),
		OuterDstAddr:  netip.MustParseAddr("172.18.0.3"),
		OuterSrcPort:  40000,
		OuterDstPort:  8472,
		Confidence:    ConfidenceCorrelated,
	}
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Encapsulation != want.Encapsulation || got.TunnelID != want.TunnelID ||
		got.OuterSrcAddr != want.OuterSrcAddr || got.OuterDstAddr != want.OuterDstAddr {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
}

func FuzzDecodeObservation(f *testing.F) {
	f.Add([]byte(`{"schema_version":1,"kind":"status","attachment_id":"source"}`))
	f.Add([]byte(`{"schema_version":1,"kind":"packet","src_addr":"10.0.0.1","dst_addr":"10.0.0.2"}`))
	f.Add([]byte(`{"schema_version":`))
	f.Fuzz(func(t *testing.T, data []byte) {
		observation, err := Decode(data)
		if err == nil {
			if err := observation.Validate(); err != nil {
				t.Fatalf("Decode returned invalid observation: %v", err)
			}
		}
	})
}
