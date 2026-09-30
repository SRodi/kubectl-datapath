package flow

import (
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/SRodi/kubectl-datapath/internal/model"
)

type Key struct {
	Protocol uint8
	AAddr    netip.Addr
	APort    uint16
	BAddr    netip.Addr
	BPort    uint16
}

func NewKey(observation model.Observation) Key {
	// Canonicalize endpoints so packets in both directions share one flow.
	aAddr, aPort := observation.SrcAddr, observation.SrcPort
	bAddr, bPort := observation.DstAddr, observation.DstPort
	if endpointString(aAddr, aPort) > endpointString(bAddr, bPort) {
		aAddr, bAddr = bAddr, aAddr
		aPort, bPort = bPort, aPort
	}
	return Key{Protocol: observation.Protocol, AAddr: aAddr, APort: aPort, BAddr: bAddr, BPort: bPort}
}

func endpointString(address netip.Addr, port uint16) string {
	return fmt.Sprintf("%s:%05d", address, port)
}

func (k Key) String() string {
	return fmt.Sprintf("%s %s:%d ↔ %s:%d", model.ProtocolName(k.Protocol), k.AAddr, k.APort, k.BAddr, k.BPort)
}

type Status string

const (
	StatusObserved   Status = "traffic observed"
	StatusRetransmit Status = "SYN retransmissions; no response observed"
	StatusResponse   Status = "both directions observed"
	StatusReset      Status = "reset observed"
	StatusIncomplete Status = "incomplete: event loss"
)

type Flow struct {
	Key            Key
	FirstSeen      time.Time
	LastSeen       time.Time
	Events         uint64
	ObservedB      uint64
	SYNs           uint64
	Lost           uint64
	Status         Status
	Confidence     model.Confidence
	FirstDirection model.Direction
	LastPacket     string
	SourceLabel    string
	DestLabel      string
	SourceEndpoint *model.Endpoint
	DestEndpoint   *model.Endpoint
}

type Tracker struct {
	flows map[Key]*Flow
}

func NewTracker() *Tracker {
	return &Tracker{flows: make(map[Key]*Flow)}
}

func (t *Tracker) Observe(observation model.Observation) {
	if observation.Kind != model.KindPacket {
		return
	}
	key := NewKey(observation)
	current, exists := t.flows[key]
	if !exists {
		current = &Flow{
			Key:            key,
			FirstSeen:      observation.WallTime,
			Status:         StatusObserved,
			Confidence:     observation.Confidence,
			FirstDirection: observation.Direction,
		}
		t.flows[key] = current
	}
	current.LastSeen = observation.WallTime
	current.Events++
	current.LastPacket = observation.PacketName()
	current.SourceLabel = observation.SrcLabel
	current.DestLabel = observation.DstLabel
	current.SourceEndpoint = observation.SrcEndpoint
	current.DestEndpoint = observation.DstEndpoint
	if observation.Protocol == 6 && observation.TCPFlags&0x02 != 0 && observation.TCPFlags&0x10 == 0 {
		current.SYNs++
	}
	if observation.Direction != model.DirectionUnknown && current.FirstDirection != model.DirectionUnknown &&
		observation.Direction != current.FirstDirection {
		current.ObservedB++
	}
	if observation.Protocol == 6 && observation.TCPFlags&0x04 != 0 {
		current.Status = StatusReset
	} else if current.ObservedB > 0 {
		current.Status = StatusResponse
	} else if current.SYNs > 1 {
		current.Status = StatusRetransmit
	}
	if observation.Lost > current.Lost {
		current.Lost = observation.Lost
		current.Status = StatusIncomplete
	}
}

func (t *Tracker) Flows() []Flow {
	flows := make([]Flow, 0, len(t.flows))
	for _, current := range t.flows {
		flows = append(flows, *current)
	}
	sort.Slice(flows, func(i, j int) bool {
		return flows[i].LastSeen.After(flows[j].LastSeen)
	})
	return flows
}
