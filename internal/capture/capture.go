package capture

import (
	"context"
	"net/netip"

	"github.com/SRodi/kubectl-datapath/internal/model"
)

type Target struct {
	Interface      string
	InterfaceIndex uint32
	CgroupIDs      []uint64
	CaptureConnect bool
	SessionID      string
	AttachID       string
	Side           string
	Node           string
	Transit        bool
	FlowAddresses  []netip.Addr
}

type Session interface {
	Events() <-chan model.Observation
	Errors() <-chan error
	Close() error
}

type Strategy interface {
	Name() string
	Open(context.Context, Target) (Session, error)
}
