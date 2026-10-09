//go:build !linux

package tcx

import (
	"context"
	"fmt"

	"github.com/SRodi/kubectl-datapath/internal/capture"
)

type ClassicStrategy struct{}

func (ClassicStrategy) Name() string { return "tc-clsact" }

func (ClassicStrategy) Open(context.Context, capture.Target) (capture.Session, error) {
	return nil, fmt.Errorf("classic TC fallback is only supported on Linux")
}
