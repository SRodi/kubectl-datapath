package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/SRodi/kubectl-datapath/internal/capture"
	"github.com/SRodi/kubectl-datapath/internal/capture/tcx"
)

type CaptureStrategies struct {
	TCX     capture.Strategy
	Classic capture.Strategy
}

func NewCaptureStrategies() CaptureStrategies {
	return CaptureStrategies{
		TCX:     tcx.Strategy{},
		Classic: tcx.ClassicStrategy{},
	}
}

func (s CaptureStrategies) Open(
	ctx context.Context,
	target capture.Target,
) (capture.Session, error) {
	session, err := s.TCX.Open(ctx, target)
	if err == nil {
		return session, nil
	}
	if !tcxUnsupported(err) {
		return nil, err
	}
	fallback, fallbackErr := s.Classic.Open(ctx, target)
	if fallbackErr != nil {
		return nil, fmt.Errorf("TCX unavailable: %v; classic TC fallback failed: %w", err, fallbackErr)
	}
	return fallback, nil
}

func tcxUnsupported(err error) bool {
	return strings.Contains(err.Error(), "attach TCX") &&
		(errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EINVAL))
}
