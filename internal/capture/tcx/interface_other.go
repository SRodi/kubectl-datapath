//go:build !linux

package tcx

import (
	"fmt"

	"github.com/SRodi/kubectl-datapath/internal/capture"
)

func resolveInterface(target *capture.Target) error {
	return fmt.Errorf("interface discovery for %q requires Linux", target.Interface)
}
