package tcx

import (
	"fmt"

	"github.com/SRodi/kubectl-datapath/internal/model"
)

func emptyDiagnostics(hooks []string) []model.HookDiagnostics {
	result := make([]model.HookDiagnostics, len(hooks))
	for i, hook := range hooks {
		result[i].Hook = hook
	}
	return result
}

func (s *session) readDiagnostics() ([]model.HookDiagnostics, error) {
	result := emptyDiagnostics(s.packetHooks)
	for i := range result {
		key := uint32(i)
		var perCPU []bpfPacketCounters
		if err := s.objects.PacketCounters.Lookup(&key, &perCPU); err != nil {
			return nil, fmt.Errorf("read %s packet counters: %w", result[i].Hook, err)
		}
		for _, counters := range perCPU {
			result[i].Seen += counters.Seen
			result[i].ParseRejected += counters.ParseRejected
			result[i].Filtered += counters.Filtered
			result[i].Emitted += counters.Emitted
			result[i].Lost += counters.Lost
		}
	}
	return result, nil
}
