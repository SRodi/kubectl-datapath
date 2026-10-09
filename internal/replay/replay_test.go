package replay

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/SRodi/kubectl-datapath/internal/model"
)

func TestReplayInterfaceMetadataAndLegacyStatus(t *testing.T) {
	input := `{"schema_version":1,"kind":"status","attachment_id":"source","interface":"nkh-test","interface_kind":"netkit","interface_mode":"L3","interface_master":"nk-vrf","interface_vrf_table":100,"diagnostics":[{"hook":"tcx/ingress","seen":7,"parse_rejected":2,"filtered":1,"emitted":3,"lost":1}]}
{"schema_version":1,"kind":"status","attachment_id":"legacy","interface":"veth-old"}`
	events, failures := Stream(context.Background(), strings.NewReader(input))
	var got []model.Observation
	for event := range events {
		got = append(got, event)
	}
	if err := <-failures; err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].InterfaceDescription() != "netkit (L3)" ||
		got[0].InterfaceMaster != "nk-vrf" || got[0].InterfaceVRFTable != 100 ||
		len(got[0].Diagnostics) != 1 || got[0].Diagnostics[0].Seen != 7 ||
		got[0].Diagnostics[0].Lost != 1 {
		t.Fatalf("metadata did not survive replay: %+v", got)
	}
	if got[1].InterfaceDescription() != "pod-facing interface" || got[1].Diagnostics != nil {
		t.Fatalf("legacy recording inferred unsupported metadata: %+v", got[1])
	}
}

func TestStreamRejectsUnsupportedSchema(t *testing.T) {
	_, errors := Stream(context.Background(), strings.NewReader(`{"schema_version":99,"kind":"status"}`))
	if err := <-errors; err == nil {
		t.Fatal("expected schema error")
	}
}

func TestTransportLossFixture(t *testing.T) {
	file, err := os.Open("../../testdata/transport-loss.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	observations, errors := Stream(context.Background(), file)
	var transportLost uint64
	for observation := range observations {
		transportLost = observation.TransportLost
	}
	if err := <-errors; err != nil {
		t.Fatal(err)
	}
	if transportLost != 2 {
		t.Fatalf("transport loss = %d, want 2", transportLost)
	}
}

func TestStreamRejectsTruncatedObservation(t *testing.T) {
	_, errors := Stream(context.Background(), strings.NewReader(
		`{"schema_version":1,"kind":"packet","src_addr":"10.0.0.1"`,
	))
	if err := <-errors; err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("error = %v", err)
	}
}
