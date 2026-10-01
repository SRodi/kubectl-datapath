package replay

import (
	"context"
	"os"
	"strings"
	"testing"
)

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
