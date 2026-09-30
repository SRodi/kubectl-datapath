package replay

import (
	"context"
	"strings"
	"testing"
)

func TestStreamRejectsUnsupportedSchema(t *testing.T) {
	_, errors := Stream(context.Background(), strings.NewReader(`{"schema_version":99,"kind":"status"}`))
	if err := <-errors; err == nil {
		t.Fatal("expected schema error")
	}
}
