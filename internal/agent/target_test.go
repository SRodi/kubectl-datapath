package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPodCgroupPathReadsUnifiedHierarchy(t *testing.T) {
	root := t.TempDir()
	pid := 42
	path := filepath.Join(root, "42")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "7:cpu:/legacy\n0::/kubepods.slice/pod123/container\n"
	if err := os.WriteFile(filepath.Join(path, "cgroup"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := podCgroupPath(root, pid)
	if err != nil {
		t.Fatal(err)
	}
	if got != "/kubepods.slice/pod123/container" {
		t.Fatalf("path = %q", got)
	}
}
