package version

import "testing"

func TestAgentImageMatchesReleaseVersion(t *testing.T) {
	original := Version
	t.Cleanup(func() { Version = original })
	Version = "v1.2.3"
	if got := AgentImage(); got != "ghcr.io/srodi/kubectl-datapath:1.2.3" {
		t.Fatalf("agent image = %q", got)
	}
}
