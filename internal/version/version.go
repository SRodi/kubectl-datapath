package version

import "strings"

var Version = "dev"

func AgentImage() string {
	tag := strings.TrimPrefix(Version, "v")
	if tag == "" {
		tag = "dev"
	}
	return "ghcr.io/srodi/kubectl-datapath:" + tag
}
