package agent

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

type Capability struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Detail    string `json:"detail"`
}

type Compatibility struct {
	Kernel       string       `json:"kernel"`
	Capabilities []Capability `json:"capabilities"`
}

func ProbeLocal() Compatibility {
	result := Compatibility{Kernel: runtime.GOOS + "/" + runtime.GOARCH}
	var uts unix.Utsname
	if err := unix.Uname(&uts); err == nil {
		result.Kernel = charsToString(uts.Release[:])
	}
	result.Capabilities = []Capability{
		fileCapability("kernel BTF", "/sys/kernel/btf/vmlinux"),
		fileCapability("cgroup v2", "/sys/fs/cgroup/cgroup.controllers"),
		fileCapability("BPF filesystem", "/sys/fs/bpf"),
		{
			Name:      "TCX strategy",
			Available: kernelAtLeast(result.Kernel, 6, 6),
			Detail:    "requires Linux 6.6+ and CAP_BPF/CAP_NET_ADMIN at runtime",
		},
	}
	return result
}

func fileCapability(name, path string) Capability {
	_, err := os.Stat(path)
	return Capability{Name: name, Available: err == nil, Detail: path}
}

func charsToString(chars []byte) string {
	end := 0
	for end < len(chars) && chars[end] != 0 {
		end++
	}
	return string(chars[:end])
}

func kernelAtLeast(release string, major, minor int) bool {
	var gotMajor, gotMinor int
	if _, err := fmt.Sscanf(release, "%d.%d", &gotMajor, &gotMinor); err != nil {
		return false
	}
	return gotMajor > major || gotMajor == major && gotMinor >= minor
}
