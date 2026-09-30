package agent

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type Target struct {
	Interface string
	CgroupIDs []uint64
}

func TargetForPodUID(procRoot, cgroupRoot, podUID string) (Target, error) {
	// Resolve the host veth through one Pod process, but collect every matching cgroup for connect capture.
	pids, err := findPodPIDs(procRoot, podUID)
	if err != nil {
		return Target{}, err
	}
	pid := pids[0]
	iflinkPath := filepath.Join(procRoot, strconv.Itoa(pid), "root", "sys", "class", "net", "eth0", "iflink")
	data, err := os.ReadFile(iflinkPath)
	if err != nil {
		return Target{}, fmt.Errorf("read target iflink: %w", err)
	}
	ifindex, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return Target{}, fmt.Errorf("parse target iflink: %w", err)
	}
	iface, err := net.InterfaceByIndex(ifindex)
	if err != nil {
		return Target{}, fmt.Errorf("resolve host interface %d: %w", ifindex, err)
	}
	cgroupIDs := make(map[uint64]struct{})
	for _, candidate := range pids {
		cgroupPath, err := podCgroupPath(procRoot, candidate)
		if err != nil {
			continue
		}
		info, err := os.Stat(filepath.Join(cgroupRoot, strings.TrimPrefix(filepath.Clean("/"+cgroupPath), "/")))
		if err != nil {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if ok {
			cgroupIDs[stat.Ino] = struct{}{}
		}
	}
	if len(cgroupIDs) == 0 {
		return Target{}, fmt.Errorf("resolve target Pod cgroup identifiers")
	}
	target := Target{Interface: iface.Name, CgroupIDs: make([]uint64, 0, len(cgroupIDs))}
	for cgroupID := range cgroupIDs {
		target.CgroupIDs = append(target.CgroupIDs, cgroupID)
	}
	return target, nil
}

func podCgroupPath(procRoot string, pid int) (string, error) {
	file, err := os.Open(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return "", fmt.Errorf("open target cgroup: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ":", 3)
		if len(parts) == 3 && parts[0] == "0" && parts[1] == "" {
			return parts[2], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read target cgroup: %w", err)
	}
	return "", fmt.Errorf("target process is not in a cgroup v2 hierarchy")
}

func findPodPIDs(procRoot, podUID string) ([]int, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("read proc root: %w", err)
	}
	dashed := "pod" + podUID
	underscored := "pod" + strings.ReplaceAll(podUID, "-", "_")
	var pids []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		file, err := os.Open(filepath.Join(procRoot, entry.Name(), "cgroup"))
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		found := false
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), dashed) || strings.Contains(scanner.Text(), underscored) {
				found = true
				break
			}
		}
		file.Close()
		if found {
			pids = append(pids, pid)
		}
	}
	if len(pids) == 0 {
		return nil, fmt.Errorf("no process found for Pod UID %s", podUID)
	}
	return pids, nil
}
