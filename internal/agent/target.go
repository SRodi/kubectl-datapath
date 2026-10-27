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

type TargetResolver struct {
	procRoot   string
	cgroupRoot string
	pidsByUID  map[string][]int
	targets    map[string]Target
}

func NewTargetResolver(procRoot, cgroupRoot string, podUIDs []string) (*TargetResolver, error) {
	wanted := make(map[string]string, len(podUIDs)*2)
	for _, podUID := range podUIDs {
		if podUID == "" {
			continue
		}
		wanted["pod"+podUID] = podUID
		wanted["pod"+strings.ReplaceAll(podUID, "-", "_")] = podUID
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("read proc root: %w", err)
	}
	pidsByUID := make(map[string][]int, len(podUIDs))
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		file, err := os.Open(filepath.Join(procRoot, entry.Name(), "cgroup"))
		if err != nil {
			continue
		}
		matches := make(map[string]struct{})
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			for needle, podUID := range wanted {
				if strings.Contains(line, needle) {
					matches[podUID] = struct{}{}
				}
			}
		}
		scanErr := scanner.Err()
		closeErr := file.Close()
		if scanErr != nil || closeErr != nil {
			continue
		}
		for podUID := range matches {
			pidsByUID[podUID] = append(pidsByUID[podUID], pid)
		}
	}
	return &TargetResolver{
		procRoot: procRoot, cgroupRoot: cgroupRoot,
		pidsByUID: pidsByUID, targets: make(map[string]Target, len(podUIDs)),
	}, nil
}

func (r *TargetResolver) TargetForPodUID(podUID string) (Target, error) {
	if target, ok := r.targets[podUID]; ok {
		return target, nil
	}
	pids := r.pidsByUID[podUID]
	if len(pids) == 0 {
		return Target{}, fmt.Errorf("no process found for Pod UID %s", podUID)
	}
	// Resolve the host peer through one Pod process, but collect every matching cgroup.
	pid := pids[0]
	podInterface, err := podPrimaryInterface(r.procRoot, pid)
	if err != nil {
		return Target{}, err
	}
	iflinkPath := filepath.Join(
		r.procRoot, strconv.Itoa(pid), "root", "sys", "class", "net", podInterface, "iflink",
	)
	data, err := os.ReadFile(iflinkPath)
	if err != nil {
		return Target{}, fmt.Errorf("read target interface %s iflink: %w", podInterface, err)
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
		cgroupPath, err := podCgroupPath(r.procRoot, candidate)
		if err != nil {
			continue
		}
		info, err := os.Stat(filepath.Join(r.cgroupRoot, strings.TrimPrefix(filepath.Clean("/"+cgroupPath), "/")))
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
	r.targets[podUID] = target
	return target, nil
}

func podPrimaryInterface(procRoot string, pid int) (string, error) {
	for _, routeFile := range []string{"route", "ipv6_route"} {
		iface, err := defaultRouteInterface(
			filepath.Join(procRoot, strconv.Itoa(pid), "net", routeFile),
			routeFile == "ipv6_route",
		)
		if err == nil && iface != "" {
			return iface, nil
		}
	}
	netRoot := filepath.Join(procRoot, strconv.Itoa(pid), "root", "sys", "class", "net")
	entries, err := os.ReadDir(netRoot)
	if err != nil {
		return "", fmt.Errorf("read target network interfaces: %w", err)
	}
	var candidates []string
	for _, entry := range entries {
		if entry.Name() != "lo" {
			candidates = append(candidates, entry.Name())
		}
	}
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("target network namespace has no non-loopback interface")
	}
	return "", fmt.Errorf(
		"target network namespace has no default route and multiple candidate interfaces: %s",
		strings.Join(candidates, ", "),
	)
}

func defaultRouteInterface(path string, ipv6 bool) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if ipv6 {
			if len(fields) >= 10 && fields[0] == strings.Repeat("0", 32) && fields[1] == "00" {
				return fields[len(fields)-1], nil
			}
			continue
		}
		if len(fields) >= 2 && fields[0] != "Iface" && fields[1] == "00000000" {
			return fields[0], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("default route not found")
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
