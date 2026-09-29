package audit

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// traceReport comes only from the observer container's private Docker volume.
// No part of this volume is mounted into the audited container.
type traceReport struct {
	ContainerID     string   `json:"container_id"`
	Nonce           string   `json:"nonce"`
	Started         bool     `json:"started"`
	Completed       bool     `json:"completed"`
	PackageEvents   int      `json:"package_events"`
	Execs           int      `json:"execs"`
	NetworkAttempts int      `json:"network_attempts"`
	UnresolvedOpens int      `json:"unresolved_opens"`
	HoneyPaths      []string `json:"honey_paths"`
	Packets         int      `json:"packets"`
	Bytes           int      `json:"bytes"`
	Complete        bool     `json:"complete"`
	Error           string   `json:"error"`
}

func traceConfig(endpoint, architecture string) ([]byte, error) {
	var outbound []int
	var aliases []int
	var namespaces []int
	var unsupported []int
	switch strings.ToLower(architecture) {
	case "aarch64", "arm64":
		outbound = []int{206, 211, 269}         // sendto, sendmsg, sendmmsg
		aliases = []int{36, 37, 38, 276}        // symlinkat, linkat, renameat, renameat2
		namespaces = []int{97, 268, 40, 41, 51} // unshare, setns, mount, pivot_root, chroot
		unsupported = []int{39, 425, 426, 427, 428, 429, 430, 431, 432, 433, 437}
	case "x86_64", "amd64":
		outbound = []int{44, 46, 307}
		aliases = []int{88, 266, 86, 265, 82, 264, 316} // symlink/link/rename variants
		namespaces = []int{272, 308, 165, 155, 161}
		unsupported = []int{166, 425, 426, 427, 428, 429, 430, 431, 432, 433, 437}
	default:
		return nil, fmt.Errorf("unsupported gVisor trace architecture %q", architecture)
	}
	contextFields := []string{"container_id", "group_id", "credentials", "cwd", "process_name"}
	type point struct {
		Name           string   `json:"name"`
		OptionalFields []string `json:"optional_fields,omitempty"`
		ContextFields  []string `json:"context_fields"`
	}
	points := make([]point, 0, 32)
	add := func(name string, optional ...string) {
		points = append(points, point{Name: name, OptionalFields: optional, ContextFields: contextFields})
	}
	for _, name := range []string{
		"container/start", "sentry/clone", "sentry/execve", "sentry/task_exit",
		"syscall/execve/enter", "syscall/execveat/enter", "syscall/connect/enter",
		"syscall/socket/enter",
	} {
		add(name)
	}
	if strings.ToLower(architecture) == "x86_64" || strings.ToLower(architecture) == "amd64" {
		add("syscall/open/enter")
		add("syscall/creat/enter")
	}
	for _, name := range []string{
		"syscall/openat/enter", "syscall/read/enter", "syscall/readv/enter",
		"syscall/pread64/enter", "syscall/preadv/enter", "syscall/preadv2/enter",
	} {
		add(name, "fd_path")
	}
	for _, sysno := range outbound {
		add(fmt.Sprintf("syscall/sysno/%d/enter", sysno))
	}
	for _, sysno := range aliases {
		add(fmt.Sprintf("syscall/sysno/%d/enter", sysno))
	}
	for _, sysno := range namespaces {
		add(fmt.Sprintf("syscall/sysno/%d/enter", sysno))
	}
	for _, sysno := range unsupported {
		add(fmt.Sprintf("syscall/sysno/%d/enter", sysno))
	}
	// Node probes io_uring availability on startup. Observe the result so
	// ENOSYS remains compatible while a successful setup fails certification.
	add("syscall/sysno/425/exit")
	config := map[string]any{"trace_session": map[string]any{
		"name":           "Default",
		"ignore_missing": false,
		"points":         points,
		"sinks": []any{map[string]any{
			"name":               "remote",
			"config":             map[string]any{"endpoint": endpoint, "retries": 3},
			"ignore_setup_error": false,
		}},
	}}
	return json.Marshal(config)
}

var droppedTrace = regexp.MustCompile(`(?m)^\s*Sink: "remote", dropped: ([0-9]+)\s*$`)

func validateTraceList(output string) error {
	if !strings.Contains(output, "SESSIONS (1)") || !strings.Contains(output, `"Default"`) {
		return fmt.Errorf("gVisor trace session missing: %s", truncate(output, 400))
	}
	matches := droppedTrace.FindAllStringSubmatch(output, -1)
	if len(matches) != 1 {
		return fmt.Errorf("gVisor remote sink status missing or duplicated: %s", truncate(output, 400))
	}
	if matches[0][1] != "0" {
		return fmt.Errorf("gVisor trace dropped %s events", matches[0][1])
	}
	return nil
}

// At the completion marker only the trusted supervisor may remain. runsc ps
// reports guest namespace PIDs, so [1] excludes dormant package descendants.
func validateRunscPS(output string) error {
	var pids []int
	if err := json.Unmarshal([]byte(output), &pids); err != nil {
		return fmt.Errorf("invalid gVisor process list: %w", err)
	}
	if len(pids) != 1 || pids[0] != 1 {
		return fmt.Errorf("gVisor workload has tasks after completion marker: %s", truncate(output, 200))
	}
	return nil
}

const testedRunscVersion = "runsc version release-20260601.0"

func validateRunscVersion(output string) error {
	if strings.SplitN(output, "\n", 2)[0] != testedRunscVersion {
		return fmt.Errorf("unsupported gVisor runsc version %q; trusted audit requires %s", truncate(strings.SplitN(output, "\n", 2)[0], 120), testedRunscVersion)
	}
	return nil
}

func validateTraceReport(report traceReport, containerID, nonce string) error {
	if report.ContainerID != containerID || report.Nonce != nonce {
		return fmt.Errorf("gVisor trace identity mismatch")
	}
	if !report.Complete || !report.Started || !report.Completed || report.Error != "" || report.Execs < 1 || report.PackageEvents < 1 || report.Packets < 1 || report.Bytes < 1 {
		return fmt.Errorf("gVisor trace incomplete: %s", report.Error)
	}
	if report.Packets > 100000 || report.Bytes > 8*1024*1024 || report.Execs > report.PackageEvents || report.PackageEvents > report.Packets || report.NetworkAttempts < 0 || report.NetworkAttempts > report.PackageEvents || report.UnresolvedOpens != 0 || len(report.HoneyPaths) > 32 {
		return fmt.Errorf("gVisor trace report outside bounds")
	}
	for _, path := range report.HoneyPaths {
		if !strings.HasPrefix(path, "/tmp/rivet-work/home/") || len(path) > 512 {
			return fmt.Errorf("gVisor trace honey path outside bounds")
		}
	}
	return nil
}
