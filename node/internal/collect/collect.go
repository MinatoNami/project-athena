// Package collect implements the observe capabilities.
//
// Every capability is a named, argument-validated operation with a fixed
// implementation. There is deliberately no generic command execution: the absence
// of a run_shell capability is the difference between a node agent and a backdoor.
package collect

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const commandTimeout = 60 * time.Second

// Registry maps a capability name to its implementation. A capability absent here
// cannot be invoked, whatever core sends.
var Registry = map[string]func(args map[string]any) (any, error){
	"get_system_info": func(map[string]any) (any, error) { return SystemInfo() },
	"list_packages":   func(map[string]any) (any, error) { return Packages() },
	"list_processes":  func(map[string]any) (any, error) { return Processes() },
	"list_services":   func(map[string]any) (any, error) { return Services() },
	"list_ports":      func(map[string]any) (any, error) { return Ports() },
	"inspect_docker":  func(map[string]any) (any, error) { return Docker() },
}

// run executes a fixed argv with a timeout. Nothing here interpolates task input
// into a command line.
func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")

	done := make(chan error, 1)
	var out strings.Builder
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		return "", err
	}
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		return out.String(), err
	case <-time.After(commandTimeout):
		_ = cmd.Process.Kill()
		return "", fmt.Errorf("%s timed out after %s", name, commandTimeout)
	}
}

func readFirstLine(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	if s.Scan() {
		return strings.TrimSpace(s.Text())
	}
	return ""
}

type Info struct {
	Hostname     string `json:"hostname"`
	MachineID    string `json:"machine_id,omitempty"`
	HardwareUUID string `json:"hardware_uuid,omitempty"`
	OS           string `json:"os"`
	OSVersion    string `json:"os_version,omitempty"`
	OSID         string `json:"os_id,omitempty"`
	OSVersionID  string `json:"os_version_id,omitempty"`
	Kernel       string `json:"kernel,omitempty"`
	Arch         string `json:"arch"`
	CollectedAt  string `json:"collected_at"`
}

func SystemInfo() (Info, error) {
	host, _ := os.Hostname()
	info := Info{
		Hostname:    host,
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		MachineID:   MachineID(),
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if kernel, err := run("uname", "-r"); err == nil {
		info.Kernel = strings.TrimSpace(kernel)
	}
	// ID and VERSION_ID are reported alongside the pretty name because correlation
	// needs the release: a fix in Ubuntu 22.04 says nothing about 24.04, and
	// parsing a human-readable string on the server is the wrong place for it.
	for _, line := range strings.Split(osRelease(), "\n") {
		value := func(prefix string) string {
			return strings.Trim(strings.TrimPrefix(line, prefix), `"`)
		}
		switch {
		case strings.HasPrefix(line, "PRETTY_NAME="):
			info.OSVersion = value("PRETTY_NAME=")
		case strings.HasPrefix(line, "ID="):
			info.OSID = value("ID=")
		case strings.HasPrefix(line, "VERSION_ID="):
			info.OSVersionID = value("VERSION_ID=")
		}
	}
	return info, nil
}

func osRelease() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	return string(data)
}

// MachineID is the most durable host identity available: it survives reboots,
// hostname changes, and IP changes, which a hostname does not.
func MachineID() string {
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if id := readFirstLine(path); id != "" {
			return id
		}
	}
	return ""
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
	Source  string `json:"source"`
}

// Packages reads the OS package database directly rather than shelling out to a
// package manager where possible, so a broken package tool cannot look like an
// empty system.
func Packages() ([]Package, error) {
	if out, err := run("dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\n"); err == nil {
		return parseTabular(out, "deb"), nil
	}
	if out, err := run("rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"); err == nil {
		return parseTabular(out, "rpm"), nil
	}
	if out, err := run("apk", "info", "-v"); err == nil {
		return parseApk(out), nil
	}
	return nil, fmt.Errorf("no supported package manager found")
}

func parseTabular(out, source string) []Package {
	var pkgs []Package
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Split(strings.TrimSpace(line), "\t")
		if len(fields) < 2 || fields[0] == "" || fields[1] == "" {
			continue
		}
		p := Package{Name: fields[0], Version: fields[1], Source: source}
		if len(fields) > 2 {
			p.Arch = fields[2]
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

func parseApk(out string) []Package {
	var pkgs []Package
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		idx := strings.LastIndex(line, "-")
		if idx < 1 {
			continue
		}
		nameVer := line[:idx]
		if j := strings.LastIndex(nameVer, "-"); j > 0 {
			pkgs = append(pkgs, Package{Name: nameVer[:j], Version: nameVer[j+1:] + line[idx:], Source: "apk"})
		}
	}
	return pkgs
}

type Process struct {
	PID     int    `json:"pid"`
	User    string `json:"user"`
	Command string `json:"command"`
}

func Processes() ([]Process, error) {
	out, err := run("ps", "-eo", "pid=,user=,comm=")
	if err != nil {
		return nil, err
	}
	var procs []Process
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		procs = append(procs, Process{PID: pid, User: fields[1], Command: fields[2]})
	}
	return procs, nil
}

type Service struct {
	Name   string `json:"name"`
	Active string `json:"active"`
	Sub    string `json:"sub,omitempty"`
}

func Services() ([]Service, error) {
	out, err := run("systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain")
	if err != nil {
		return nil, fmt.Errorf("systemctl unavailable: %w", err)
	}
	var services []Service
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		services = append(services, Service{Name: fields[0], Active: fields[2], Sub: fields[3]})
	}
	return services, nil
}

type Port struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Process  string `json:"process,omitempty"`
}

// Ports reports listening sockets. New exposure is the signal that matters here, so
// the address is kept: 127.0.0.1:6379 and 0.0.0.0:6379 are very different facts.
func Ports() ([]Port, error) {
	out, err := run("ss", "-lntupH")
	if err != nil {
		if out, err = run("netstat", "-lntup"); err != nil {
			return nil, fmt.Errorf("neither ss nor netstat available: %w", err)
		}
	}
	var ports []Port
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		proto := strings.ToLower(fields[0])
		if !strings.HasPrefix(proto, "tcp") && !strings.HasPrefix(proto, "udp") {
			continue
		}
		local := fields[4]
		idx := strings.LastIndex(local, ":")
		if idx < 0 {
			continue
		}
		port, err := strconv.Atoi(local[idx+1:])
		if err != nil {
			continue
		}
		p := Port{Protocol: proto, Address: local[:idx], Port: port}
		if len(fields) > 6 {
			p.Process = fields[6]
		}
		ports = append(ports, p)
	}
	return ports, nil
}

type DockerState struct {
	Images     []DockerImage     `json:"images"`
	Containers []DockerContainer `json:"containers"`
}

type DockerImage struct {
	// The local image ID, which is what `docker ps` prints for a container whose
	// image carries no usable tag. Without it such a container cannot be matched to
	// the image it runs, and the image looks like one nothing uses.
	ID         string `json:"id"`
	Digest     string `json:"digest"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
}

type DockerContainer struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Image  string `json:"image"`
	Digest string `json:"digest,omitempty"`
	State  string `json:"state"`
	// Published port mappings, verbatim, e.g. "0.0.0.0:8080->80/tcp". Reported
	// rather than interpreted: whether binding to loopback means a container is
	// unreachable depends on what else runs on the host, which the agent cannot see.
	// The empty string and "no ports reported" are different facts, so the field is
	// always present once an agent is new enough to send it.
	Ports string `json:"ports"`
}

func Docker() (DockerState, error) {
	state := DockerState{Images: []DockerImage{}, Containers: []DockerContainer{}}

	// Images are identified by digest, never by tag: a tag is a moving pointer.
	if out, err := run("docker", "image", "ls", "--digests", "--format",
		"{{.ID}}\t{{.Digest}}\t{{.Repository}}\t{{.Tag}}"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			f := strings.Split(strings.TrimSpace(line), "\t")
			if len(f) < 4 || !strings.HasPrefix(f[1], "sha256:") {
				continue
			}
			state.Images = append(state.Images,
				DockerImage{ID: f[0], Digest: f[1], Repository: f[2], Tag: f[3]})
		}
	} else {
		// Distinguishing "no Docker here" from "the read-only proxy is unreachable"
		// matters: the first is a fact about the host, the second is a coverage gap
		// the operator can fix.
		host := os.Getenv("DOCKER_HOST")
		if host == "" {
			return state, fmt.Errorf("docker unavailable and no DOCKER_HOST set: %w", err)
		}
		return state, fmt.Errorf("docker API at %s unreachable: %w", host, err)
	}

	if out, err := run("docker", "ps", "-a", "--format",
		"{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Ports}}"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			// Ports is last and is routinely empty, so the line is split to a fixed
			// width rather than requiring every field to be non-empty.
			f := strings.SplitN(strings.TrimSpace(line), "\t", 5)
			if len(f) < 4 {
				continue
			}
			ports := ""
			if len(f) == 5 {
				ports = f[4]
			}
			state.Containers = append(state.Containers,
				DockerContainer{ID: f[0], Name: f[1], Image: f[2], State: f[3], Ports: ports})
		}
	}
	return state, nil
}
