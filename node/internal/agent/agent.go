// Package agent holds enrolment, on-disk state, and the run loop.
package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/MinatoNami/project-athena/node/internal/client"
	"github.com/MinatoNami/project-athena/node/internal/collect"
)

const (
	Version      = "0.1.0"
	pollInterval = 15 * time.Second
	maxBackoff   = 5 * time.Minute
)

// State is what persists across restarts. The private key lives here and nowhere
// else; the file is created 0600 and the directory 0700.
type State struct {
	CoreURL       string `json:"core_url"`
	NodeID        string `json:"node_id"`
	PrivateKey    string `json:"private_key"`
	CorePublicKey string `json:"core_public_key"`
}

func statePath(dir string) string { return filepath.Join(dir, "node.json") }

func Load(dir string) (*State, error) {
	data, err := os.ReadFile(statePath(dir))
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("state file is corrupt: %w", err)
	}
	return &s, nil
}

func (s *State) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	// 0600: the private key is the node's whole identity.
	return os.WriteFile(statePath(dir), data, 0o600)
}

// Enrol redeems a single-use token.
//
// The keypair is generated here, on the protected host. Only the public half is
// ever sent, so core — and anyone who compromises it — never holds a credential
// that can impersonate this node.
func Enrol(coreURL, token, dir string) (*State, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	info, _ := collect.SystemInfo()
	body, err := json.Marshal(map[string]any{
		"token":         token,
		"public_key":    base64.StdEncoding.EncodeToString(pub),
		"hostname":      info.Hostname,
		"machine_id":    info.MachineID,
		"platform":      info.OS,
		"arch":          runtime.GOARCH,
		"agent_version": Version,
	})
	if err != nil {
		return nil, err
	}

	url := strings.TrimRight(coreURL, "/") + "/api/v1/nodes/enrol"
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Post(url, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("cannot reach core at %s: %w", coreURL, err)
	}
	defer resp.Body.Close()

	var out struct {
		NodeID        string   `json:"node_id"`
		AssetID       string   `json:"asset_id"`
		Capabilities  []string `json:"capabilities"`
		CorePublicKey string   `json:"core_public_key"`
		Detail        any      `json:"detail"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("unexpected response from core: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("enrolment rejected (%d): %v", resp.StatusCode, out.Detail)
	}
	if out.CorePublicKey == "" {
		return nil, fmt.Errorf("core did not return a signing key; refusing to enrol")
	}

	state := &State{
		CoreURL:       strings.TrimRight(coreURL, "/"),
		NodeID:        out.NodeID,
		PrivateKey:    base64.StdEncoding.EncodeToString(priv),
		CorePublicKey: out.CorePublicKey,
	}
	if err := state.Save(dir); err != nil {
		return nil, err
	}
	slog.Info("enrolled", "node_id", out.NodeID, "asset_id", out.AssetID,
		"capabilities", out.Capabilities)
	return state, nil
}

func (s *State) client() (*client.Client, error) {
	priv, err := base64.StdEncoding.DecodeString(s.PrivateKey)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("stored private key is invalid")
	}
	corePub, err := base64.StdEncoding.DecodeString(s.CorePublicKey)
	if err != nil || len(corePub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("stored core public key is invalid")
	}
	return client.New(s.CoreURL, s.NodeID, priv, corePub, Version), nil
}

// Run polls for work until the context is cancelled.
func Run(state *State, stop <-chan struct{}) error {
	c, err := state.client()
	if err != nil {
		return err
	}
	slog.Info("agent started", "core", state.CoreURL, "node_id", state.NodeID, "version", Version)

	backoff := pollInterval
	for {
		select {
		case <-stop:
			slog.Info("agent stopped")
			return nil
		default:
		}

		tasks, err := c.PollTasks()
		if err != nil {
			// Core being unreachable is expected and survivable; the node keeps
			// trying rather than exiting and needing a supervisor to notice.
			slog.Warn("poll failed", "error", err, "retry_in", backoff)
			sleep(backoff, stop)
			if backoff < maxBackoff {
				backoff *= 2
			}
			continue
		}
		backoff = pollInterval

		for _, task := range tasks {
			executeAndReport(c, task)
		}
		sleep(pollInterval, stop)
	}
}

func executeAndReport(c *client.Client, task client.Task) {
	// A task is only executed if core signed it. An unsigned or expired instruction
	// is refused and reported, never run.
	if err := task.Verify(c.CorePublicKey); err != nil {
		slog.Error("refusing task", "task", task.TaskID, "error", err)
		_ = c.SubmitResult(client.Result{
			TaskID: task.TaskID, Succeeded: false,
			Error: "refused: " + err.Error(),
		})
		return
	}

	impl, ok := collect.Registry[task.Capability]
	if !ok {
		slog.Error("unknown capability", "task", task.TaskID, "capability", task.Capability)
		_ = c.SubmitResult(client.Result{
			TaskID: task.TaskID, Succeeded: false,
			Error: "capability not implemented by this agent: " + task.Capability,
		})
		return
	}

	var args map[string]any
	_ = json.Unmarshal(task.Args, &args)

	started := time.Now()
	value, err := impl(args)
	if err != nil {
		slog.Warn("capability failed", "capability", task.Capability, "error", err)
		_ = c.SubmitResult(client.Result{TaskID: task.TaskID, Succeeded: false, Error: err.Error()})
		return
	}

	slog.Info("capability done", "capability", task.Capability,
		"ms", time.Since(started).Milliseconds())
	if err := c.SubmitResult(client.Result{
		TaskID: task.TaskID, Succeeded: true,
		Result: map[string]any{"capability": task.Capability, "data": value},
	}); err != nil {
		slog.Error("could not report result", "task", task.TaskID, "error", err)
	}
}

func sleep(d time.Duration, stop <-chan struct{}) {
	select {
	case <-time.After(d):
	case <-stop:
	}
}
