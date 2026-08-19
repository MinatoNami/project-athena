// Package client speaks the node side of the Athena protocol.
//
// The node always dials out: core never opens a connection to a protected host, so
// nothing Athena protects needs an inbound listener.
package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	userAgent      = "athena-node"
	requestTimeout = 60 * time.Second
)

// Client holds the node identity. The private key is generated on this host and is
// never transmitted; only the public half ever reaches core.
type Client struct {
	BaseURL       string
	NodeID        string
	PrivateKey    ed25519.PrivateKey
	CorePublicKey ed25519.PublicKey
	AgentVersion  string

	http *http.Client
}

func New(baseURL, nodeID string, priv ed25519.PrivateKey, corePub ed25519.PublicKey, version string) *Client {
	return &Client{
		BaseURL:       strings.TrimRight(baseURL, "/"),
		NodeID:        nodeID,
		PrivateKey:    priv,
		CorePublicKey: corePub,
		AgentVersion:  version,
		http:          &http.Client{Timeout: requestTimeout},
	}
}

func nonce() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// canonicalRequest must match athena/nodes/protocol.py exactly. Binding method,
// path, timestamp, nonce, and a body digest stops a captured signature being
// replayed against another endpoint or a modified payload.
func canonicalRequest(method, path, timestamp, nonce string, body []byte) []byte {
	sum := sha256.Sum256(body)
	return []byte(strings.Join([]string{
		strings.ToUpper(method), path, timestamp, nonce, hex.EncodeToString(sum[:]),
	}, "\n"))
}

func (c *Client) signed(method, path string, body []byte) (*http.Request, error) {
	full := c.BaseURL + path
	parsed, err := url.Parse(full)
	if err != nil {
		return nil, err
	}

	n, err := nonce()
	if err != nil {
		return nil, err
	}
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	signature := ed25519.Sign(c.PrivateKey, canonicalRequest(method, parsed.Path, timestamp, n, body))

	req, err := http.NewRequest(method, full, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent+"/"+c.AgentVersion)
	req.Header.Set("X-Athena-Node", c.NodeID)
	req.Header.Set("X-Athena-Timestamp", timestamp)
	req.Header.Set("X-Athena-Nonce", n)
	req.Header.Set("X-Athena-Signature", base64.StdEncoding.EncodeToString(signature))
	return req, nil
}

func (c *Client) do(req *http.Request, out any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("core returned %d: %s", resp.StatusCode, strings.TrimSpace(string(payload)))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(payload, out)
}

// Task is one signed instruction from core.
type Task struct {
	TaskID     string          `json:"task_id"`
	Capability string          `json:"capability"`
	Args       json.RawMessage `json:"args"`
	IssuedAt   string          `json:"issued_at"`
	ExpiresAt  string          `json:"expires_at"`
	Nonce      string          `json:"nonce"`
	Signature  string          `json:"signature"`
}

// Verify checks that core actually authorised this task, and that it has not expired.
//
// Without this a node would execute whatever reached it. With it, a task is only
// run if it was signed by the key pinned at enrolment — which is what makes a
// compromised or spoofed core unable to drive the agent.
func (t *Task) Verify(corePub ed25519.PublicKey) error {
	raw := map[string]any{
		"task_id":    t.TaskID,
		"capability": t.Capability,
		"issued_at":  t.IssuedAt,
		"expires_at": t.ExpiresAt,
		"nonce":      t.Nonce,
	}
	var args any
	if err := json.Unmarshal(t.Args, &args); err != nil {
		return fmt.Errorf("malformed args: %w", err)
	}
	raw["args"] = args

	canonical, err := canonicalJSON(raw)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(t.Signature)
	if err != nil {
		return fmt.Errorf("malformed signature: %w", err)
	}
	if !ed25519.Verify(corePub, canonical, sig) {
		return fmt.Errorf("task %s: signature verification failed", t.TaskID)
	}

	expires, err := time.Parse(time.RFC3339Nano, t.ExpiresAt)
	if err != nil {
		return fmt.Errorf("task %s: malformed expiry: %w", t.TaskID, err)
	}
	if time.Now().After(expires) {
		return fmt.Errorf("task %s: expired at %s", t.TaskID, t.ExpiresAt)
	}
	return nil
}

func (c *Client) PollTasks() ([]Task, error) {
	req, err := c.signed(http.MethodGet, "/api/v1/nodes/tasks", nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Tasks []Task `json:"tasks"`
	}
	if err := c.do(req, &out); err != nil {
		return nil, err
	}
	return out.Tasks, nil
}

type Result struct {
	TaskID    string `json:"task_id"`
	Succeeded bool   `json:"succeeded"`
	Result    any    `json:"result,omitempty"`
	Error     string `json:"error,omitempty"`
}

func (c *Client) SubmitResult(r Result) error {
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	req, err := c.signed(http.MethodPost, "/api/v1/nodes/results", body)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}
