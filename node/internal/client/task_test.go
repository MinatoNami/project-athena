package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func signTask(t *testing.T, priv ed25519.PrivateKey, task *Task) {
	t.Helper()
	var args any
	if err := json.Unmarshal(task.Args, &args); err != nil {
		t.Fatalf("args: %v", err)
	}
	canonical, err := canonicalJSON(map[string]any{
		"task_id": task.TaskID, "capability": task.Capability, "args": args,
		"issued_at": task.IssuedAt, "expires_at": task.ExpiresAt, "nonce": task.Nonce,
	})
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	task.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonical))
}

func newTask() *Task {
	return &Task{
		TaskID: "t-1", Capability: "list_packages", Args: json.RawMessage(`{}`),
		IssuedAt:  time.Now().UTC().Format(time.RFC3339Nano),
		ExpiresAt: time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339Nano),
		Nonce:     "abc",
	}
}

// A node must run nothing core did not authorise. Without this check, anything that
// could reach the agent could drive it.
func TestTaskVerification(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)

	t.Run("accepts a task signed by the pinned key", func(t *testing.T) {
		task := newTask()
		signTask(t, priv, task)
		if err := task.Verify(pub); err != nil {
			t.Errorf("legitimate task refused: %v", err)
		}
	})

	t.Run("refuses a task signed by another key", func(t *testing.T) {
		task := newTask()
		signTask(t, otherPriv, task)
		if err := task.Verify(pub); err == nil {
			t.Error("a task signed by an unpinned key must be refused")
		}
		if err := task.Verify(otherPub); err != nil {
			t.Errorf("sanity: the other key should verify its own signature: %v", err)
		}
	})

	t.Run("refuses a task whose capability was tampered with", func(t *testing.T) {
		task := newTask()
		signTask(t, priv, task)
		task.Capability = "inspect_docker"
		if err := task.Verify(pub); err == nil {
			t.Error("swapping the capability after signing must invalidate the task")
		}
	})

	t.Run("refuses a task whose args were tampered with", func(t *testing.T) {
		task := newTask()
		signTask(t, priv, task)
		task.Args = json.RawMessage(`{"path":"/etc/shadow"}`)
		if err := task.Verify(pub); err == nil {
			t.Error("modified args must invalidate the task")
		}
	})

	t.Run("refuses an unsigned task", func(t *testing.T) {
		task := newTask()
		if err := task.Verify(pub); err == nil {
			t.Error("an unsigned task must be refused")
		}
	})

	t.Run("refuses an expired task even when correctly signed", func(t *testing.T) {
		task := newTask()
		task.ExpiresAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
		signTask(t, priv, task)
		if err := task.Verify(pub); err == nil {
			t.Error("an expired task must be refused, signature notwithstanding")
		}
	})
}
