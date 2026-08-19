package client

import (
	"encoding/json"
	"testing"
)

// Expected output produced by Python's
//
//	json.dumps(value, sort_keys=True, separators=(",", ":"))
//
// The two implementations must agree byte for byte: core signs the Python rendering
// and the node verifies the Go one, so any divergence rejects every task. Go's
// encoding/json escapes <, >, and & where Python does not, which is exactly the
// class of difference this guards.
func TestCanonicalJSONMatchesPython(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "empty args",
			input: `{"task_id":"t-1","capability":"list_packages","args":{},"issued_at":"2026-08-19T10:00:00+00:00","expires_at":"2026-08-19T10:15:00+00:00","nonce":"abc"}`,
			want:  `{"args":{},"capability":"list_packages","expires_at":"2026-08-19T10:15:00+00:00","issued_at":"2026-08-19T10:00:00+00:00","nonce":"abc","task_id":"t-1"}`,
		},
		{
			name:  "html characters are not escaped",
			input: `{"task_id":"t-2","capability":"list_ports","args":{"b":2,"a":"x<y&z"},"issued_at":"2026-08-19T10:00:00+00:00","expires_at":"2026-08-19T10:15:00+00:00","nonce":"n2"}`,
			want:  `{"args":{"a":"x<y&z","b":2},"capability":"list_ports","expires_at":"2026-08-19T10:15:00+00:00","issued_at":"2026-08-19T10:00:00+00:00","nonce":"n2","task_id":"t-2"}`,
		},
		{
			name:  "nested structures sort at every level",
			input: `{"task_id":"t-3","capability":"inspect_docker","args":{"nested":{"z":[1,2,{"k":"v"}],"a":null,"t":true}},"issued_at":"2026-08-19T10:00:00+00:00","expires_at":"2026-08-19T10:15:00+00:00","nonce":"n3"}`,
			want:  `{"args":{"nested":{"a":null,"t":true,"z":[1,2,{"k":"v"}]}},"capability":"inspect_docker","expires_at":"2026-08-19T10:15:00+00:00","issued_at":"2026-08-19T10:00:00+00:00","nonce":"n3","task_id":"t-3"}`,
		},
		{
			name:  "quotes, backslashes, and control characters",
			input: `{"task_id":"quote\"and\\\\slash","capability":"get_system_info","args":{"s":"line\newline\ttab"},"issued_at":"2026-08-19T10:00:00+00:00","expires_at":"2026-08-19T10:15:00+00:00","nonce":"n4"}`,
			want:  `{"args":{"s":"line\newline\ttab"},"capability":"get_system_info","expires_at":"2026-08-19T10:15:00+00:00","issued_at":"2026-08-19T10:00:00+00:00","nonce":"n4","task_id":"quote\"and\\\\slash"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var value any
			if err := json.Unmarshal([]byte(tc.input), &value); err != nil {
				t.Fatalf("bad test input: %v", err)
			}
			got, err := canonicalJSON(value)
			if err != nil {
				t.Fatalf("canonicalJSON: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("canonical mismatch\n  got:  %s\n  want: %s", got, tc.want)
			}
		})
	}
}

func TestCanonicalRequestIsStable(t *testing.T) {
	a := canonicalRequest("get", "/api/v1/nodes/tasks", "2026-08-19T10:00:00Z", "n", nil)
	b := canonicalRequest("GET", "/api/v1/nodes/tasks", "2026-08-19T10:00:00Z", "n", nil)
	if string(a) != string(b) {
		t.Error("method case must not change the signed bytes")
	}

	withBody := canonicalRequest("POST", "/x", "2026-08-19T10:00:00Z", "n", []byte(`{"a":1}`))
	tampered := canonicalRequest("POST", "/x", "2026-08-19T10:00:00Z", "n", []byte(`{"a":2}`))
	if string(withBody) == string(tampered) {
		t.Error("a modified body must change the signed bytes")
	}
}
