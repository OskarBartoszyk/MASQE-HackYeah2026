package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func callGateway(t *testing.T, handler http.Handler, key, path string, body any) (int, ExecuteResponse) {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(payload))
	r.Header.Set("Authorization", "Bearer "+key)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	var out ExecuteResponse
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestExecutionBindsIdentityAndRunsTool(t *testing.T) {
	e, _ := testEngine(t, SemanticScores{})
	h := NewServer(e, "").Handler()
	req := baseRequest()
	req.User = Principal{}
	req.Usage = Usage{Tokens: 0, ToolCalls: 0, Steps: 0}
	code, out := callGateway(t, h, "demo-key", "/v1/execute", req)
	if code != 200 || out.Evaluation.Decision != Allow || !out.Executed || !strings.Contains(out.Result, "Q4 revenue") {
		t.Fatalf("execution code=%d response=%+v", code, out)
	}
	var charged int
	if err := e.Store.DB().QueryRow(`SELECT tokens FROM audit_events WHERE id=?`, out.Evaluation.RequestID).Scan(&charged); err != nil || charged <= 0 {
		t.Fatalf("gateway did not measure usage: %d %v", charged, err)
	}
	var executionStatus string
	if err := e.Store.DB().QueryRow(`SELECT execution_status FROM audit_events WHERE id=?`, out.Evaluation.RequestID).Scan(&executionStatus); err != nil || executionStatus != "EXECUTED" {
		t.Fatalf("audit did not record execution: %q %v", executionStatus, err)
	}
	req.User = Principal{ID: "admin", Role: "admin"}
	code, _ = callGateway(t, h, "demo-key", "/v1/execute", req)
	if code != 403 {
		t.Fatalf("spoofed identity returned HTTP %d", code)
	}
	req.User = Principal{Permissions: []string{"customer.delete"}}
	code, _ = callGateway(t, h, "demo-key", "/v1/execute", req)
	if code != 403 {
		t.Fatalf("client-granted permissions returned HTTP %d", code)
	}
}

func TestPolicyEndpointDoesNotExposeCredentials(t *testing.T) {
	e, _ := testEngine(t, SemanticScores{})
	r := httptest.NewRequest(http.MethodGet, "/v1/policy", nil)
	r.Header.Set("Authorization", "Bearer viewer-demo-key")
	w := httptest.NewRecorder()
	NewServer(e, "").Handler().ServeHTTP(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), "admin-demo-key") || strings.Contains(w.Body.String(), "secops-demo-key") {
		t.Fatalf("policy endpoint leaked credentials: HTTP %d %s", w.Code, w.Body.String())
	}
}

func TestBlockedActionCannotChangeCustomer(t *testing.T) {
	e, _ := testEngine(t, SemanticScores{})
	h := NewServer(e, "").Handler()
	req := baseRequest()
	req.User = Principal{}
	req.Action = "customer.delete"
	req.Resource = "customer/123"
	code, out := callGateway(t, h, "demo-key", "/v1/execute", req)
	if code != 200 || out.Evaluation.Decision != Block || out.Executed {
		t.Fatalf("blocked action ran: %d %+v", code, out)
	}
	var count int
	if err := e.Store.DB().QueryRow(`SELECT COUNT(*) FROM demo_customers WHERE id='123'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("customer missing after denied action: %d %v", count, err)
	}
}

func TestTwoPersonApprovalIsOneTime(t *testing.T) {
	e, _ := testEngine(t, SemanticScores{})
	h := NewServer(e, "").Handler()
	req := baseRequest()
	req.User = Principal{}
	req.Action = "customer.delete"
	req.Resource = "customer/123"
	req.Prompt = "Delete the demo customer 123"
	req.OriginalIntent = req.Prompt
	code, out := callGateway(t, h, "admin-demo-key", "/v1/execute", req)
	if code != 200 || out.Evaluation.Decision != RequireApproval || out.Executed || out.Evaluation.ApprovalID == "" {
		t.Fatalf("approval not pending: %d %+v", code, out)
	}
	id := out.Evaluation.ApprovalID
	code, _ = callGateway(t, h, "admin-demo-key", "/v1/approvals/"+id+"/approve", nil)
	if code != 403 {
		t.Fatalf("self-approval returned HTTP %d", code)
	}
	code, out = callGateway(t, h, "secops-demo-key", "/v1/approvals/"+id+"/approve", nil)
	if code != 200 || !out.Executed || !strings.Contains(out.Result, "deleted 1") {
		t.Fatalf("second approver failed: %d %+v", code, out)
	}
	code, _ = callGateway(t, h, "secops-demo-key", "/v1/approvals/"+id+"/approve", nil)
	if code != 403 {
		t.Fatalf("replayed approval returned HTTP %d", code)
	}
	var approver, status string
	if err := e.Store.DB().QueryRow(`SELECT approved_by,execution_status FROM audit_events WHERE id=?`, out.Evaluation.RequestID).Scan(&approver, &status); err != nil || approver != "secops" || status != "EXECUTED" {
		t.Fatalf("audit lost approval outcome: %q %q %v", approver, status, err)
	}
}

func TestGhostRunsOnlyVirtualReadOnlyTool(t *testing.T) {
	e, _ := testEngine(t, SemanticScores{})
	h := NewServer(e, "").Handler()
	req := baseRequest()
	req.User = Principal{}
	req.Action = "repository.analyze"
	req.Resource = "untrusted/repo"
	req.Prompt = "Analyze an untrusted repository"
	req.OriginalIntent = req.Prompt
	code, out := callGateway(t, h, "demo-key", "/v1/execute", req)
	if code != 200 || out.Evaluation.Decision != Ghost || !out.Executed || !strings.Contains(out.Result, "Virtual repository") {
		t.Fatalf("Ghost execution failed: %d %+v", code, out)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestModelReceivesRedactedInputAndFiltersOutput(t *testing.T) {
	e, _ := testEngine(t, SemanticScores{})
	s := NewServer(e, "")
	var received string
	s.Execution.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		received = string(b)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"message":{"role":"assistant","content":"Contact anna@example.pl"},"prompt_eval_count":12,"eval_count":4}`)), Header: make(http.Header)}, nil
	})}
	req := baseRequest()
	req.User = Principal{}
	req.Agent.Model = "gemma3:4b"
	req.Action = "llm.generate"
	req.Resource = "model/gemma3:4b"
	req.Prompt = "Summarize the report; contact jan@example.pl"
	req.OriginalIntent = "Summarize the report"
	code, out := callGateway(t, s.Handler(), "demo-key", "/v1/execute", req)
	if code != 200 || out.Evaluation.Decision != Redact || !out.Executed || out.ActualTokens != 16 {
		t.Fatalf("model interception failed: %d %+v", code, out)
	}
	if strings.Contains(received, "jan@example.pl") || strings.Contains(out.Result, "anna@example.pl") || !strings.Contains(out.Result, "[REDACTED:EMAIL]") {
		t.Fatalf("PII leaked: input=%s output=%s", received, out.Result)
	}
}
