package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGhostShellDoesNotGrantViewerAuthority(t *testing.T) {
	engine, _ := testEngine(t, SemanticScores{})
	request := httptest.NewRequest("POST", "/v1/ghost/sessions", bytes.NewBufferString(`{"agent":"corporate-agent"}`))
	request.Header.Set("Authorization", "Bearer viewer-demo-key")
	recorder := httptest.NewRecorder()
	NewServer(engine, "").Handler().ServeHTTP(recorder, request)
	if recorder.Code != 403 {
		t.Fatalf("expected 403, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestGhostShellEnforcesPermissionsAndRejectsRealSecrets(t *testing.T) {
	engine, _ := testEngine(t, SemanticScores{})
	executions := 0
	python := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-MASQE-Internal") != "test-internal" {
			t.Error("missing internal auth")
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["op"] == "exec" {
			executions++
		}
		writeJSON(w, 200, map[string]any{"agent": "corporate-agent", "status": "active", "events": []any{map[string]any{"content": map[string]any{"output": "virtual"}}}})
	}))
	defer python.Close()
	t.Setenv("MASQE_AI_GUARD_URL", python.URL)
	t.Setenv("MASQE_INTERNAL_KEY", "test-internal")
	service := NewExecutionService(engine)
	req := baseRequest()
	req.SessionID = "gs_test"
	req.Action = "shell.exec"
	req.Prompt = "cat .env"
	result, err := service.Execute(context.Background(), req)
	if err != nil || !result.Executed || result.Result != "virtual" {
		t.Fatalf("virtual execution failed: %+v %v", result, err)
	}
	req.User = Principal{ID: "vicky", Role: "viewer"}
	result, err = service.Execute(context.Background(), req)
	if err != nil || result.Executed || result.Evaluation.Decision != Block {
		t.Fatalf("viewer not blocked: %+v %v", result, err)
	}
	req.User = Principal{ID: "alice", Role: "analyst"}
	req.Prompt = "echo AKIAIOSFODNN7EXAMPLE"
	result, err = service.Execute(context.Background(), req)
	if err != nil || result.Executed || result.Evaluation.Decision != Block {
		t.Fatalf("real-looking inline secret accepted: %+v %v", result, err)
	}
	var status string
	if err := engine.Store.DB().QueryRow(`SELECT execution_status FROM audit_events WHERE id=?`, result.Evaluation.RequestID).Scan(&status); err != nil || status != "REJECTED" {
		t.Fatalf("rejected secret not audited: %q %v", status, err)
	}
	if executions != 1 {
		t.Fatalf("unexpected executions: %d", executions)
	}
}
