package gateway

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIAuthentication(t *testing.T) {
	e, _ := testEngine(t, SemanticScores{})
	req := httptest.NewRequest(http.MethodPost, "/v1/evaluate", bytes.NewBufferString(`{}`))
	recorder := httptest.NewRecorder()
	NewServer(e, "").Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", recorder.Code)
	}
}
func TestHealthIsPublic(t *testing.T) {
	e, _ := testEngine(t, SemanticScores{})
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	recorder := httptest.NewRecorder()
	NewServer(e, "").Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("got %d", recorder.Code)
	}
}
