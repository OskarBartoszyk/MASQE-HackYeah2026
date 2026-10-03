package gateway

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTelemetryRangeShapesTimeline(t *testing.T) {
	e, _ := testEngine(t, SemanticScores{})
	h := NewServer(e, "").Handler()
	evaluate(t, e, baseRequest())
	for rng, buckets := range map[string]int{"15m": 15, "1h": 30, "24h": 24, "7d": 28} {
		_, m := getJSON(t, h, "demo-key", "/v1/telemetry?range="+rng)
		if m["range"] != rng || len(m["timeline"].([]any)) != buckets || m["requests"].(float64) != 1 {
			t.Fatalf("range %s: %v buckets, %v requests", rng, len(m["timeline"].([]any)), m["requests"])
		}
		last := m["timeline"].([]any)[buckets-1].(map[string]any)
		if last["allowed"].(float64) != 1 {
			t.Fatalf("range %s: current bucket misses the event: %v", rng, last)
		}
	}
}

func TestLiveStreamPushesOnlyVisibleEvents(t *testing.T) {
	e, _ := testEngine(t, SemanticScores{})
	srv := httptest.NewServer(NewServer(e, "").Handler())
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL+"/v1/stream", nil)
	req.Header.Set("Authorization", "Bearer demo-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("stream not opened: %v %v", err, resp)
	}
	defer resp.Body.Close()
	lines := make(chan string, 100)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	time.Sleep(50 * time.Millisecond)
	h := NewServer(e, "").Handler()
	other := baseRequest()
	other.User = Principal{}
	callGateway(t, h, "viewer-demo-key", "/v1/execute", other)
	mine := baseRequest()
	mine.User = Principal{}
	callGateway(t, h, "demo-key", "/v1/execute", mine)
	deadline := time.After(3 * time.Second)
	for {
		select {
		case line := <-lines:
			if strings.HasPrefix(line, "data: ") {
				if strings.Contains(line, `"user":"vicky"`) {
					t.Fatal("analyst received another user's event")
				}
				if strings.Contains(line, `"user":"alice"`) {
					if strings.Contains(line, `"prompt_injection":0.`) && !strings.Contains(line, "details_hidden") {
						t.Fatal("stream leaks detector scores")
					}
					return
				}
			}
		case <-deadline:
			t.Fatal("no live event received")
		}
	}
}

func TestIncidentQueueAndWorkflow(t *testing.T) {
	e, _ := testEngine(t, SemanticScores{})
	h := NewServer(e, "").Handler()
	req := baseRequest()
	req.User = Principal{}
	req.Prompt = "JURY_TEST_ATTACK"
	callGateway(t, h, "demo-key", "/v1/execute", req)
	safe := baseRequest()
	safe.User = Principal{}
	callGateway(t, h, "viewer-demo-key", "/v1/execute", safe)
	_, all := getJSON(t, h, "secops-demo-key", "/v1/incidents")
	list := all["incidents"].([]any)
	if len(list) != 1 {
		t.Fatalf("expected one incident, got %v", list)
	}
	inc := list[0].(map[string]any)
	if inc["type"] != "threat_signature" || inc["status"] != "open" || inc["user"] != "alice" {
		t.Fatalf("unexpected incident: %v", inc)
	}
	id := inc["id"].(string)
	if code, _ := postJSON(t, h, "demo-key", "/v1/incidents/"+id+"/status", map[string]any{"status": "resolved"}, nil); code != 403 {
		t.Fatalf("analyst changed incident state: %d", code)
	}
	if code, _ := postJSON(t, h, "secops-demo-key", "/v1/incidents/"+id+"/status", map[string]any{"status": "acknowledged", "note": "triaging"}, nil); code != 200 {
		t.Fatalf("security role cannot acknowledge: %d", code)
	}
	_, all = getJSON(t, h, "secops-demo-key", "/v1/incidents")
	if got := all["incidents"].([]any)[0].(map[string]any); got["status"] != "acknowledged" || got["updated_by"] != "secops" {
		t.Fatalf("workflow state not stored: %v", got)
	}
	_, own := getJSON(t, h, "viewer-demo-key", "/v1/incidents")
	if len(own["incidents"].([]any)) != 0 {
		t.Fatal("viewer sees another user's incident")
	}
	_, mine := getJSON(t, h, "demo-key", "/v1/incidents")
	if got := mine["incidents"].([]any)[0].(map[string]any); strings.Contains(got["summary"].(string), "EXPLOIT") {
		t.Fatalf("incident summary leaks signature ids to the user: %v", got["summary"])
	}
}
