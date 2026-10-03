package gateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeNER struct{ fail bool }

func (f fakeNER) Detect(_ context.Context, text string, _ float64) ([]Finding, error) {
	if f.fail {
		return nil, errors.New("down")
	}
	var out []Finding
	for _, w := range []struct{ word, label string }{{"Anna", "NAME"}, {"Kowalska", "SURNAME"}, {"cukrzycę", "HEALTH"}, {"Orlen", "COMPANY"}} {
		if i := strings.Index(text, w.word); i >= 0 {
			out = append(out, Finding{Kind: w.label, Value: w.word, Start: i, End: i + len(w.word)})
		}
	}
	return out, nil
}

func TestHerBERTFindingsAreRedactedWithRules(t *testing.T) {
	e, _ := testEngine(t, SemanticScores{})
	e.PII = fakeNER{}
	req := baseRequest()
	req.Prompt = "Podsumuj raport Q4 dla Anna Kowalska z Orlen, ma cukrzycę, PESEL 44051401458"
	got := evaluate(t, e, req)
	for _, leaked := range []string{"Anna", "Kowalska", "cukrzycę", "44051401458"} {
		if strings.Contains(got.RedactedPrompt, leaked) {
			t.Fatalf("%s not redacted: %q", leaked, got.RedactedPrompt)
		}
	}
	if !strings.Contains(got.RedactedPrompt, "Orlen") {
		t.Fatal("COMPANY is not in the default label set and must stay")
	}
	if got.Decision != Redact {
		t.Fatalf("expected REDACT, got %s", got.Decision)
	}
}

func TestHerBERTFailureFallsBackOrFailsClosed(t *testing.T) {
	e, p := testEngine(t, SemanticScores{})
	e.PII = fakeNER{fail: true}
	req := baseRequest()
	req.Prompt = "Podsumuj raport Q4, PESEL 44051401458"
	got := evaluate(t, e, req)
	if got.Decision != Redact || len(got.Warnings) == 0 || strings.Contains(got.RedactedPrompt, "44051401458") {
		t.Fatalf("rules fallback failed: %+v", got)
	}
	rewritePolicy(t, p, "  on_model_failure: rules\n", "  on_model_failure: block\n")
	req.RequestID, req.SessionID = "", newID("t")
	if got = evaluate(t, e, req); got.Decision != Block {
		t.Fatalf("fail-closed mode allowed the request: %s", got.Decision)
	}
}

type slowNER struct {
	delay time.Duration
	calls *atomic.Int32
	err   error
}

func (s slowNER) Detect(ctx context.Context, text string, min float64) ([]Finding, error) {
	s.calls.Add(1)
	time.Sleep(s.delay)
	if s.err != nil {
		return nil, s.err
	}
	return fakeNER{}.Detect(ctx, text, min)
}

type slowSemantic struct{ delay time.Duration }

func (s slowSemantic) Analyze(context.Context, SemanticRequest) (SemanticScores, error) {
	time.Sleep(s.delay)
	return SemanticScores{IntentAlignment: 1}, nil
}

func TestPIIModelResultsAreCached(t *testing.T) {
	e, _ := testEngine(t, SemanticScores{})
	calls := &atomic.Int32{}
	e.PII = slowNER{delay: 5 * time.Millisecond, calls: calls}
	req := baseRequest()
	req.Prompt = "Podsumuj raport Q4 dla Anna Kowalska"
	first := evaluate(t, e, req)
	req.RequestID, req.SessionID = "", newID("t")
	second := evaluate(t, e, req)
	if calls.Load() != 1 {
		t.Fatalf("model called %d times for the same text", calls.Load())
	}
	if first.Timings.PIIModelMS <= 0 || second.Timings.PIIModelMS != 0 {
		t.Fatalf("pii_model_ms should be measured on a miss and 0 on a hit: %v / %v", first.Timings.PIIModelMS, second.Timings.PIIModelMS)
	}
	if strings.Contains(second.RedactedPrompt, "Kowalska") {
		t.Fatalf("cached result lost a finding: %q", second.RedactedPrompt)
	}
	trace := ""
	for _, st := range second.Trace {
		trace += st.Detail
	}
	if !strings.Contains(trace, "cached") {
		t.Fatalf("trace does not say the model result was cached: %s", trace)
	}
}

func TestModelCallsRunInParallelAndAreNotGatewayOverhead(t *testing.T) {
	e, _ := testEngine(t, SemanticScores{})
	e.PII = slowNER{delay: 60 * time.Millisecond, calls: &atomic.Int32{}}
	e.Semantic = slowSemantic{delay: 60 * time.Millisecond}
	req := baseRequest()
	req.Action, req.Resource = "database.query", "database/customers" // risk >= .25: semantic escalation
	req.Prompt, req.OriginalIntent = "Read customer 123 for Anna Kowalska", "Read customer 123 for Anna Kowalska"
	started := time.Now()
	got := evaluate(t, e, req)
	elapsed := time.Since(started)
	if !got.SemanticEscalated {
		t.Fatal("expected semantic escalation")
	}
	if elapsed > 105*time.Millisecond {
		t.Fatalf("PII model and semantic guard ran sequentially: %v", elapsed)
	}
	if got.Timings.GatewayMS > 25 || got.Timings.PIIModelMS < 55 || got.Timings.SemanticMS < 55 {
		t.Fatalf("timings mix model time into gateway overhead: %+v", got.Timings)
	}
}

func TestPIIModelNotInstalledIsReportedNotDegraded(t *testing.T) {
	e, _ := testEngine(t, SemanticScores{})
	e.PII = slowNER{calls: &atomic.Int32{}, err: errPIIModelNotInstalled}
	got := evaluate(t, e, baseRequest())
	if got.Decision != Allow || len(got.Warnings) == 0 {
		t.Fatalf("missing model must fall back to rules with a warning: %+v", got)
	}
	_, health := getJSON(t, NewServer(e, "").Handler(), "", "/health")
	if health["pii_model"] != "not_installed" {
		t.Fatalf("health reports %v", health["pii_model"])
	}
}

func TestHealthProbesPIIModelStateBeforeAnyRequest(t *testing.T) {
	for body, want := range map[string]string{
		`{"ner":{"ready":true,"loading":false,"error":null}}`:                                            "enabled",
		`{"ner":{"ready":false,"loading":true,"error":null}}`:                                            "loading",
		`{"ner":{"ready":false,"loading":false,"error":"ModuleNotFoundError: not installed (pip ...)"}}`: "not_installed",
		`{"ner":{"ready":false,"loading":false,"error":"OSError: weights missing"}}`:                     "degraded",
	} {
		guard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }))
		e, _ := testEngine(t, SemanticScores{})
		e.PII = HTTPNERClient{URL: guard.URL}
		_, health := getJSON(t, NewServer(e, "").Handler(), "", "/health")
		guard.Close()
		if health["pii_model"] != want {
			t.Fatalf("%s: health reports %v, want %s", body, health["pii_model"], want)
		}
	}
}
