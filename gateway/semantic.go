package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"
)

type SemanticAnalyzer interface {
	Analyze(context.Context, SemanticRequest) (SemanticScores, error)
}
type SemanticRequest struct {
	Prompt         string   `json:"prompt"`
	OriginalIntent string   `json:"original_intent"`
	Action         string   `json:"action"`
	Resource       string   `json:"resource"`
	History        []string `json:"history"`
}
type HTTPSemanticClient struct {
	URL    string
	Client *http.Client
}

func (c HTTPSemanticClient) Analyze(ctx context.Context, req SemanticRequest) (SemanticScores, error) {
	b, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/analyze", bytes.NewReader(b))
	if err != nil {
		return SemanticScores{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	cl := c.Client
	if cl == nil {
		cl = &http.Client{Timeout: 2 * time.Second}
	}
	resp, err := cl.Do(httpReq)
	if err != nil {
		return SemanticScores{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return SemanticScores{}, fmt.Errorf("semantic service returned %s", resp.Status)
	}
	var scores SemanticScores
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&scores); err != nil {
		return SemanticScores{}, err
	}
	// Scores are evidence only; clamp them so a faulty service cannot push
	// values outside the range the policy thresholds are written for.
	scores.PromptInjection = min1(scores.PromptInjection)
	scores.DataExfiltration = min1(scores.DataExfiltration)
	if math.IsNaN(scores.IntentAlignment) {
		scores.IntentAlignment = 0
	}
	scores.IntentAlignment = min1(scores.IntentAlignment)
	scores.PrivilegeDrift = min1(scores.PrivilegeDrift)
	scores.MemoryPoisoning = min1(scores.MemoryPoisoning)
	scores.Risk = min1(scores.Risk)
	if len(scores.Signals) > 20 {
		scores.Signals = scores.Signals[:20]
	}
	return scores, nil
}

type ResilientAnalyzer struct {
	Primary  SemanticAnalyzer
	Fallback SemanticAnalyzer
}

// UnavailableAnalyzer fails closed when the ML guard is unreachable. Only
// requests selected for semantic escalation reach this fallback.
type UnavailableAnalyzer struct{}

func (UnavailableAnalyzer) Analyze(_ context.Context, _ SemanticRequest) (SemanticScores, error) {
	return SemanticScores{PromptInjection: 1, DataExfiltration: 1, IntentAlignment: 0, Risk: 1, Signals: []string{"semantic-service-unavailable"}}, nil
}

func (r ResilientAnalyzer) Analyze(ctx context.Context, req SemanticRequest) (SemanticScores, error) {
	if r.Primary != nil {
		if s, err := r.Primary.Analyze(ctx, req); err == nil {
			return s, nil
		}
	}
	if r.Fallback == nil {
		return SemanticScores{IntentAlignment: 1}, nil
	}
	return r.Fallback.Analyze(ctx, req)
}

type LocalFallbackAnalyzer struct{}

func (LocalFallbackAnalyzer) Analyze(_ context.Context, req SemanticRequest) (SemanticScores, error) {
	// Deliberately conservative fallback. The Python service is the primary semantic layer;
	// this keeps the gateway fail-closed for obvious attacks during service degradation.
	text := normalize(req.Prompt + " " + req.Action + " " + req.Resource)
	inj := keywordScore(text, []string{"ignore previous", "ignore all", "system prompt", "developer message", "jailbreak", "zignoruj poprzednie", "ujawnij instrukcje"})
	exfil := keywordScore(text, []string{"dump all", "export all", "send externally", "credentials", "secrets", "wszystkie dane", "wyślij dane"})
	align := 1.0
	if req.OriginalIntent != "" {
		align = tokenOverlap(normalize(req.OriginalIntent), text)
	}
	drift := 0.0
	if len(req.History) >= 3 {
		drift = float64(len(req.History)-2) * 0.18
	}
	return SemanticScores{PromptInjection: inj, DataExfiltration: exfil, IntentAlignment: align, PrivilegeDrift: min1(drift), Risk: maxFloat(inj, exfil, 1-align, min1(drift)), Signals: []string{"local-fallback"}}, nil
}

func normalize(s string) string {
	var out []rune
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			r += 32
		}
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r >= 128 {
			out = append(out, r)
		} else {
			out = append(out, ' ')
		}
	}
	return string(out)
}
func keywordScore(text string, terms []string) float64 {
	score := 0.0
	for _, t := range terms {
		if containsText(text, t) {
			score += 0.48
		}
	}
	return min1(score)
}
func containsText(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
func tokenOverlap(a, b string) float64 {
	am := map[string]bool{}
	for _, w := range splitWords(a) {
		if len(w) > 2 {
			am[w] = true
		}
	}
	if len(am) == 0 {
		return 1
	}
	hit := 0
	for _, w := range splitWords(b) {
		if am[w] {
			hit++
		}
	}
	ratio := float64(hit) / float64(len(am))
	if ratio < 0.12 {
		return 0.18
	}
	if ratio < 0.3 {
		return 0.45
	}
	return min1(0.55 + ratio)
}
func splitWords(s string) []string {
	var out []string
	start := -1
	for i, r := range s {
		space := r == ' '
		if !space && start < 0 {
			start = i
		}
		if space && start >= 0 {
			out = append(out, s[start:i])
			start = -1
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}
func min1(v float64) float64 {
	if math.IsNaN(v) {
		return 1
	}
	if v > 1 {
		return 1
	}
	if v < 0 {
		return 0
	}
	return v
}
