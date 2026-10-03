package gateway

import (
	"bytes"
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// PIIDetector finds personal data with a model. Offsets are UTF-8 bytes.
type PIIDetector interface {
	Detect(ctx context.Context, text string, minScore float64) ([]Finding, error)
}

// HTTPNERClient calls the fine-tuned Polish HerBERT model (PLVeil) served by
// the AI Guard at POST /redact.
type HTTPNERClient struct {
	URL    string
	Client *http.Client
}

// PIIStatusReporter is implemented by detectors that can report whether the
// model is ready without running a detection.
type PIIStatusReporter interface {
	ModelStatus(ctx context.Context) string
}

// ModelStatus reads the AI Guard's /health: "enabled", "loading",
// "not_installed" or "degraded" (error or AI Guard unreachable).
func (c HTTPNERClient) ModelStatus(ctx context.Context) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(c.URL, "/")+"/health", nil)
	if err != nil {
		return "degraded"
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "degraded"
	}
	defer resp.Body.Close()
	var health struct {
		NER struct {
			Ready   bool    `json:"ready"`
			Loading bool    `json:"loading"`
			Error   *string `json:"error"`
		} `json:"ner"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&health) != nil {
		return "degraded"
	}
	switch {
	case health.NER.Ready:
		return "enabled"
	case health.NER.Loading:
		return "loading"
	case health.NER.Error != nil && (strings.Contains(*health.NER.Error, "not installed") || strings.Contains(*health.NER.Error, "disabled")):
		return "not_installed"
	default:
		return "degraded"
	}
}

func (c HTTPNERClient) Detect(ctx context.Context, text string, minScore float64) ([]Finding, error) {
	body, _ := json.Marshal(map[string]any{"text": text})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(c.URL, "/")+"/redact", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if key := os.Getenv("MASQE_INTERNAL_KEY"); key != "" {
		req.Header.Set("X-MASQE-Internal", key)
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == 503 && strings.Contains(string(body), "loading") {
			return nil, errPIIModelLoading
		}
		if resp.StatusCode == 503 && (strings.Contains(string(body), "not installed") || strings.Contains(string(body), "disabled")) {
			return nil, errPIIModelNotInstalled
		}
		return nil, fmt.Errorf("PII model returned HTTP %d", resp.StatusCode)
	}
	var out struct {
		Spans []struct {
			Start, End int
			Label      string
			Score      float64
		} `json:"spans"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return nil, err
	}
	var findings []Finding
	for _, s := range out.Spans {
		if s.Start < 0 || s.End > len(text) || s.Start >= s.End || s.Score < minScore {
			continue
		}
		findings = append(findings, Finding{Kind: strings.ToUpper(s.Label), Value: text[s.Start:s.End], Start: s.Start, End: s.End})
	}
	return findings, nil
}

// DefaultModelLabels are the model labels treated as personal data. Dates,
// ages, job titles, companies, schools and cities alone are left out to avoid
// masking ordinary business text; add them in redaction.labels if needed.
var DefaultModelLabels = []string{"NAME", "SURNAME", "ADDRESS", "PESEL", "PHONE", "EMAIL", "BANK_ACCOUNT", "CREDIT_CARD_NUMBER", "DOCUMENT_NUMBER", "NIP", "DATE_OF_BIRTH", "USERNAME", "RELATIVE", "HEALTH", "ETHNICITY", "POLITICAL_VIEW", "RELIGION", "SEXUAL_ORIENTATION", "SECRET"}

var errPIIModelUnavailable = errors.New("personal-data model unavailable")

// errPIIModelLoading is the short start-up window; it is not a failure.
var errPIIModelLoading = errors.New("personal-data model is loading")

// errPIIModelNotInstalled is a deployment choice (light image without torch),
// reported as "not installed" rather than as a failing model.
var errPIIModelNotInstalled = errors.New("personal-data model is not installed")

// piiScan is the result of the personal-data scan of one text.
type piiScan struct {
	Findings []Finding
	Warning  string
	Err      error
	// ModelMS is the time spent in the model call (0 when cached or unused).
	ModelMS float64
	// Engine describes what produced the findings, for the decision trace.
	Engine string
}

// sensitive merges the deterministic detectors (checksums, secrets) with the
// HerBERT model. When the model is unavailable the policy decides: fall back
// to rules (warning) or fail closed (error).
func (e *Engine) sensitive(ctx context.Context, p Policy, text string) ([]Finding, string, error) {
	scan := e.scanPII(ctx, p, text)
	return scan.Findings, scan.Warning, scan.Err
}

func (e *Engine) scanPII(ctx context.Context, p Policy, text string) piiScan {
	findings := ScanSensitive(text)
	r := p.Redaction
	if !r.UseModel || e.PII == nil || strings.TrimSpace(text) == "" {
		return piiScan{Findings: findings, Engine: "rules"}
	}
	engine := "HerBERT model (cached) + rules"
	key := piiCacheKey(text, r.MinScore)
	model, cached := e.piiCache().get(key, text)
	var modelMS float64
	if !cached {
		started := time.Now()
		var err error
		model, err = e.PII.Detect(ctx, text, r.MinScore)
		modelMS = ms(time.Since(started))
		if err != nil {
			switch {
			case errors.Is(err, errPIIModelNotInstalled):
				e.piiNotInstalled.Store(time.Now().Unix())
			case !errors.Is(err, errPIIModelLoading):
				e.piiFailure.Store(time.Now().Unix())
			}
			if strings.EqualFold(r.OnModelFailure, "block") {
				return piiScan{Findings: findings, Err: errPIIModelUnavailable, ModelMS: modelMS, Engine: "rules (model unavailable)"}
			}
			return piiScan{Findings: findings, Warning: "personal-data model unavailable: rules only", ModelMS: modelMS, Engine: "rules (model unavailable)"}
		}
		e.piiCache().put(key, model)
		engine = "HerBERT model + rules"
	}
	allowed := map[string]bool{}
	labels := r.Labels
	if len(labels) == 0 {
		labels = DefaultModelLabels
	}
	for _, l := range labels {
		allowed[strings.ToUpper(l)] = true
	}
	for _, f := range model {
		if allowed[f.Kind] {
			findings = append(findings, f)
		}
	}
	return piiScan{Findings: nonOverlapping(findings), ModelMS: modelMS, Engine: engine}
}

// --- Model result cache ---------------------------------------------------
//
// The model is deterministic, so identical texts (fixed tool outputs, repeated
// prompts, resent chat history) reuse the previous result. Only offsets and
// labels are cached — never the personal data itself — keyed by a hash.

const piiCacheSize = 4096

type cachedSpan struct {
	Kind       string
	Start, End int
}

type findingCache struct {
	mu    sync.Mutex
	order *list.List
	items map[string]*list.Element
}

type cacheEntry struct {
	key   string
	spans []cachedSpan
}

func (e *Engine) piiCache() *findingCache {
	e.piiCacheOnce.Do(func() {
		e.piiCacheStore = &findingCache{order: list.New(), items: map[string]*list.Element{}}
	})
	return e.piiCacheStore
}

func piiCacheKey(text string, minScore float64) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:]) + fmt.Sprintf("/%.3f", minScore)
}

func (c *findingCache) get(key, text string) ([]Finding, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	c.order.MoveToFront(el)
	spans := el.Value.(*cacheEntry).spans
	out := make([]Finding, 0, len(spans))
	for _, s := range spans {
		if s.End <= len(text) {
			out = append(out, Finding{Kind: s.Kind, Value: text[s.Start:s.End], Start: s.Start, End: s.End})
		}
	}
	return out, true
}

func (c *findingCache) put(key string, findings []Finding) {
	spans := make([]cachedSpan, len(findings))
	for i, f := range findings {
		spans[i] = cachedSpan{f.Kind, f.Start, f.End}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		el.Value.(*cacheEntry).spans = spans
		c.order.MoveToFront(el)
		return
	}
	c.items[key] = c.order.PushFront(&cacheEntry{key: key, spans: spans})
	for c.order.Len() > piiCacheSize {
		oldest := c.order.Back()
		c.order.Remove(oldest)
		delete(c.items, oldest.Value.(*cacheEntry).key)
	}
}

// PIIModelNotInstalled reports that the AI Guard runs without the model.
func (e *Engine) PIIModelNotInstalled() bool {
	last := e.piiNotInstalled.Load()
	return last > 0 && time.Since(time.Unix(last, 0)) < 5*time.Minute
}

// PIIModelDegraded reports a model failure in the last five minutes.
func (e *Engine) PIIModelDegraded() bool {
	last := e.piiFailure.Load()
	return last > 0 && time.Since(time.Unix(last, 0)) < 5*time.Minute
}

func nonOverlapping(out []Finding) []Finding {
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Start == out[j].Start {
			return out[i].End > out[j].End
		}
		return out[i].Start < out[j].Start
	})
	filtered := out[:0]
	last := -1
	for _, f := range out {
		if f.Start >= last {
			filtered = append(filtered, f)
			last = f.End
		}
	}
	return filtered
}
