package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type ExplainRequest struct {
	Decision       Decision       `json:"decision"`
	Reasons        []string       `json:"reasons"`
	Action         string         `json:"action"`
	Resource       string         `json:"resource"`
	Prompt         string         `json:"prompt"`
	OriginalIntent string         `json:"original_intent"`
	Risk           float64        `json:"risk"`
	Semantic       SemanticScores `json:"semantic"`
}

type ExplanationGenerator interface {
	Explain(context.Context, ExplainRequest) (Explanation, error)
}

// HTTPExplanationClient only transports evidence to the Python service.
// Natural-language explanations are never authored by the Go gateway.
type HTTPExplanationClient struct {
	URL    string
	Client *http.Client
}

func (c HTTPExplanationClient) Explain(ctx context.Context, req ExplainRequest) (Explanation, error) {
	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(c.URL, "/")+"/explain", bytes.NewReader(body))
	if err != nil {
		return Explanation{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 48 * time.Second}
	}
	response, err := client.Do(httpReq)
	if err != nil {
		return Explanation{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Explanation{}, fmt.Errorf("Python explanation service returned HTTP %d", response.StatusCode)
	}
	var explanation Explanation
	if err := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&explanation); err != nil {
		return Explanation{}, err
	}
	if explanation.Status != "generated" || explanation.Title == "" || explanation.Summary == "" || len(explanation.Factors) == 0 {
		return Explanation{}, errors.New("Python explanation response is incomplete")
	}
	return explanation, nil
}

func sanitizeExplanation(ex Explanation) Explanation {
	clean := func(value string, maxLen int) string {
		runes := []rune(strings.TrimSpace(value))
		if len(runes) > maxLen {
			runes = runes[:maxLen]
		}
		text := string(runes)
		return RedactText(text, ScanSensitive(text))
	}
	ex.Title = clean(ex.Title, 100)
	ex.Summary = clean(ex.Summary, 500)
	ex.NextStep = clean(ex.NextStep, 500)
	ex.Model = clean(ex.Model, 80)
	if len(ex.Factors) > 3 {
		ex.Factors = ex.Factors[:3]
	}
	for i := range ex.Factors {
		ex.Factors[i] = clean(ex.Factors[i], 240)
	}
	ex.Status = "generated"
	return ex
}
