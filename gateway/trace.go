package gateway

import (
	"fmt"
	"strings"
)

type traceInput struct {
	req           EvaluateRequest
	policy        Policy
	permission    string
	resp          EvaluateResponse
	resourceNotes []string
	sessionReason string
	steps         int
	budget        BudgetResult
	secret, pii   bool
	redacted      int
	threats       []ThreatHit
	signatures    int
	canaries      int
	scores        SemanticScores
	escalated     bool
	memoryWrite   bool
}

func f64(v float64) *float64 { return &v }

// buildTrace explains the verdict as an ordered list of checks, so security
// staff can see which control decided, with which score and threshold.
func buildTrace(in traceInput) []TraceStep {
	var out []TraceStep
	add := func(check, result, detail string, score, threshold *float64) {
		out = append(out, TraceStep{Check: check, Result: result, Detail: detail, Score: score, Threshold: threshold})
	}
	reasons := strings.Join(in.resp.Reasons, " | ")
	has := func(sub string) bool { return strings.Contains(reasons, sub) }

	add("identity", "pass", in.req.User.ID+" / "+in.req.User.Role+" via "+in.req.Agent.ID, nil, nil)
	switch {
	case has("unknown action"), has("unknown agent"), has("missing effective permission"):
		add("permissions", "fail", firstMatch(in.resp.Reasons, "unknown action", "unknown agent", "missing effective permission"), nil, nil)
	default:
		add("permissions", "pass", "user ∩ agent grants "+in.permission, nil, nil)
	}
	if in.req.Agent.Model != "" || in.req.Action == "llm.generate" {
		if has("model") {
			add("model allowlist", "fail", firstMatch(in.resp.Reasons, "model"), nil, nil)
		} else {
			add("model allowlist", "pass", in.req.Agent.Model+" allowed", nil, nil)
		}
	}
	if len(in.resourceNotes) > 0 {
		result := "flag"
		if has("resource policy") && in.resp.Decision == Block {
			result = "fail"
		}
		add("resource policy", result, "matched "+strings.Join(in.resourceNotes, ", "), nil, nil)
	}
	if in.sessionReason != "" {
		add("session", "fail", in.sessionReason, nil, nil)
	} else {
		add("session", "pass", fmt.Sprintf("step %d", in.steps), nil, nil)
	}
	switch {
	case in.budget.Reason != "":
		add("budget & runaway limits", "fail", in.budget.Reason, nil, nil)
	case len(in.budget.Warnings) > 0:
		add("budget & runaway limits", "flag", strings.Join(in.budget.Warnings, "; "), nil, nil)
	default:
		add("budget & runaway limits", "pass", "within limits", nil, nil)
	}
	sec := in.policy.Security
	if !sec.PII.Enabled {
		add("personal data", "skip", "control disabled", nil, nil)
	} else if in.pii {
		add("personal data", "flag", fmt.Sprintf("detected · action %s · %d item(s) redacted", sec.PII.Action, in.redacted), nil, nil)
	} else {
		add("personal data", "pass", "none detected", nil, nil)
	}
	if !sec.Secrets.Enabled {
		add("secrets", "skip", "control disabled", nil, nil)
	} else if in.secret {
		add("secrets", resultFor(sec.Secrets.Action), "detected · action "+sec.Secrets.Action, nil, nil)
	} else {
		add("secrets", "pass", "none detected", nil, nil)
	}
	if len(in.threats) > 0 {
		ids := make([]string, 0, len(in.threats))
		result := "flag"
		for _, h := range in.threats {
			ids = append(ids, h.ID)
			if h.Action == "block" {
				result = "fail"
			}
		}
		add("threat signatures", result, "matched "+strings.Join(ids, ", "), nil, nil)
	} else {
		add("threat signatures", "pass", fmt.Sprintf("0 of %d signatures matched", in.signatures), nil, nil)
	}
	if in.canaries > 0 {
		add("honeytokens", "fail", "honeytoken from Ghost Shell detected", nil, nil)
	}
	if !in.escalated {
		add("semantic analysis", "skip", "deterministic fast path (short, low-risk request)", nil, nil)
	} else {
		threshold := func(c Control, name string, score float64, below bool) {
			if !c.Enabled {
				add(name, "skip", "control disabled", nil, nil)
				return
			}
			hit := score >= c.Threshold
			if below {
				hit = score < c.Threshold
			}
			result := "pass"
			if hit {
				result = resultFor(c.Action)
			}
			add(name, result, "", f64(round3(score)), f64(c.Threshold))
		}
		threshold(sec.PromptInjection, "prompt injection", in.scores.PromptInjection, false)
		threshold(sec.DataExfiltration, "data exfiltration", in.scores.DataExfiltration, false)
		if in.req.OriginalIntent != "" {
			threshold(sec.IntentLock, "intent lock (alignment)", in.scores.IntentAlignment, true)
		}
		if in.memoryWrite {
			threshold(sec.MemoryPoisoning, "memory poisoning", in.scores.MemoryPoisoning, false)
		}
	}
	if sec.PrivilegeDrift.Enabled {
		result := "pass"
		if in.scores.PrivilegeDrift >= sec.PrivilegeDrift.Threshold {
			result = resultFor(sec.PrivilegeDrift.Action)
		}
		add("privilege drift", result, "", f64(round3(in.scores.PrivilegeDrift)), f64(sec.PrivilegeDrift.Threshold))
	}
	tier, result := "low → no escalation", "pass"
	switch {
	case in.resp.Risk >= in.policy.Risk.Critical:
		tier, result = "critical → BLOCK", "fail"
	case in.resp.Risk >= in.policy.Risk.High:
		tier, result = "high → human approval", "flag"
	case in.resp.Risk >= in.policy.Risk.Medium:
		tier, result = "medium → Ghost Session", "flag"
	}
	add("risk engine", result, tier, f64(round3(in.resp.Risk)), f64(in.policy.Risk.Medium))
	add("decision", decisionResult(in.resp.Decision), string(in.resp.Decision), nil, nil)
	return out
}

func resultFor(action string) string {
	switch strings.ToLower(action) {
	case "log":
		return "flag"
	case "block":
		return "fail"
	default:
		return "flag"
	}
}

func decisionResult(d Decision) string {
	switch d {
	case Allow:
		return "pass"
	case Block, Throttle:
		return "fail"
	default:
		return "flag"
	}
}

func firstMatch(reasons []string, subs ...string) string {
	for _, r := range reasons {
		for _, s := range subs {
			if strings.Contains(r, s) {
				return r
			}
		}
	}
	return ""
}

func round3(v float64) float64 { return float64(int(v*1000+0.5)) / 1000 }
