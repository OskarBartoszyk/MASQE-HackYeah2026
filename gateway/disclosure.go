package gateway

import (
	"net/http"
	"strings"
)

// Responses are tailored to the caller. Detector scores, thresholds, signature
// IDs and regexes are an oracle: with them an attacker can tune a prompt until
// it lands just below a threshold. Only roles with decision.details (security
// staff) see them; everyone else gets the decision and an actionable reason.

func (s *Server) canSee(r *http.Request, perm string) bool {
	snap, _ := s.Engine.Config.Snapshot()
	return contains(consolePermissions(snap.Policy, identityFrom(r.Context()).Role), perm)
}

// publicReason keeps reasons a legitimate user can act on and folds detector
// internals into neutral categories.
func publicReason(reason string) string {
	r := strings.ToLower(reason)
	switch {
	case strings.Contains(r, "intent lock"):
		return "action does not match the goal of this session"
	case strings.Contains(r, "privilege drift"):
		return "unusual escalation of access in this session"
	case strings.Contains(r, "honeytoken"), strings.Contains(r, "threat signature"), strings.Contains(r, "prompt injection"),
		strings.Contains(r, "data exfiltration"), strings.Contains(r, "memory poisoning"), strings.Contains(r, "aggregate risk"),
		strings.Contains(r, "indirect prompt injection"):
		return "content flagged by security analysis"
	default:
		return reason
	}
}

func publicReasons(reasons []string) []string {
	out := make([]string, 0, len(reasons))
	for _, r := range reasons {
		out = append(out, publicReason(r))
	}
	return uniqueSorted(out)
}

func publicEvaluation(ev EvaluateResponse) EvaluateResponse {
	ev.Reasons = publicReasons(ev.Reasons)
	ev.Semantic = SemanticScores{}
	ev.Risk = 0
	ev.DetailsHidden = true
	ev.Trace = publicTrace(ev.Trace)
	return ev
}

func publicTrace(steps []TraceStep) []TraceStep {
	out := make([]TraceStep, 0, len(steps))
	for _, st := range steps {
		st.Detail = publicReason(st.Detail)
		st.Score, st.Threshold = nil, nil
		out = append(out, st)
	}
	return out
}

func publicAudit(e AuditEvent) AuditEvent {
	e.Reasons = publicReasons(e.Reasons)
	e.Semantic = SemanticScores{}
	e.Risk = 0
	e.DetailsHidden = true
	e.Trace = publicTrace(e.Trace)
	controls := []string{}
	for _, c := range e.Controls {
		if strings.HasPrefix(c, "threat:") {
			c = "threat_signature"
		}
		controls = append(controls, c)
	}
	e.Controls = uniqueSorted(controls)
	return e
}

func (s *Server) publicExecute(r *http.Request, res ExecuteResponse) ExecuteResponse {
	if s.canSee(r, "decision.details") {
		return res
	}
	res.Evaluation = publicEvaluation(res.Evaluation)
	return res
}

func (s *Server) publicEvents(r *http.Request, events []AuditEvent) []AuditEvent {
	if s.canSee(r, "decision.details") {
		return events
	}
	out := make([]AuditEvent, len(events))
	for i, e := range events {
		out[i] = publicAudit(e)
	}
	return out
}

// publicPolicy hides thresholds and signature regexes from roles without
// policy.read_full; control names, actions and limits stay visible.
func publicPolicy(p Policy, feed ThreatFeed, full bool) (Policy, ThreatFeed) {
	p.Clients = nil
	if full {
		return p, feed
	}
	for _, c := range []*Control{&p.Security.PII, &p.Security.Secrets, &p.Security.PromptInjection, &p.Security.DataExfiltration, &p.Security.IntentLock, &p.Security.PrivilegeDrift, &p.Security.MemoryPoisoning, &p.Security.OutputInjection} {
		c.Threshold = 0
	}
	p.Strictness = nil
	p.Risk = RiskPolicy{}
	p.ThreatFeedRemote.URL = ""
	sigs := make([]ThreatSignature, len(feed.Signatures))
	for i, sig := range feed.Signatures {
		sig.Pattern = ""
		sigs[i] = sig
	}
	feed.Signatures = sigs
	return p, feed
}
