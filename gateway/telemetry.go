package gateway

import (
	"database/sql"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

type PostureComponent struct {
	Name   string `json:"name"`
	Points int    `json:"points"`
	Max    int    `json:"max"`
	Detail string `json:"detail"`
}

type BudgetStatus struct {
	Scope        string  `json:"scope"`
	Tokens       int     `json:"tokens"`
	TokenLimit   int     `json:"token_limit"`
	CostUSD      float64 `json:"cost_usd"`
	CostLimitUSD float64 `json:"cost_limit_usd"`
	UsedRatio    float64 `json:"used_ratio"`
	Status       string  `json:"status"`
}

type TelemetryInput struct {
	Policy           Policy
	ConfigError      string
	SemanticDegraded bool
	PendingApprovals int
}

// Telemetry aggregates management and security-team metrics from the audit
// log and today's budget ledger.
func (s *Store) Telemetry(in TelemetryInput) (map[string]any, error) {
	p := in.Policy
	rows, err := s.db.Query(`SELECT decision,COUNT(*) FROM audit_events GROUP BY decision`)
	if err != nil {
		return nil, err
	}
	decisions := map[string]int{}
	total := 0
	for rows.Next() {
		var d string
		var c int
		if err := rows.Scan(&d, &c); err != nil {
			rows.Close()
			return nil, err
		}
		decisions[d] = c
		total += c
	}
	rows.Close()

	var avg, gateway, deterministic, semantic, cost float64
	var tokens, escalations int
	if err := s.db.QueryRow(`SELECT COALESCE(AVG(latency_ms),0),COALESCE(AVG(gateway_ms),0),COALESCE(AVG(deterministic_ms),0),COALESCE(AVG(CASE WHEN semantic_escalated=1 THEN semantic_ms END),0),COALESCE(SUM(tokens),0),COALESCE(SUM(cost_usd),0),COALESCE(SUM(semantic_escalated),0) FROM audit_events`).Scan(&avg, &gateway, &deterministic, &semantic, &tokens, &cost, &escalations); err != nil {
		return nil, err
	}
	latencies, gateways, err := s.recentLatencies(2000)
	if err != nil {
		return nil, err
	}
	since := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339Nano)
	controlCounts, signatureCounts, err := s.controlCounts(since)
	if err != nil {
		return nil, err
	}
	var recent int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE timestamp>=?`, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)).Scan(&recent); err != nil {
		return nil, err
	}
	// Executed without approval although the risk reached the HIGH tier: this
	// should never happen and is the posture's incident signal.
	var unapprovedHighRisk int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE timestamp>=? AND risk>=? AND execution_status LIKE 'EXECUTED%' AND approved_by=''`, since, p.Risk.High).Scan(&unapprovedHighRisk); err != nil {
		return nil, err
	}
	budgets, err := s.budgetStatus(p)
	if err != nil {
		return nil, err
	}
	timeline, err := s.timeline(30)
	if err != nil {
		return nil, err
	}
	var dailyTokens int
	var dailyCost float64
	if err := s.db.QueryRow(`SELECT tokens,cost_usd FROM usage_daily WHERE day=? AND subject='global'`, time.Now().UTC().Format("2006-01-02")).Scan(&dailyTokens, &dailyCost); err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	escalationRate := 0.0
	if total > 0 {
		escalationRate = float64(escalations) / float64(total)
	}
	posture, components := securityPosture(in, unapprovedHighRisk)
	return map[string]any{
		"requests": total, "decisions": decisions,
		"average_latency_ms": avg, "average_gateway_ms": gateway, "average_deterministic_ms": deterministic, "average_semantic_ms": semantic,
		"latency_ms":               map[string]float64{"p50": percentile(latencies, .50), "p95": percentile(latencies, .95), "p99": percentile(latencies, .99)},
		"gateway_overhead_ms":      map[string]float64{"p50": percentile(gateways, .50), "p95": percentile(gateways, .95)},
		"semantic_escalations":     escalations,
		"semantic_escalation_rate": escalationRate, "deterministic_resolution_rate": 1 - escalationRate,
		"tokens": tokens, "cost_usd": cost, "daily_tokens": dailyTokens, "daily_cost_usd": dailyCost,
		"requests_per_second_1m": float64(recent) / 60,
		"controls_triggered_24h": controlCounts, "threat_signatures_24h": signatureCounts,
		"budgets": budgets, "timeline": timeline,
		"pending_approvals": in.PendingApprovals, "unapproved_high_risk_executions_24h": unapprovedHighRisk,
		"high_risk_allowed": unapprovedHighRisk,
		"security_posture":  posture, "posture_components": components,
		"config_error": in.ConfigError, "semantic_degraded": in.SemanticDegraded,
	}, nil
}

func securityPosture(in TelemetryInput, incidents int) (int, []PostureComponent) {
	sec := in.Policy.Security
	all := []Control{sec.PII, sec.Secrets, sec.PromptInjection, sec.DataExfiltration, sec.IntentLock, sec.PrivilegeDrift, sec.MemoryPoisoning, sec.OutputInjection}
	enabled := 0
	for _, c := range all {
		if c.Enabled && !strings.EqualFold(c.Action, "log") {
			enabled++
		}
	}
	modePoints := map[string]int{"strict": 20, "balanced": 15, "permissive": 8}[in.Policy.Mode]
	if modePoints == 0 {
		modePoints = 10
	}
	semPoints, semDetail := 15, "semantic guard reachable"
	if in.SemanticDegraded {
		semPoints, semDetail = 0, "semantic guard failed in the last 5 minutes (fail-closed)"
	}
	cfgPoints, cfgDetail := 10, "configuration valid"
	if in.ConfigError != "" {
		cfgPoints, cfgDetail = 0, "latest edit rejected; previous policy active"
	}
	incPoints := 15 - minInt(15, incidents*5)
	components := []PostureComponent{
		{"Aktywne kontrole", enabled * 40 / len(all), 40, itoa(enabled) + " of " + itoa(len(all)) + " guardrails enforcing"},
		{"Tryb ochrony", modePoints, 20, "mode " + in.Policy.Mode},
		{"Warstwa AI", semPoints, 15, semDetail},
		{"Konfiguracja", cfgPoints, 10, cfgDetail},
		{"Incydenty (24h)", incPoints, 15, itoa(incidents) + " high-risk actions executed without approval"},
	}
	score := 0
	for _, c := range components {
		score += c.Points
	}
	return score, components
}

func (s *Store) recentLatencies(limit int) ([]float64, []float64, error) {
	rows, err := s.db.Query(`SELECT latency_ms,gateway_ms FROM audit_events ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var lat, gw []float64
	for rows.Next() {
		var l, g float64
		if err := rows.Scan(&l, &g); err != nil {
			return nil, nil, err
		}
		lat, gw = append(lat, l), append(gw, g)
	}
	return lat, gw, rows.Err()
}

func (s *Store) controlCounts(since string) (map[string]int, map[string]int, error) {
	rows, err := s.db.Query(`SELECT controls FROM audit_events WHERE timestamp>=? AND (decision<>'ALLOW' OR execution_status='EXECUTED_OUTPUT_BLOCKED')`, since)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	controls, sigs := map[string]int{}, map[string]int{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, nil, err
		}
		var list []string
		_ = json.Unmarshal([]byte(raw), &list)
		for _, c := range list {
			if strings.HasPrefix(c, "threat:") {
				sigs[strings.TrimPrefix(c, "threat:")]++
				controls["threat_signature"]++
			} else {
				controls[c]++
			}
		}
	}
	return controls, sigs, rows.Err()
}

func (s *Store) budgetStatus(p Policy) ([]BudgetStatus, error) {
	day := time.Now().UTC().Format("2006-01-02")
	rows, err := s.db.Query(`SELECT subject,tokens,cost_usd FROM usage_daily WHERE day=?`, day)
	if err != nil {
		return nil, err
	}
	used := map[string][2]float64{}
	for rows.Next() {
		var subject string
		var t int
		var c float64
		if err := rows.Scan(&subject, &t, &c); err != nil {
			rows.Close()
			return nil, err
		}
		used[subject] = [2]float64{float64(t), c}
	}
	rows.Close()
	scopes := map[string]Limits{"global": p.Budgets}
	for name, a := range p.Agents {
		scopes["agent:"+name] = mergeLimits(p.Budgets, a.Limits)
	}
	for name, l := range p.ModelBudgets {
		scopes["model:"+name] = mergeLimits(p.Budgets, l)
	}
	for subject := range used {
		if strings.HasPrefix(subject, "user:") {
			id := strings.TrimPrefix(subject, "user:")
			l, ok := p.UserBudgets[id]
			if !ok {
				l = p.UserDefaultBudget
			}
			scopes[subject] = mergeLimits(p.Budgets, l)
		}
	}
	out := []BudgetStatus{}
	for scope, lim := range scopes {
		u := used[scope]
		b := BudgetStatus{Scope: scope, Tokens: int(u[0]), TokenLimit: lim.DailyTokens, CostUSD: u[1], CostLimitUSD: lim.DailyCostUSD}
		if lim.DailyTokens > 0 {
			b.UsedRatio = u[0] / float64(lim.DailyTokens)
		}
		if lim.DailyCostUSD > 0 && u[1]/lim.DailyCostUSD > b.UsedRatio {
			b.UsedRatio = u[1] / lim.DailyCostUSD
		}
		switch {
		case b.UsedRatio >= 1:
			b.Status = "EXCEEDED"
		case p.BudgetAlerts.ThrottleAt > 0 && b.UsedRatio >= p.BudgetAlerts.ThrottleAt:
			b.Status = "THROTTLE"
		case p.BudgetAlerts.WarnAt > 0 && b.UsedRatio >= p.BudgetAlerts.WarnAt:
			b.Status = "WARN"
		default:
			b.Status = "OK"
		}
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UsedRatio == out[j].UsedRatio {
			return out[i].Scope < out[j].Scope
		}
		return out[i].UsedRatio > out[j].UsedRatio
	})
	return out, nil
}

type TimelinePoint struct {
	Minute     string `json:"minute"`
	Allowed    int    `json:"allowed"`
	Restricted int    `json:"restricted"`
	Blocked    int    `json:"blocked"`
}

func (s *Store) timeline(minutes int) ([]TimelinePoint, error) {
	now := time.Now().UTC().Truncate(time.Minute)
	start := now.Add(-time.Duration(minutes-1) * time.Minute)
	rows, err := s.db.Query(`SELECT substr(timestamp,1,16),decision,COUNT(*) FROM audit_events WHERE timestamp>=? GROUP BY 1,2`, start.Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	points := make([]TimelinePoint, minutes)
	index := map[string]int{}
	for i := range points {
		m := start.Add(time.Duration(i) * time.Minute).Format("2006-01-02T15:04")
		points[i].Minute = m
		index[m] = i
	}
	for rows.Next() {
		var minute, decision string
		var c int
		if err := rows.Scan(&minute, &decision, &c); err != nil {
			return nil, err
		}
		i, ok := index[minute]
		if !ok {
			continue
		}
		switch Decision(decision) {
		case Allow:
			points[i].Allowed += c
		case Block, Throttle:
			points[i].Blocked += c
		default:
			points[i].Restricted += c
		}
	}
	return points, rows.Err()
}

func percentile(values []float64, q float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64{}, values...)
	sort.Float64s(sorted)
	idx := int(q*float64(len(sorted)-1) + 0.5)
	return sorted[idx]
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func itoa(v int) string {
	b, _ := json.Marshal(v)
	return string(b)
}
