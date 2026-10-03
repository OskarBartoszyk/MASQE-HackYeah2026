package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Engine struct {
	Config    *ConfigManager
	Store     *Store
	Semantic  SemanticAnalyzer
	Explainer ExplanationGenerator

	explainOnce     sync.Once
	explainSlots    chan struct{}
	explainWG       sync.WaitGroup
	semanticFailure atomic.Int64
}

// MaxConcurrentExplanations bounds the local LLM explainer so denied or
// throttled traffic cannot be amplified into unbounded model calls.
const MaxConcurrentExplanations = 2

func (e *Engine) Evaluate(ctx context.Context, req EvaluateRequest) (EvaluateResponse, error) {
	started := time.Now()
	snap, err := e.Config.Snapshot()
	if err != nil {
		return EvaluateResponse{}, err
	}
	p := applyStrictness(snap.Policy)
	if req.RequestID == "" {
		req.RequestID = newID("req")
	}
	if req.SessionID == "" {
		req.SessionID = newID("ses")
	}
	// Inspect and forward only canonical text: invisible characters and
	// full-width look-alikes cannot hide a signature or an identifier.
	req.Prompt = Canonicalize(req.Prompt)
	req.Resource = Canonicalize(req.Resource)
	req.OriginalIntent = Canonicalize(req.OriginalIntent)
	for k, v := range req.Metadata {
		req.Metadata[k] = Canonicalize(v)
	}
	resp := EvaluateResponse{RequestID: req.RequestID, SessionID: req.SessionID, Decision: Allow, Reasons: []string{}, PolicyVersion: p.Version + "+" + snap.Hash, PolicyReloadedAt: snap.ReloadedAt.Format(time.RFC3339Nano)}
	controls := map[string]bool{}
	deny := func(control, reason string) {
		controls[control] = true
		resp.Reasons = append(resp.Reasons, reason)
		resp.Decision = Block
	}
	act := func(control, reason, action string) {
		controls[control] = true
		resp.Reasons = append(resp.Reasons, reason)
		applyAction(&resp, action)
	}

	// --- Identity and authorization: USER ∩ AGENT ∩ ORGANIZATION ∩ RESOURCE.
	detStarted := time.Now()
	userPerms := uniqueSorted(p.Roles[req.User.Role].Permissions)
	agentCfg, agentKnown := p.Agents[req.Agent.ID]
	agentPerms := agentCfg.Permissions
	if len(req.Agent.Permissions) > 0 {
		agentPerms = intersection(agentPerms, req.Agent.Permissions)
	}
	resp.EffectivePermissions = intersection(userPerms, agentPerms)
	action, actionKnown := p.Actions[req.Action]
	if !actionKnown {
		deny("permission", "unknown action")
	}
	if !agentKnown {
		deny("permission", "unknown agent")
	}
	permission := action.Permission
	if permission == "" {
		permission = req.Action
	}
	if !contains(resp.EffectivePermissions, permission) {
		deny("permission", "missing effective permission: "+permission)
	}
	if req.Agent.Model != "" && !contains(p.AllowedModels, req.Agent.Model) {
		deny("model", "model is not allowed: "+req.Agent.Model)
	}
	if req.Action == "llm.generate" {
		if req.Agent.Model == "" {
			deny("model", "llm.generate requires an allowed model")
		} else if _, ok := p.ModelProviders[req.Agent.Model]; !ok {
			deny("model", "model has no configured provider: "+req.Agent.Model)
		}
	}
	sensitivity := action.Sensitivity
	var resourceDecision string
	for _, rule := range matchResources(p.Resources, req.Action, req.Resource) {
		label := rule.ID
		if label == "" {
			label = rule.Pattern
		}
		if rule.Sensitivity > sensitivity {
			sensitivity = rule.Sensitivity
		}
		if rule.Permission != "" && !contains(resp.EffectivePermissions, rule.Permission) {
			deny("resource", fmt.Sprintf("resource policy %s requires permission %s", label, rule.Permission))
		}
		switch strings.ToLower(rule.Decision) {
		case "block":
			deny("resource", fmt.Sprintf("resource policy %s: %s", label, firstNonEmpty(rule.Reason, "access denied")))
		case "require_approval", "ghost":
			if resourceDecision != "require_approval" {
				resourceDecision = strings.ToLower(rule.Decision)
			}
			controls["resource"] = true
			resp.Reasons = append(resp.Reasons, fmt.Sprintf("resource policy %s: %s", label, firstNonEmpty(rule.Reason, rule.Decision)))
		}
	}
	authorizationDenied := resp.Decision == Block

	// --- Session: server-side step counter and cross-session drift history.
	principal := req.User.ID + ":" + req.Agent.ID
	session, reason := e.Store.AcquireSession(principal+":"+req.SessionID, principal, req.OriginalIntent, p.Sessions, !req.DryRun)
	if reason != "" {
		if strings.Contains(reason, "rate") {
			controls["runaway"] = true
			resp.Reasons = append(resp.Reasons, reason)
			applyAction(&resp, "throttle")
		} else {
			deny("session", reason)
		}
	}
	req.OriginalIntent = session.OriginalIntent
	if session.Steps > req.Usage.Steps {
		req.Usage.Steps = session.Steps
	}
	if session.Steps > req.Usage.ToolCalls {
		req.Usage.ToolCalls = session.Steps
	}

	// --- Budgets. Denied requests consume no tokens and only count against
	// the caller's own rate limit, so nobody can drain a shared budget.
	userLimits := p.UserDefaultBudget
	if l, ok := p.UserBudgets[req.User.ID]; ok {
		userLimits = l
	}
	scopes := []BudgetScope{{Subject: "global", Limits: p.Budgets}, {Subject: "user:" + req.User.ID, Limits: mergeLimits(p.Budgets, userLimits)}, {Subject: "agent:" + req.Agent.ID, Limits: mergeLimits(p.Budgets, agentCfg.Limits)}}
	if req.Agent.Model != "" {
		scopes = append(scopes, BudgetScope{Subject: "model:" + req.Agent.Model, Limits: mergeLimits(p.Budgets, p.ModelBudgets[req.Agent.Model])})
	}
	budgetScopes, budgetUsage := scopes, req.Usage
	if authorizationDenied || resp.Decision == Block {
		budgetScopes = scopes[1:2]
		budgetUsage = Usage{}
	}
	budget, err := e.Store.CheckAndReserve(budgetScopes, budgetUsage, p.BudgetAlerts)
	if err != nil {
		return EvaluateResponse{}, dbErr(err)
	}
	resp.Warnings = append(resp.Warnings, budget.Warnings...)
	if budget.Reason != "" {
		resp.Reasons = append(resp.Reasons, budget.Reason)
		if budget.Throttle {
			controls["budget"] = true
			applyAction(&resp, "throttle")
		} else {
			control := "budget"
			if strings.Contains(budget.Reason, "steps") || strings.Contains(budget.Reason, "tool calls") || strings.Contains(budget.Reason, "runtime") {
				control = "runaway"
			}
			deny(control, budget.Reason)
		}
	} else if !authorizationDenied {
		resp.reserved, resp.scopes = budgetUsage, budgetScopes
	}

	// --- Deterministic content guards (input).
	findings := ScanSensitive(req.Prompt)
	var redactable []Finding
	secret, pii := false, false
	for _, f := range findings {
		if isSecretKind(f.Kind) {
			secret = true
			if p.Security.Secrets.Enabled {
				redactable = append(redactable, f)
			}
		} else {
			pii = true
			if p.Security.PII.Enabled {
				redactable = append(redactable, f)
			}
		}
	}
	for _, field := range []string{req.Resource, req.OriginalIntent, metadataText(req.Metadata)} {
		for _, f := range ScanSensitive(field) {
			if isSecretKind(f.Kind) {
				secret = true
			}
		}
	}
	if secret && p.Security.Secrets.Enabled {
		act("secrets", "secret detected", p.Security.Secrets.Action)
	}
	if pii && p.Security.PII.Enabled {
		reason := "personal data detected"
		if req.Metadata["direction"] == "output" {
			reason = "personal data detected in output"
		}
		act("pii", reason, p.Security.PII.Action)
	}
	// Redaction is applied whatever the final decision is, so escalating to
	// GHOST or REQUIRE_APPROVAL can never forward raw personal data.
	if len(redactable) > 0 {
		resp.RedactedPrompt = RedactText(req.Prompt, redactable)
	}
	for _, hit := range MatchThreats([]string{req.Prompt, req.Resource, req.Action, req.OriginalIntent, metadataText(req.Metadata)}, snap.compiled) {
		reason := hit.ID + ": threat signature matched"
		if hit.Severity != "" {
			reason += " (" + hit.Severity + ")"
		}
		act("threat:"+hit.ID, reason, hit.Action)
	}
	memoryScore := 0.0
	if req.Action == "memory.write" {
		memoryScore = memoryPoisonScore(req.Prompt)
	}
	resp.Timings.DeterministicMS = ms(time.Since(detStarted))

	// --- Semantic guard.
	history := session.History
	scores := SemanticScores{IntentAlignment: 1, Signals: []string{"deterministic-fast-path"}}
	if shouldEscalateSemantic(req, action, session) {
		resp.SemanticEscalated = true
		semStarted := time.Now()
		var semErr error
		scores, semErr = e.Semantic.Analyze(ctx, SemanticRequest{Prompt: req.Prompt, OriginalIntent: req.OriginalIntent, Action: req.Action, Resource: req.Resource, History: history})
		resp.Timings.SemanticMS = ms(time.Since(semStarted))
		if semErr != nil {
			return EvaluateResponse{}, semErr
		}
		if contains(scores.Signals, "semantic-service-unavailable") {
			e.semanticFailure.Store(time.Now().Unix())
		}
	}
	scores.MemoryPoisoning = maxFloat(scores.MemoryPoisoning, memoryScore)
	if req.Action != "memory.write" {
		scores.MemoryPoisoning = 0
	}
	drift := maxFloat(
		sequenceDrift(session.Sensitivity, session.History, sensitivity, req.Action),
		sequenceDrift(session.PrincipalSensitivity, session.PrincipalHistory, sensitivity, req.Action),
	)
	scores.PrivilegeDrift = maxFloat(scores.PrivilegeDrift, drift)

	// Aggregate risk only from enabled controls, so switching a guard off in
	// policy.yaml really removes its influence on the verdict.
	sec := p.Security
	risk := maxFloat(action.Risk, sensitivity*0.6)
	if sec.PromptInjection.Enabled {
		risk = maxFloat(risk, scores.PromptInjection)
	}
	if sec.DataExfiltration.Enabled {
		risk = maxFloat(risk, scores.DataExfiltration)
	}
	if sec.IntentLock.Enabled && req.OriginalIntent != "" {
		risk = maxFloat(risk, 1-scores.IntentAlignment)
	}
	if sec.PrivilegeDrift.Enabled {
		risk = maxFloat(risk, scores.PrivilegeDrift)
	}
	if sec.MemoryPoisoning.Enabled {
		risk = maxFloat(risk, scores.MemoryPoisoning)
	}
	scores.Risk = risk
	resp.Semantic = scores
	resp.Risk = risk
	if sec.PromptInjection.Enabled && scores.PromptInjection >= sec.PromptInjection.Threshold {
		act("prompt_injection", "prompt injection threshold exceeded", sec.PromptInjection.Action)
	}
	if sec.DataExfiltration.Enabled && scores.DataExfiltration >= sec.DataExfiltration.Threshold {
		act("data_exfiltration", "data exfiltration threshold exceeded", sec.DataExfiltration.Action)
	}
	if sec.IntentLock.Enabled && req.OriginalIntent != "" && scores.IntentAlignment < sec.IntentLock.Threshold {
		act("intent_lock", "intent lock violation", sec.IntentLock.Action)
	}
	if sec.PrivilegeDrift.Enabled && scores.PrivilegeDrift >= sec.PrivilegeDrift.Threshold {
		act("privilege_drift", "privilege drift detected", sec.PrivilegeDrift.Action)
	}
	if sec.MemoryPoisoning.Enabled && scores.MemoryPoisoning >= sec.MemoryPoisoning.Threshold {
		act("memory_poisoning", "memory poisoning attempt detected", sec.MemoryPoisoning.Action)
	}

	// --- Risk tiers: when trust decreases, isolation increases.
	if resp.Decision != Block && resp.Decision != Throttle {
		switch {
		case resp.Risk >= p.Risk.Critical:
			controls["risk"] = true
			resp.Decision = Block
			resp.Reasons = append(resp.Reasons, "critical aggregate risk")
		case action.RequireApproval || resourceDecision == "require_approval" || resp.Risk >= p.Risk.High:
			controls["approval"] = true
			resp.Decision = RequireApproval
			resp.Reasons = append(resp.Reasons, "human approval required")
		case resp.Decision != RequireApproval && p.Ghost.Enabled && (resp.Risk >= p.Risk.Medium || resourceDecision == "ghost"):
			controls["ghost"] = true
			resp.Decision = Ghost
			resp.Reasons = append(resp.Reasons, "elevated risk isolated in Ghost Session")
		}
	}
	if resp.Decision == Ghost {
		resp.GhostSession = &GhostSession{ID: newID("ghost"), ReadOnly: true, NetworkDisabled: true, Credentials: false, AllowedTools: p.Ghost.AllowedActions, ExpiresAt: time.Now().Add(time.Duration(p.Ghost.TTLSeconds) * time.Second).UTC().Format(time.RFC3339)}
	}
	if resp.Decision == RequireApproval && !req.DryRun {
		resp.ApprovalID = newID("apr")
		approvalContext := map[string]any{
			"user": req.User.ID, "role": req.User.Role, "agent": req.Agent.ID,
			"action": req.Action, "resource": RedactAll(req.Resource), "risk": resp.Risk,
			"policy_version": resp.PolicyVersion, "reasons": resp.Reasons,
		}
		if err := e.Store.CreateApproval(resp.ApprovalID, req.RequestID, approvalContext); err != nil {
			return EvaluateResponse{}, dbErr(err)
		}
	}
	// A request that will not run gives its reserved tokens back.
	if (resp.Decision == Block || resp.Decision == Throttle) && resp.scopes != nil {
		if err := e.Store.Adjust(resp.scopes, -resp.reserved.Tokens, -resp.reserved.CostUSD); err != nil {
			return EvaluateResponse{}, dbErr(err)
		}
		resp.scopes = nil
	}
	resp.Reasons = uniqueSorted(resp.Reasons)
	if len(resp.Reasons) == 0 {
		resp.Reasons = []string{"policy checks passed"}
	}
	if !req.DryRun {
		e.Store.RecordStep(session.Key, principal, req.Action+" "+RedactAll(req.Resource), sensitivity, p.Sessions)
	}
	resp.Timings.TotalMS = ms(time.Since(started))
	resp.Timings.GatewayMS = maxFloatMS(0, resp.Timings.TotalMS-resp.Timings.SemanticMS)

	explain := resp.Decision != Allow && resp.Decision != Throttle
	switch {
	case !explain:
		resp.Explanation = Explanation{Status: "not_required"}
	case e.Explainer == nil:
		resp.Explanation = Explanation{Status: "unavailable"}
	default:
		resp.Explanation = Explanation{Status: "pending"}
	}
	executionStatus := "VERDICT_ONLY"
	if !req.DryRun {
		executionStatus = "EVALUATED"
	}
	tokens := req.Usage.Tokens
	if resp.Decision == Block || resp.Decision == Throttle {
		tokens = 0
	}
	event := AuditEvent{ID: req.RequestID, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), User: req.User.ID, Role: req.User.Role, Agent: req.Agent.ID, Model: req.Agent.Model, Action: req.Action, Resource: RedactAll(req.Resource), Decision: resp.Decision, Reasons: resp.Reasons, Controls: sortedKeys(controls), PolicyVersion: resp.PolicyVersion, Risk: resp.Risk, Semantic: resp.Semantic, Tokens: tokens, CostUSD: req.Usage.CostUSD, LatencyMS: resp.Timings.TotalMS, GatewayMS: resp.Timings.GatewayMS, DeterministicMS: resp.Timings.DeterministicMS, SemanticMS: resp.Timings.SemanticMS, SemanticEscalated: resp.SemanticEscalated, SessionID: req.SessionID, ExecutionStatus: executionStatus, Explanation: resp.Explanation}
	if resp.Decision == Block || resp.Decision == Throttle {
		event.CostUSD = 0
	}
	if err := e.Store.AddAudit(event); err != nil {
		return EvaluateResponse{}, dbErr(err)
	}
	if explain && e.Explainer != nil {
		e.explainAsync(req, resp, redactable)
	}
	return resp, nil
}

// explainAsync generates the plain-language explanation after the verdict has
// been returned. Decision latency never includes local LLM generation time.
func (e *Engine) explainAsync(req EvaluateRequest, resp EvaluateResponse, redactable []Finding) {
	e.explainOnce.Do(func() { e.explainSlots = make(chan struct{}, MaxConcurrentExplanations) })
	select {
	case e.explainSlots <- struct{}{}:
	default:
		_ = e.Store.UpdateExplanation(resp.RequestID, Explanation{Status: "unavailable"})
		return
	}
	payload := ExplainRequest{Decision: resp.Decision, Reasons: resp.Reasons, Action: req.Action, Resource: RedactAll(req.Resource), Prompt: RedactAll(RedactText(req.Prompt, redactable)), OriginalIntent: RedactAll(req.OriginalIntent), Risk: resp.Risk, Semantic: resp.Semantic}
	e.explainWG.Add(1)
	go func() {
		defer e.explainWG.Done()
		defer func() { <-e.explainSlots }()
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
		defer cancel()
		result := Explanation{Status: "unavailable"}
		if explanation, err := e.Explainer.Explain(ctx, payload); err == nil {
			result = sanitizeExplanation(explanation)
		}
		_ = e.Store.UpdateExplanation(resp.RequestID, result)
	}()
}

// WaitExplanations blocks until in-flight explanations finish (tests, shutdown).
func (e *Engine) WaitExplanations() { e.explainWG.Wait() }

// SemanticDegraded reports whether the semantic service failed recently.
func (e *Engine) SemanticDegraded() bool {
	last := e.semanticFailure.Load()
	return last > 0 && time.Since(time.Unix(last, 0)) < 5*time.Minute
}

var escalationSignals = []string{"ignore", "ignoruj", "zignoruj", "disregard", "forget", "zapomnij", "pretend", "udawaj", "act as", "you are now", "jesteś teraz", "override", "bypass", "obejdź", "omiń", "jailbreak", "dan", "unrestricted", "bez ograniczeń", "dump", "export", "eksport", "secret", "sekret", "credential", "poświadcz", "password", "hasł", "token", "key", "klucz", "admin", "root", "sudo", "external", "zewnętrz", "send", "wyślij", "upload", "system prompt", "instruction", "instrukcj", "authorize", "autoryzuj", "skip", "pomiń", "disable", "wyłącz", "reveal", "ujawnij", "hidden", "ukryt", "all records", "wszystkie", "everything", "delete", "usuń", "base64", "decode"}

// shouldEscalateSemantic keeps the deterministic fast path only for short,
// low-risk requests that carry no instruction-like or exfiltration vocabulary.
func shouldEscalateSemantic(req EvaluateRequest, action ActionPolicy, session SessionState) bool {
	if action.Risk >= .25 || len(session.History) >= 2 || req.Metadata["direction"] == "output" {
		return true
	}
	text := " " + normalize(skeleton(req.Prompt+" "+req.Resource)) + " "
	if len(splitWords(text)) > 8 {
		return true
	}
	for _, signal := range escalationSignals {
		if containsText(text, " "+signal) {
			return true
		}
	}
	return req.OriginalIntent != "" && tokenOverlap(normalize(req.OriginalIntent), normalize(req.Prompt)) < .8
}

// applyAction never weakens a stronger decision. Unknown actions fail closed;
// "log" only records the reason.
func applyAction(resp *EvaluateResponse, action string) {
	switch strings.ToUpper(action) {
	case "LOG":
		return
	case "REQUIRE_APPROVAL":
		if resp.Decision != Block && resp.Decision != Throttle {
			resp.Decision = RequireApproval
		}
	case "GHOST":
		if resp.Decision == Allow || resp.Decision == Redact {
			resp.Decision = Ghost
		}
	case "THROTTLE":
		if resp.Decision != Block {
			resp.Decision = Throttle
		}
	case "REDACT":
		if resp.Decision == Allow {
			resp.Decision = Redact
		}
	default:
		resp.Decision = Block
	}
}

func matchResources(rules []ResourceRule, action, resource string) []ResourceRule {
	var out []ResourceRule
	res := strings.ToLower(resource)
	for _, r := range rules {
		if r.compiled == nil || (len(r.Actions) > 0 && !contains(r.Actions, action)) {
			continue
		}
		if r.compiled.MatchString(res) {
			out = append(out, r)
		}
	}
	return out
}

func mergeLimits(global, scope Limits) Limits {
	out := global
	if scope.DailyTokens > 0 {
		out.DailyTokens = minPositiveInt(out.DailyTokens, scope.DailyTokens)
	}
	if scope.DailyCostUSD > 0 {
		out.DailyCostUSD = minPositiveFloat(out.DailyCostUSD, scope.DailyCostUSD)
	}
	if scope.RequestsPerMinute > 0 {
		out.RequestsPerMinute = minPositiveInt(out.RequestsPerMinute, scope.RequestsPerMinute)
	}
	if scope.MaxToolCalls > 0 {
		out.MaxToolCalls = minPositiveInt(out.MaxToolCalls, scope.MaxToolCalls)
	}
	if scope.MaxSteps > 0 {
		out.MaxSteps = minPositiveInt(out.MaxSteps, scope.MaxSteps)
	}
	if scope.MaxRuntimeMS > 0 {
		out.MaxRuntimeMS = minPositiveInt(out.MaxRuntimeMS, scope.MaxRuntimeMS)
	}
	return out
}
func minPositiveInt(a, b int) int {
	if a <= 0 || b < a {
		return b
	}
	return a
}
func minPositiveFloat(a, b float64) float64 {
	if a <= 0 || b < a {
		return b
	}
	return a
}

// outboundActions weights how strongly an action moves data outside after it
// was collected. E-mail is weighted lower because reading a customer and then
// replying is a normal support workflow.
var outboundActions = map[string]float64{"api.external.call": 0.45, "customer.export": 0.45, "database.export": 0.45, "email.send": 0.25}

// sequenceDrift scores escalation in a behaviour sequence rather than its
// length: new sensitivity high-water marks, a staircase of escalations, and an
// outbound action after data access (the classic collect-then-exfiltrate chain).
func sequenceDrift(previous []float64, history []string, current float64, action string) float64 {
	if len(previous) == 0 {
		return 0
	}
	maxPrev := 0.0
	for _, v := range previous {
		if v > maxPrev {
			maxPrev = v
		}
	}
	drift := 0.0
	if current > maxPrev {
		drift += (current - maxPrev) * 0.8
	}
	high := previous[0]
	climbs := 0
	for _, v := range append(append([]float64{}, previous[1:]...), current) {
		if v > high+0.05 {
			climbs++
			high = v
		}
	}
	drift += minFloat(0.3, 0.1*float64(climbs))
	if weight := outboundActions[action]; weight > 0 {
		for _, h := range history {
			if strings.HasPrefix(h, "customer.") || strings.HasPrefix(h, "database.") || strings.HasPrefix(h, "memory.read") || strings.HasPrefix(h, "documents.read") {
				drift += weight
				break
			}
		}
	}
	return min1(drift)
}

func metadataText(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	parts := make([]string, 0, len(m))
	for k, v := range m {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, " ")
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return uniqueSorted(out)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
func newID(prefix string) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(b[:]))
}
func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
func maxFloatMS(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
