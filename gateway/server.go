package gateway

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type identityKey struct{}

func identityFrom(ctx context.Context) ClientPolicy {
	identity, _ := ctx.Value(identityKey{}).(ClientPolicy)
	return identity
}

type Server struct {
	Engine       *Engine
	Execution    *ExecutionService
	DashboardDir string
	logger       *slog.Logger
}

func NewServer(engine *Engine, dashboardDir string) *Server {
	return &Server{Engine: engine, Execution: NewExecutionService(engine), DashboardDir: dashboardDir, logger: slog.Default()}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("POST /v1/sessions", s.auth("", s.openSession))
	mux.HandleFunc("POST /v1/evaluate", s.auth("", s.evaluate))
	mux.HandleFunc("POST /v1/execute", s.auth("", s.execute))
	mux.HandleFunc("GET /v1/approvals", s.auth("", s.approvals))
	mux.HandleFunc("POST /v1/approvals/{id}/approve", s.auth("", s.approve))
	mux.HandleFunc("GET /v1/audit", s.auth("audit.read_own", s.audit))
	mux.HandleFunc("GET /v1/events/{id}", s.auth("audit.read_own", s.event))
	mux.HandleFunc("GET /v1/audit/export.csv", s.auth("audit.export", s.auditCSV))
	mux.HandleFunc("GET /v1/audit/export.json", s.auth("audit.export", s.auditJSON))
	mux.HandleFunc("GET /v1/audit/verify", s.auth("audit.read_all", s.auditVerify))
	mux.HandleFunc("GET /v1/telemetry", s.auth("telemetry.read", s.telemetry))
	mux.HandleFunc("GET /v1/policy", s.auth("policy.read", s.policy))
	mux.HandleFunc("GET /v1/me", s.auth("", s.me))
	mux.HandleFunc("GET /v1/stream", s.auth("audit.read_own", s.stream))
	mux.HandleFunc("GET /v1/incidents", s.auth("audit.read_own", s.incidents))
	mux.HandleFunc("POST /v1/incidents/{id}/status", s.auth("audit.read_all", s.incidentStatus))
	// Integration surfaces: OpenAI-compatible proxy and SDK tool guarding.
	mux.HandleFunc("POST /v1/chat/completions", s.auth("", s.chatCompletions))
	mux.HandleFunc("GET /v1/models", s.auth("", s.models))
	mux.HandleFunc("POST /v1/authorize", s.auth("", s.authorize))
	mux.HandleFunc("POST /v1/outputs", s.auth("", s.outputs))
	mux.HandleFunc("POST /v1/ghost/sessions", s.auth("", s.ghostSession))
	mux.HandleFunc("GET /v1/ghost/sessions", s.auth("audit.read_own", s.ghostSession))
	mux.HandleFunc("GET /v1/ghost/sessions/{id}", s.auth("audit.read_own", s.ghostSession))
	mux.HandleFunc("POST /v1/ghost/sessions/{id}/terminate", s.auth("audit.read_own", s.ghostSession))
	mux.HandleFunc("POST /v1/ghost/sessions/{id}/explain", s.auth("audit.read_own", s.ghostSession))
	mux.HandleFunc("POST /v1/ghost/sessions/{id}/step", s.auth("", s.ghostAgentStep))
	if s.DashboardDir != "" {
		mux.Handle("/", http.FileServer(http.Dir(s.DashboardDir)))
	}
	return s.headers(s.recoverer(mux))
}

// consolePermissions resolves reporting access for the caller's role.
// audit.read_all implies read_own; audit.export implies read_all.
func consolePermissions(p Policy, role string) []string {
	perms := p.Roles[role].Console
	out := append([]string{}, perms...)
	if contains(perms, "audit.export") {
		out = append(out, "audit.read_all")
	}
	if contains(out, "audit.read_all") {
		// Security staff see detector scores, thresholds and signature regexes.
		out = append(out, "audit.read_own", "decision.details", "policy.read_full")
	}
	return uniqueSorted(out)
}

func (s *Server) auth(console string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snap, err := s.Engine.Config.Snapshot()
		if err != nil {
			writeError(w, 503, err.Error())
			return
		}
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == r.Header.Get("Authorization") {
			token = r.Header.Get("X-MASQE-Key")
		}
		identity, valid := snap.Policy.Clients[token]
		if token == "" || !valid {
			writeError(w, 401, "invalid or missing API key")
			return
		}
		if console != "" && !contains(consolePermissions(snap.Policy, identity.Role), console) {
			writeError(w, 403, "role "+identity.Role+" lacks console permission "+console)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, identity)))
	}
}

func decodeRequest(w http.ResponseWriter, r *http.Request) (EvaluateRequest, bool) {
	var req EvaluateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(&req); err != nil {
		writeError(w, 400, "invalid JSON")
		return req, false
	}
	if req.Agent.ID == "" || req.Action == "" {
		writeError(w, 422, "agent.id and action are required")
		return req, false
	}
	if len(req.SessionID) > 128 || len(req.RequestID) > 128 || len(req.Metadata) > 32 {
		writeError(w, 422, "session_id/request_id must be at most 128 characters and metadata at most 32 keys")
		return req, false
	}
	// Request ids are always issued by the gateway so audit rows cannot collide.
	req.RequestID = ""
	if err := bindIdentity(&req, identityFrom(r.Context())); err != nil {
		writeError(w, 403, err.Error())
		return req, false
	}
	return req, true
}

func (s *Server) evaluate(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeRequest(w, r)
	if !ok {
		return
	}
	snap, _ := s.Engine.Config.Snapshot()
	MeasureUsage(&req, applyStrictness(snap.Policy))
	req.DryRun = true
	resp, err := s.Engine.Evaluate(r.Context(), req)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if !s.canSee(r, "decision.details") {
		resp = publicEvaluation(resp)
	}
	writeJSON(w, 200, resp)
}

func bindIdentity(req *EvaluateRequest, identity ClientPolicy) error {
	if req.User.ID != "" && req.User.ID != identity.UserID {
		return fmt.Errorf("user identity does not match API credential")
	}
	if req.User.Role != "" && req.User.Role != identity.Role {
		return fmt.Errorf("role does not match API credential")
	}
	if len(req.User.Permissions) > 0 {
		return fmt.Errorf("client cannot grant user permissions")
	}
	if !contains(identity.Agents, req.Agent.ID) {
		return fmt.Errorf("agent is not assigned to authenticated user")
	}
	req.User = Principal{ID: identity.UserID, Role: identity.Role}
	return nil
}

func (s *Server) execute(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeRequest(w, r)
	if !ok {
		return
	}
	result, err := s.Execution.Execute(r.Context(), req)
	if err != nil {
		writeError(w, statusOf(err, 500), err.Error())
		return
	}
	writeJSON(w, 200, s.publicExecute(r, result))
}

// openSession registers the user's original intent before an agent acts, so
// Intent Lock does not depend on what the agent later claims.
func (s *Server) openSession(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Agent  string `json:"agent"`
		Intent string `json:"intent"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil || body.Agent == "" || strings.TrimSpace(body.Intent) == "" {
		writeError(w, 422, "agent and intent are required")
		return
	}
	identity := identityFrom(r.Context())
	if !contains(identity.Agents, body.Agent) {
		writeError(w, 403, "agent is not assigned to authenticated user")
		return
	}
	snap, _ := s.Engine.Config.Snapshot()
	id := newID("ses")
	principal := identity.UserID + ":" + body.Agent
	if reason := s.Engine.Store.RegisterSession(principal+":"+id, principal, Canonicalize(body.Intent), snap.Policy.Sessions); reason != "" {
		writeError(w, 429, reason)
		return
	}
	writeJSON(w, 201, map[string]any{"session_id": id, "agent": body.Agent, "intent_locked": true})
}

func (s *Server) approvals(w http.ResponseWriter, r *http.Request) {
	list, err := s.Execution.Pending(identityFrom(r.Context()))
	if err != nil {
		writeError(w, 403, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"approvals": list})
}
func (s *Server) approve(w http.ResponseWriter, r *http.Request) {
	result, err := s.Execution.Approve(r.Context(), r.PathValue("id"), identityFrom(r.Context()))
	if err != nil {
		writeError(w, 403, err.Error())
		return
	}
	writeJSON(w, 200, s.publicExecute(r, result))
}

// health is public; it reports liveness and whether the last config edit was
// rejected (the gateway keeps serving the previous valid snapshot).
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	snap, _ := s.Engine.Config.Snapshot()
	status := "ok"
	if snap.Error != "" {
		status = "degraded"
	}
	writeJSON(w, 200, map[string]any{"status": status, "policy_version": snap.Policy.Version, "config_hash": snap.Hash, "config_error": snap.Error, "semantic_degraded": s.Engine.SemanticDegraded(), "pii_model": s.piiModelState(r.Context(), snap.Policy), "time": time.Now().UTC()})
}

func (s *Server) piiModelState(ctx context.Context, p Policy) string {
	if !p.Redaction.UseModel || s.Engine.PII == nil {
		return "disabled"
	}
	if reporter, ok := s.Engine.PII.(PIIStatusReporter); ok {
		ctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		if state := reporter.ModelStatus(ctx); state != "enabled" {
			return state
		}
	}
	switch {
	case s.Engine.PIIModelDegraded():
		return "degraded"
	case s.Engine.PIIModelNotInstalled():
		return "not_installed"
	default:
		return "enabled"
	}
}
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	identity := identityFrom(r.Context())
	snap, _ := s.Engine.Config.Snapshot()
	writeJSON(w, 200, map[string]any{"user_id": identity.UserID, "role": identity.Role, "agents": identity.Agents, "can_approve": identity.CanApprove, "console": consolePermissions(snap.Policy, identity.Role)})
}

func (s *Server) auditFilter(r *http.Request, limit int) AuditFilter {
	q := r.URL.Query()
	if l, err := strconv.Atoi(q.Get("limit")); err == nil {
		limit = l
	}
	f := AuditFilter{Limit: limit, User: q.Get("user"), Decision: q.Get("decision"), Since: q.Get("since")}
	snap, _ := s.Engine.Config.Snapshot()
	identity := identityFrom(r.Context())
	if !contains(consolePermissions(snap.Policy, identity.Role), "audit.read_all") {
		f.User = identity.UserID
	}
	return f
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	f := s.auditFilter(r, 100)
	events, err := s.Engine.Store.Audits(f)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	snap, _ := s.Engine.Config.Snapshot()
	scope := "own"
	if contains(consolePermissions(snap.Policy, identityFrom(r.Context()).Role), "audit.read_all") {
		scope = "all"
	}
	writeJSON(w, 200, map[string]any{"events": s.publicEvents(r, events), "scope": scope})
}

func (s *Server) event(w http.ResponseWriter, r *http.Request) {
	e, err := s.Engine.Store.AuditByID(r.PathValue("id"))
	if err != nil {
		writeError(w, 404, "event not found")
		return
	}
	snap, _ := s.Engine.Config.Snapshot()
	identity := identityFrom(r.Context())
	if e.User != identity.UserID && !contains(consolePermissions(snap.Policy, identity.Role), "audit.read_all") {
		writeError(w, 404, "event not found")
		return
	}
	writeJSON(w, 200, s.publicEvents(r, []AuditEvent{e})[0])
}

func (s *Server) telemetry(w http.ResponseWriter, r *http.Request) {
	snap, _ := s.Engine.Config.Snapshot()
	// Ghost Shell statistics are organisation-wide aggregates (no content), so
	// every role sees the same posture.
	ctx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
	defer cancel()
	stats := ghostStats(ctx)
	m, err := s.Engine.Store.Telemetry(TelemetryInput{Policy: applyStrictness(snap.Policy), ConfigError: snap.Error, SemanticDegraded: s.Engine.SemanticDegraded(), PendingApprovals: s.Execution.PendingCount(), GhostIncidents24h: stats.Incidents24h, Range: r.URL.Query().Get("range")})
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	m["ghost_shell"] = map[string]any{"available": stats.Available, "active_sessions": stats.Active, "incidents": stats.Incidents, "incidents_24h": stats.Incidents24h, "canary_hits": stats.CanaryHits}
	writeJSON(w, 200, m)
}

type GhostStats struct {
	Available                                   bool
	Active, Incidents, Incidents24h, CanaryHits int
	Sessions                                    []map[string]any
}

func ghostStats(ctx context.Context) GhostStats {
	out := GhostStats{}
	result, code, err := ghostCall(ctx, map[string]any{"op": "list", "owner": "__gateway__", "security": true})
	if err != nil || code != 200 {
		return out
	}
	out.Available = true
	since := float64(time.Now().Add(-24 * time.Hour).Unix())
	list, _ := result["sessions"].([]any)
	for _, raw := range list {
		item, _ := raw.(map[string]any)
		out.Sessions = append(out.Sessions, item)
		if item["status"] == "active" {
			out.Active++
		}
		if inc, ok := item["incident"].(map[string]any); ok {
			out.Incidents++
			if numberOf(inc["opened_at"]) >= since {
				out.Incidents24h++
			}
		}
		out.CanaryHits += int(numberOf(item["canary_hits"]))
	}
	return out
}
func (s *Server) policy(w http.ResponseWriter, r *http.Request) {
	snap, _ := s.Engine.Config.Snapshot()
	// API credentials never leave the server; thresholds and signature regexes
	// only for roles with policy.read_full.
	visible, feed := publicPolicy(applyStrictness(snap.Policy), snap.Threats, s.canSee(r, "policy.read_full"))
	writeJSON(w, 200, map[string]any{"policy": visible, "threat_feed": feed, "full": s.canSee(r, "policy.read_full"), "hash": snap.Hash, "reloaded_at": snap.ReloadedAt, "config_error": snap.Error, "config_error_at": snap.ErrorAt, "remote_feed": snap.RemoteFeed})
}

// csvSafe neutralises spreadsheet formulas (CSV injection) in exported cells.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

func (s *Server) auditCSV(w http.ResponseWriter, r *http.Request) {
	events, err := s.Engine.Store.Audits(s.auditFilter(r, 5000))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=masqe-audit.csv")
	if seq, hash := s.Engine.Store.AuditChainHead(); seq > 0 {
		w.Header().Set("X-MASQE-Audit-Chain-Head", strconv.FormatInt(seq, 10)+":"+hash)
	}
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"timestamp", "request_id", "session_id", "user", "role", "agent", "model", "action", "resource", "decision", "execution_status", "approved_by", "reasons", "controls", "policy", "risk", "prompt_injection", "data_exfiltration", "intent_alignment", "privilege_drift", "memory_poisoning", "semantic_escalated", "reserved_tokens", "actual_model_tokens", "cost_usd", "latency_ms", "gateway_ms", "deterministic_ms", "semantic_ms", "pii_model_ms"})
	f3 := func(v float64) string { return strconv.FormatFloat(v, 'f', 3, 64) }
	for _, e := range events {
		row := []string{e.Timestamp, e.ID, e.SessionID, e.User, e.Role, e.Agent, e.Model, e.Action, e.Resource, string(e.Decision), e.ExecutionStatus, e.ApprovedBy, strings.Join(e.Reasons, "; "), strings.Join(e.Controls, "; "), e.PolicyVersion, f3(e.Risk), f3(e.Semantic.PromptInjection), f3(e.Semantic.DataExfiltration), f3(e.Semantic.IntentAlignment), f3(e.Semantic.PrivilegeDrift), f3(e.Semantic.MemoryPoisoning), strconv.FormatBool(e.SemanticEscalated), strconv.Itoa(e.Tokens), strconv.Itoa(e.ActualTokens), strconv.FormatFloat(e.CostUSD, 'f', 6, 64), f3(e.LatencyMS), f3(e.GatewayMS), f3(e.DeterministicMS), f3(e.SemanticMS), f3(e.PIIModelMS)}
		for i := range row {
			row[i] = csvSafe(row[i])
		}
		_ = cw.Write(row)
	}
	cw.Flush()
}

func (s *Server) auditJSON(w http.ResponseWriter, r *http.Request) {
	events, err := s.Engine.Store.Audits(s.auditFilter(r, 5000))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	integrity, err := s.Engine.Store.VerifyAudit()
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=masqe-audit.json")
	writeJSON(w, 200, map[string]any{"exported_at": time.Now().UTC(), "count": len(events), "events": events, "integrity": integrity})
}

// auditVerify recomputes the tamper-evident audit chain (audit_chain.go).
func (s *Server) auditVerify(w http.ResponseWriter, r *http.Request) {
	integrity, err := s.Engine.Store.VerifyAudit()
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, integrity)
}

func (s *Server) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			h.Set("Cache-Control", "no-store")
		}
		// The bundled dashboard is same-origin. Cross-origin access must be
		// explicitly provided by a reverse proxy rather than wildcard CORS.
		next.ServeHTTP(w, r)
	})
}
func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				s.logger.Error("request panic", "error", v)
				writeError(w, 500, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
