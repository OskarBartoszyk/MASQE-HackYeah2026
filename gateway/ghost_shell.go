package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Ghost Shell is an explicitly simulated tool, never a route to a host shell.
// Ordinary execution policies remain unchanged. Console requests to this tool
// authorize observation inside a synthetic repository, not the depicted action.
func ghostCall(ctx context.Context, body map[string]any) (map[string]any, int, error) {
	endpoint := os.Getenv("MASQE_AI_GUARD_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8090"
	}
	key := os.Getenv("MASQE_INTERNAL_KEY")
	if key == "" {
		return nil, 503, fmt.Errorf("Ghost Shell internal authentication is not configured")
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, 500, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(endpoint, "/")+"/ghost", bytes.NewReader(data))
	if err != nil {
		return nil, 503, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MASQE-Internal", key)
	timeout := 8 * time.Second
	if body["op"] == "plan" || body["op"] == "explain" {
		timeout = 50 * time.Second
	}
	response, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return nil, 503, fmt.Errorf("Ghost Shell service unavailable")
	}
	defer response.Body.Close()
	var result map[string]any
	if err = json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(&result); err != nil {
		return nil, 503, fmt.Errorf("invalid Ghost Shell response")
	}
	return result, response.StatusCode, nil
}

// --- Honeytoken registry ------------------------------------------------------

// CanaryInfo is a synthetic credential planted in a Ghost Shell session.
type CanaryInfo struct {
	Token, Kind, Session, Owner, Agent string
}

// canaryRegistry caches every active honeytoken so the gateway can recognise
// them in any channel (prompts, e-mail, API calls, tool output), not only in
// the shell where they were planted.
type canaryRegistry struct {
	mu      sync.Mutex
	items   []CanaryInfo
	fetched time.Time
}

var canaries = &canaryRegistry{}

const canaryRefresh = 3 * time.Second

func (c *canaryRegistry) snapshot(ctx context.Context) []CanaryInfo {
	c.mu.Lock()
	items, stale := c.items, time.Since(c.fetched) > canaryRefresh
	c.mu.Unlock()
	if !stale || os.Getenv("MASQE_INTERNAL_KEY") == "" {
		return items
	}
	cctx, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
	defer cancel()
	result, code, err := ghostCall(cctx, map[string]any{"op": "canaries", "owner": "__gateway__"})
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fetched = time.Now()
	if err != nil || code != 200 {
		return c.items // keep the last known registry when the service is slow
	}
	list, _ := result["canaries"].([]any)
	next := make([]CanaryInfo, 0, len(list))
	for _, raw := range list {
		m, _ := raw.(map[string]any)
		token, _ := m["token"].(string)
		if len(token) < 12 {
			continue
		}
		next = append(next, CanaryInfo{Token: token, Kind: fmt.Sprint(m["kind"]), Session: fmt.Sprint(m["session"]), Owner: fmt.Sprint(m["owner"]), Agent: fmt.Sprint(m["agent"])})
	}
	c.items = next
	return next
}

func (c *canaryRegistry) invalidate() {
	c.mu.Lock()
	c.fetched = time.Time{}
	c.mu.Unlock()
}

// findCanaries looks for honeytokens in the texts, their decoded payloads and
// their base64 form.
func findCanaries(items []CanaryInfo, texts ...string) []CanaryInfo {
	if len(items) == 0 {
		return nil
	}
	var corpus []string
	for _, t := range texts {
		if t == "" {
			continue
		}
		corpus = append(corpus, t)
		for _, blob := range DecodedPayloads(t) {
			corpus = append(corpus, blob.Text)
		}
	}
	var hits []CanaryInfo
	for _, item := range items {
		encoded := base64.StdEncoding.EncodeToString([]byte(item.Token))
		for _, t := range corpus {
			if strings.Contains(t, item.Token) || strings.Contains(t, encoded) {
				hits = append(hits, item)
				break
			}
		}
	}
	return hits
}

// reportCanaryUse opens or extends the incident of the session that planted
// the honeytoken. It runs in the background so decisions are never delayed.
func reportCanaryUse(hits []CanaryInfo, channel, user, agent string) {
	for _, hit := range hits {
		go func(h CanaryInfo) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, _, _ = ghostCall(ctx, map[string]any{"op": "external_hit", "owner": "__gateway__", "security": true, "id": h.Session, "kind": h.Kind, "channel": channel, "user": user, "agent": agent})
		}(hit)
	}
}

// --- HTTP handlers ------------------------------------------------------------

func (s *Server) ghostSession(w http.ResponseWriter, r *http.Request) {
	identity := identityFrom(r.Context())
	snap, err := s.Engine.Config.Snapshot()
	if err != nil {
		writeError(w, 503, "policy unavailable")
		return
	}
	body := map[string]any{"owner": identity.UserID, "id": r.PathValue("id"), "security": contains(consolePermissions(snap.Policy, identity.Role), "audit.read_all")}
	switch {
	case r.Method == "POST" && r.PathValue("id") == "":
		var input struct {
			Agent string `json:"agent"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input) != nil || !contains(identity.Agents, input.Agent) {
			writeError(w, 422, "assigned agent is required")
			return
		}
		if !snap.Policy.Ghost.Enabled || !contains(snap.Policy.Roles[identity.Role].Permissions, "shell.exec") || !contains(snap.Policy.Agents[input.Agent].Permissions, "shell.exec") {
			writeError(w, 403, "Ghost Shell permission required")
			return
		}
		body["op"], body["agent"], body["ttl"] = "create", input.Agent, maxInt(30, snap.Policy.Ghost.TTLSeconds)
	case strings.HasSuffix(r.URL.Path, "/explain"):
		body["op"] = "explain"
	case r.Method == "POST":
		body["op"] = "terminate"
	case r.PathValue("id") == "":
		body["op"] = "list"
	default:
		body["op"] = "get"
	}
	result, code, err := ghostCall(r.Context(), body)
	if err != nil {
		writeError(w, code, err.Error())
		return
	}
	if body["op"] == "create" && code == 200 {
		canaries.invalidate()
		id, _ := result["id"].(string)
		agent, _ := body["agent"].(string)
		if reason := s.Engine.Store.RegisterSession(identity.UserID+":"+agent+":"+id, identity.UserID+":"+agent, ghostIntent, snap.Policy.Sessions); reason != "" {
			_, _, _ = ghostCall(r.Context(), map[string]any{"op": "terminate", "owner": identity.UserID, "id": id})
			writeError(w, 429, reason)
			return
		}
	}
	writeJSON(w, code, result)
}

const ghostIntent = "Analyze repository code quality in the virtual repository"

func (s *Server) ghostAgentStep(w http.ResponseWriter, r *http.Request) {
	identity := identityFrom(r.Context())
	snap, _ := s.Engine.Config.Snapshot()
	if !snap.Policy.Ghost.Enabled || !contains(snap.Policy.Roles[identity.Role].Permissions, "shell.exec") {
		writeError(w, 403, "Ghost Shell permission required")
		return
	}
	state, code, err := ghostCall(r.Context(), map[string]any{"op": "get", "owner": identity.UserID, "id": r.PathValue("id")})
	if err != nil {
		writeError(w, code, err.Error())
		return
	}
	agent, _ := state["agent"].(string)
	if code != 200 || !contains(identity.Agents, agent) || !contains(snap.Policy.Agents[agent].Permissions, "shell.exec") {
		writeError(w, 403, "session unavailable")
		return
	}
	plan, code, err := ghostCall(r.Context(), map[string]any{"op": "plan", "owner": identity.UserID, "id": r.PathValue("id")})
	if err != nil {
		writeError(w, code, err.Error())
		return
	}
	if code != 200 {
		writeJSON(w, code, plan)
		return
	}
	if plan["done"] == true {
		writeJSON(w, 200, map[string]any{"plan": plan})
		return
	}
	command, _ := plan["command"].(string)
	req := EvaluateRequest{SessionID: r.PathValue("id"), User: Principal{ID: identity.UserID, Role: identity.Role}, Agent: Agent{ID: agent, Model: "demo-local"}, Action: "shell.exec", Prompt: command}
	result, err := s.Execution.Execute(r.Context(), req)
	if err != nil {
		writeError(w, statusOf(err, 422), err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"plan": plan, "execution": s.publicExecute(r, result)})
}

// --- Execution ----------------------------------------------------------------

// StatusError carries the HTTP status a rejected request should produce.
type StatusError struct {
	Code int
	Msg  string
}

func (e *StatusError) Error() string { return e.Msg }

func statusOf(err error, fallback int) int {
	if se, ok := err.(*StatusError); ok {
		return se.Code
	}
	return fallback
}

func (s *ExecutionService) executeShell(ctx context.Context, req EvaluateRequest) (ExecuteResponse, error) {
	snap, err := s.Engine.Config.Snapshot()
	if err != nil {
		return ExecuteResponse{}, err
	}
	command := Canonicalize(req.Prompt)
	if len(command) == 0 || len(command) > 4096 || !strings.HasPrefix(req.SessionID, "gs_") {
		return ExecuteResponse{}, &StatusError{422, "a Ghost Shell session and command of 1–4096 bytes are required"}
	}
	if !snap.Policy.Ghost.Enabled {
		s.auditShellRejection(req, snap, "Ghost Shell is disabled by policy", "ghost_shell")
		return ExecuteResponse{}, &StatusError{403, "Ghost Shell is disabled"}
	}
	state, code, err := ghostCall(ctx, map[string]any{"op": "get", "owner": req.User.ID, "id": req.SessionID})
	if err != nil {
		return ExecuteResponse{}, &StatusError{503, err.Error()}
	}
	if code != 200 || state["agent"] != req.Agent.ID || state["status"] != "active" {
		// Touching a session that is not yours (or no longer active) is itself a signal.
		s.auditShellRejection(req, snap, "Ghost Shell session is not available to this user and agent", "session")
		return ExecuteResponse{}, &StatusError{403, "Ghost Shell session is unavailable for this agent"}
	}
	// Synthetic credentials of THIS session are honeytokens: sending them on is
	// exactly what the honeypot must record. Anything else that looks like a
	// real secret or personal data is refused and never reaches the recorder.
	own := map[string]bool{}
	for _, c := range canaries.snapshot(ctx) {
		if c.Session == req.SessionID {
			own[c.Token] = true
		}
	}
	for _, f := range ScanSensitive(command) {
		if isOwnCanary(f.Value, own) {
			continue
		}
		kind := "pii"
		if isSecretKind(f.Kind) {
			kind = "secrets"
		}
		return s.blockShell(req, snap, "real-looking "+strings.ToLower(f.Kind)+" in a Ghost Shell command; use the synthetic files", kind), nil
	}
	// The emulator receives the attack as data; the gateway still records what
	// the command would have been in the real world.
	threats := MatchThreats([]string{command}, snap.compiled)
	MeasureUsage(&req, applyStrictness(snap.Policy))
	envelope := req
	envelope.Prompt, envelope.OriginalIntent, envelope.Resource, envelope.Metadata = ghostIntent, ghostIntent, "virtual/repository", nil
	evaluation, err := s.Engine.Evaluate(ctx, envelope)
	if err != nil {
		return ExecuteResponse{}, err
	}
	result := ExecuteResponse{Evaluation: evaluation}
	if evaluation.Decision != Allow && evaluation.Decision != Redact && evaluation.Decision != Ghost {
		_ = s.Engine.Store.UpdateExecution(evaluation.RequestID, string(evaluation.Decision), 0, "")
		return result, nil
	}
	before := int(numberOf(state["canary_hits"]))
	if err := s.Engine.Store.UpdateExecution(evaluation.RequestID, "RUNNING", 0, ""); err != nil {
		return result, err
	}
	state, code, err = ghostCall(ctx, map[string]any{"op": "exec", "owner": req.User.ID, "agent": req.Agent.ID, "id": req.SessionID, "command": command})
	if err != nil {
		result.ExecutionError = err.Error()
	} else if code != 200 {
		result.ExecutionError = fmt.Sprint(state["error"])
	} else {
		result.Executed = true
		result.Shell = state
		if events, ok := state["events"].([]any); ok && len(events) > 0 {
			last, _ := events[len(events)-1].(map[string]any)
			content, _ := last["content"].(map[string]any)
			result.Result, _ = content["output"].(string)
		}
	}
	controls := []string{"ghost_shell"}
	var reasons []string
	for _, hit := range threats {
		controls = append(controls, "threat:"+hit.ID)
		reasons = append(reasons, hit.ID+": threat signature matched in Ghost Shell (emulated, nothing executed)")
	}
	if after := int(numberOf(state["canary_hits"])); after > before {
		controls = append(controls, "canary")
		reasons = append(reasons, "honeytoken sent to an outbound destination: confirmed exfiltration attempt (captured, nothing sent)")
	}
	decision := ""
	if len(reasons) > 0 {
		// The agent still sees a working shell; the audit shows what really happened.
		decision = string(Ghost)
	}
	_ = s.Engine.Store.AnnotateAudit(evaluation.RequestID, decision, reasons, controls)
	return result, s.Engine.Store.UpdateExecution(evaluation.RequestID, executionStatus(result), 0, "")
}

func isOwnCanary(value string, own map[string]bool) bool {
	for token := range own {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}

func numberOf(v any) float64 {
	f, _ := v.(float64)
	return f
}

func (s *ExecutionService) blockShell(req EvaluateRequest, snap ConfigSnapshot, reason, control string) ExecuteResponse {
	id := s.auditShellRejection(req, snap, reason, control)
	return ExecuteResponse{Evaluation: EvaluateResponse{RequestID: id, SessionID: req.SessionID, Decision: Block, Reasons: []string{reason}, PolicyVersion: snap.Policy.Version + "+" + snap.Hash, Explanation: Explanation{Status: "not_required"}}, ExecutionError: reason}
}

func (s *ExecutionService) auditShellRejection(req EvaluateRequest, snap ConfigSnapshot, reason, control string) string {
	id := newID("req")
	_ = s.Engine.Store.AddAudit(AuditEvent{ID: id, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), User: req.User.ID, Role: req.User.Role, Agent: req.Agent.ID, Action: "shell.exec", Resource: "virtual/repository", Decision: Block, Reasons: []string{reason}, Controls: []string{"ghost_shell", control}, PolicyVersion: snap.Policy.Version + "+" + snap.Hash, Risk: 1, SessionID: req.SessionID, ExecutionStatus: "REJECTED", Explanation: Explanation{Status: "not_required"}})
	return id
}

// openGhostShell turns a GHOST decision on untrusted code into a live,
// isolated workspace: the agent keeps working, every command is emulated and
// recorded, and planted honeytokens reveal any attempt to move data out.
// It returns "" when Ghost Shell is unavailable or not permitted.
func (s *ExecutionService) openGhostShell(ctx context.Context, req EvaluateRequest, p Policy) string {
	if !p.Ghost.Enabled || !contains(p.Roles[req.User.Role].Permissions, "shell.exec") || !contains(p.Agents[req.Agent.ID].Permissions, "shell.exec") {
		return ""
	}
	result, code, err := ghostCall(ctx, map[string]any{"op": "create", "owner": req.User.ID, "agent": req.Agent.ID, "ttl": maxInt(30, p.Ghost.TTLSeconds)})
	if err != nil || code != 200 {
		return ""
	}
	id, _ := result["id"].(string)
	if id == "" {
		return ""
	}
	canaries.invalidate()
	principal := req.User.ID + ":" + req.Agent.ID
	if reason := s.Engine.Store.RegisterSession(principal+":"+id, principal, ghostIntent, p.Sessions); reason != "" {
		_, _, _ = ghostCall(ctx, map[string]any{"op": "terminate", "owner": req.User.ID, "id": id})
		return ""
	}
	return id
}
