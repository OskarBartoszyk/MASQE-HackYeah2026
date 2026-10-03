package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// --- OpenAI-compatible endpoint ----------------------------------------------
//
// Any application using an OpenAI SDK (or LangChain, LlamaIndex, ...) is put
// behind MASQE by changing one line: base_url="http://<masqe>/v1" and
// api_key=<MASQE key>. Every call then passes identity, budgets, the model
// allowlist, PII/secret redaction, injection and output controls.

type chatCompletionRequest struct {
	Model     string        `json:"model"`
	Messages  []ChatMessage `json:"messages"`
	MaxTokens int           `json:"max_tokens"`
	Stream    bool          `json:"stream"`
}

func openAIError(w http.ResponseWriter, status int, kind, code, message string, extra map[string]any) {
	body := map[string]any{"error": map[string]any{"message": message, "type": kind, "code": code}}
	for k, v := range extra {
		body[k] = v
	}
	writeJSON(w, status, body)
}

func (s *Server) chatCompletions(w http.ResponseWriter, r *http.Request) {
	var in chatCompletionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil || in.Model == "" || len(in.Messages) == 0 {
		openAIError(w, 400, "invalid_request_error", "invalid_request", "model and messages are required", nil)
		return
	}
	if in.Stream {
		openAIError(w, 400, "invalid_request_error", "stream_unsupported", "streaming is not supported by the MASQE gateway; use stream=false", nil)
		return
	}
	identity := identityFrom(r.Context())
	agent := r.Header.Get("X-MASQE-Agent")
	if agent == "" && len(identity.Agents) > 0 {
		agent = identity.Agents[0]
	}
	// Developer system prompts are forwarded and scanned for secrets and
	// signatures; user, assistant and tool messages go through every control.
	var conversation, system []string
	firstUser := ""
	for _, m := range in.Messages {
		if m.Role == "system" || m.Role == "developer" {
			system = append(system, m.Content)
			continue
		}
		if m.Role == "user" && firstUser == "" {
			firstUser = m.Content
		}
		conversation = append(conversation, m.Content)
	}
	intent := firstNonEmpty(r.Header.Get("X-MASQE-Intent"), firstUser)
	session := r.Header.Get("X-MASQE-Session")
	if session == "" {
		// Chat clients resend the history, so the first user message identifies
		// the conversation: one session per conversation, not per call.
		sum := sha256.Sum256([]byte(identity.UserID + "\x00" + agent + "\x00" + firstUser))
		session = "chat_" + hex.EncodeToString(sum[:8])
	}
	req := EvaluateRequest{SessionID: session, Agent: Agent{ID: agent, Model: in.Model}, Action: "llm.generate", Resource: "model/" + in.Model, Prompt: strings.Join(conversation, "\n"), OriginalIntent: intent, Messages: in.Messages}
	if len(system) > 0 {
		req.Metadata = map[string]string{"system": strings.Join(system, "\n")}
	}
	if err := bindIdentity(&req, identity); err != nil {
		openAIError(w, 403, "permission_error", "identity", err.Error(), nil)
		return
	}
	result, err := s.Execution.Execute(r.Context(), req)
	if err != nil {
		openAIError(w, statusOf(err, 500), "server_error", "gateway_error", err.Error(), nil)
		return
	}
	result = s.publicExecute(r, result)
	ev := result.Evaluation
	masqe := map[string]any{"request_id": ev.RequestID, "decision": ev.Decision, "reasons": ev.Reasons, "approval_id": ev.ApprovalID, "redacted": ev.RedactedPrompt != ""}
	switch {
	case ev.Decision == Throttle:
		openAIError(w, 429, "rate_limit_error", string(ev.Decision), "MASQE: "+strings.Join(ev.Reasons, "; "), map[string]any{"masqe": masqe})
	case !result.Executed && result.ExecutionError == "":
		openAIError(w, 403, "masqe_policy_violation", string(ev.Decision), "MASQE: "+strings.Join(ev.Reasons, "; "), map[string]any{"masqe": masqe})
	case result.ExecutionError != "" && !result.Executed:
		code := 502
		if ev.Decision == Ghost {
			code = 403
		}
		openAIError(w, code, "masqe_execution_error", string(ev.Decision), "MASQE: "+result.ExecutionError, map[string]any{"masqe": masqe})
	case result.ExecutionError != "":
		masqe["output_findings"] = result.OutputFindings
		openAIError(w, 403, "masqe_output_blocked", "OUTPUT_BLOCKED", "MASQE: "+result.ExecutionError, map[string]any{"masqe": masqe})
	default:
		masqe["output_findings"] = result.OutputFindings
		total := maxInt(result.ActualTokens, 1)
		prompt := minInt(total, maxInt(1, len([]rune(req.Prompt))/4))
		writeJSON(w, 200, map[string]any{
			"id": "chatcmpl-" + ev.RequestID, "object": "chat.completion", "created": time.Now().Unix(), "model": in.Model,
			"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": result.Result}, "finish_reason": "stop"}},
			"usage":   map[string]any{"prompt_tokens": prompt, "completion_tokens": total - prompt, "total_tokens": total},
			"masqe":   masqe,
		})
	}
}

func (s *Server) models(w http.ResponseWriter, r *http.Request) {
	snap, _ := s.Engine.Config.Snapshot()
	data := []any{}
	for _, m := range snap.Policy.AllowedModels {
		data = append(data, map[string]any{"id": m, "object": "model", "owned_by": "masqe:" + snap.Policy.ModelProviders[m].Kind})
	}
	writeJSON(w, 200, map[string]any{"object": "list", "data": data})
}

// --- Authorize / outputs: guarding tools that run in the caller's process ----
//
// The SDK wrapper asks MASQE before running a local tool (authorize) and sends
// the result back for the output guard (outputs). Decisions stay in the
// gateway; execution stays in the application.

type grant struct {
	Request   EvaluateRequest
	Decision  Decision
	ExpiresAt time.Time
}

type grantStore struct {
	mu     sync.Mutex
	grants map[string]grant
}

var externalGrants = &grantStore{grants: map[string]grant{}}

func (g *grantStore) put(id string, gr grant) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	for k, v := range g.grants {
		if now.After(v.ExpiresAt) {
			delete(g.grants, k)
		}
	}
	g.grants[id] = gr
}

// take returns the grant once, and only to the user it was issued to; a tool
// result can be reported a single time and nobody else can consume it.
func (g *grantStore) take(id, user string) (grant, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	gr, ok := g.grants[id]
	if !ok || gr.Request.User.ID != user {
		return grant{}, false
	}
	delete(g.grants, id)
	if time.Now().After(gr.ExpiresAt) {
		return grant{}, false
	}
	return gr, true
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeRequest(w, r)
	if !ok {
		return
	}
	snap, _ := s.Engine.Config.Snapshot()
	p := applyStrictness(snap.Policy)
	MeasureUsage(&req, p)
	ev, err := s.Engine.Evaluate(r.Context(), req)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	allowed := ev.Decision == Allow || ev.Decision == Redact || (ev.Decision == Ghost && contains(p.Ghost.AllowedActions, req.Action))
	status := "AUTHORIZED_EXTERNAL"
	if !allowed {
		status = string(ev.Decision)
		if ev.Decision == RequireApproval {
			status = "PENDING_APPROVAL"
		}
	} else {
		externalGrants.put(ev.RequestID, grant{Request: req, Decision: ev.Decision, ExpiresAt: time.Now().Add(5 * time.Minute)})
	}
	_ = s.Engine.Store.UpdateExecution(ev.RequestID, status, 0, "")
	if !s.canSee(r, "decision.details") {
		ev = publicEvaluation(ev)
	}
	writeJSON(w, 200, map[string]any{"allowed": allowed, "evaluation": ev})
}

func (s *Server) outputs(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RequestID string `json:"request_id"`
		Output    string `json:"output"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil || in.RequestID == "" {
		writeError(w, 422, "request_id and output are required")
		return
	}
	gr, ok := externalGrants.take(in.RequestID, identityFrom(r.Context()).UserID)
	if !ok {
		writeError(w, 404, "no open authorization for this request_id")
		return
	}
	snap, _ := s.Engine.Config.Snapshot()
	res, err := s.Execution.guardOutput(r.Context(), gr.Request, ExecuteResponse{Executed: true}, in.Output, applyStrictness(snap.Policy))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	_ = s.Engine.Store.AddControls(in.RequestID, outputControls(res.OutputFindings))
	_ = s.Engine.Store.UpdateExecution(in.RequestID, executionStatus(res), 0, "")
	writeJSON(w, 200, map[string]any{"allowed": res.ExecutionError == "", "output": res.Result, "reason": res.ExecutionError, "findings": res.OutputFindings})
}
