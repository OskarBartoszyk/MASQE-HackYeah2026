package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// stream pushes audit events to the console as Server-Sent Events. Clients use
// fetch() streaming so the API key stays in the Authorization header.
func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, 500, "streaming unsupported")
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	ch, cancel := s.Engine.Store.Subscribe()
	defer cancel()
	identity := identityFrom(r.Context())
	all := s.canSee(r, "audit.read_all")
	fmt.Fprint(w, "retry: 3000\n: connected\n\n")
	flusher.Flush()
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case id := <-ch:
			e, err := s.Engine.Store.AuditByID(id)
			if err != nil || (!all && e.User != identity.UserID) {
				continue
			}
			b, _ := json.Marshal(s.publicEvents(r, []AuditEvent{e})[0])
			fmt.Fprintf(w, "event: audit\ndata: %s\n\n", b)
			flusher.Flush()
		}
	}
}

// Incident is one item of the unified incident queue (gateway + Ghost Shell).
type Incident struct {
	ID        string `json:"id"`
	Source    string `json:"source"`
	Type      string `json:"type"`
	Severity  string `json:"severity"`
	User      string `json:"user"`
	Agent     string `json:"agent"`
	OpenedAt  string `json:"opened_at"`
	Ref       string `json:"ref"`
	Summary   string `json:"summary"`
	Status    string `json:"status"`
	Note      string `json:"note,omitempty"`
	UpdatedBy string `json:"updated_by,omitempty"`
}

var incidentStatuses = map[string]bool{"open": true, "acknowledged": true, "resolved": true}

func (s *Server) incidents(w http.ResponseWriter, r *http.Request) {
	list, err := s.collectIncidents(r)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"incidents": list})
}

func (s *Server) collectIncidents(r *http.Request) ([]Incident, error) {
	identity := identityFrom(r.Context())
	all := s.canSee(r, "audit.read_all")
	window := ParseRange(r.URL.Query().Get("range"))
	if r.URL.Query().Get("range") == "" {
		window = ParseRange("7d")
	}
	from := time.Now().Add(-window.Span)
	out := []Incident{}
	ctx, cancel := context.WithTimeout(r.Context(), 800*time.Millisecond)
	defer cancel()
	for _, sess := range ghostStats(ctx).Sessions {
		inc, ok := sess["incident"].(map[string]any)
		owner, _ := sess["owner"].(string)
		if !ok || (!all && owner != identity.UserID) {
			continue
		}
		opened := time.Unix(int64(numberOf(inc["opened_at"])), 0).UTC()
		if opened.Before(from) {
			continue
		}
		agent, _ := sess["agent"].(string)
		kind, _ := inc["type"].(string)
		summary := "Synthetic credentials from Ghost Shell were sent to an outbound destination; nothing left the emulator."
		if kind == "canary_used_outside_ghost" {
			summary = "A honeytoken planted in Ghost Shell appeared in another channel and was blocked."
		}
		if src, _ := inc["source_resource"].(string); src != "" {
			summary += " Correlated source: " + src + "."
		}
		out = append(out, Incident{ID: fmt.Sprint(inc["id"]), Source: "ghost_shell", Type: kind, Severity: fmt.Sprint(inc["severity"]), User: owner, Agent: agent, OpenedAt: opened.Format(time.RFC3339), Ref: fmt.Sprint(sess["id"]), Summary: summary})
	}
	snap, _ := s.Engine.Config.Snapshot()
	severity := map[string]string{}
	for _, sig := range snap.compiled {
		severity[sig.ID] = strings.ToLower(sig.Severity)
	}
	f := AuditFilter{Limit: 1000, Since: from.UTC().Format(time.RFC3339Nano)}
	if !all {
		f.User = identity.UserID
	}
	events, err := s.Engine.Store.Audits(f)
	if err != nil {
		return nil, err
	}
	for _, e := range events {
		if contains(e.Controls, "ghost_shell") {
			continue // covered by the Ghost Shell incident of that session
		}
		kind, sev := "", ""
		for _, c := range e.Controls {
			switch {
			case c == "canary":
				kind, sev = "honeytoken_reuse", "critical"
			case c == "output_injection" && sev != "critical":
				kind, sev = "indirect_prompt_injection", "high"
			case c == "memory_poisoning" && sev != "critical":
				kind, sev = "memory_poisoning", "high"
			case strings.HasPrefix(c, "threat:") && sev != "critical":
				if level := severity[strings.TrimPrefix(c, "threat:")]; level == "critical" || level == "high" {
					kind, sev = "threat_signature", level
				}
			}
		}
		if kind == "" {
			continue
		}
		reasons := e.Reasons
		if !s.canSee(r, "decision.details") {
			reasons = publicReasons(reasons)
		}
		out = append(out, Incident{ID: "EVT-" + strings.TrimPrefix(e.ID, "req_"), Source: "gateway", Type: kind, Severity: sev, User: e.User, Agent: e.Agent, OpenedAt: e.Timestamp, Ref: e.ID, Summary: e.Action + " · " + strings.Join(reasons, "; ")})
	}
	states, err := s.Engine.Store.IncidentStates()
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Status = "open"
		if st, ok := states[out[i].ID]; ok {
			out[i].Status, out[i].Note, out[i].UpdatedBy = st[0], st[1], st[2]
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OpenedAt > out[j].OpenedAt })
	return out, nil
}

func (s *Server) incidentStatus(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Status string `json:"status"`
		Note   string `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil || !incidentStatuses[in.Status] || len(in.Note) > 1000 {
		writeError(w, 422, "status must be open, acknowledged or resolved")
		return
	}
	if err := s.Engine.Store.SetIncidentState(r.PathValue("id"), in.Status, in.Note, identityFrom(r.Context()).UserID); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"id": r.PathValue("id"), "status": in.Status})
}
