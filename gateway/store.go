package gateway

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const (
	maxSessions        = 10000
	sessionHistoryCap  = 50
	defaultSessionTTL  = time.Hour
	defaultDriftWindow = 15 * time.Minute
)

type stepRecord struct {
	At          time.Time
	Entry       string
	Sensitivity float64
}

type Store struct {
	db          *sql.DB
	mu          sync.Mutex
	sessions    map[string]*SessionState
	principals  map[string][]stepRecord
	newSessions map[string][]time.Time
	subsMu      sync.Mutex
	subs        map[chan string]struct{}
}
type BudgetScope struct {
	Subject string
	Limits  Limits
}

type BudgetResult struct {
	Reason   string
	Throttle bool
	Warnings []string
}

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path+"?_busy_timeout=5000&_journal_mode=WAL")
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, sessions: map[string]*SessionState{}, principals: map[string][]stepRecord{}, newSessions: map[string][]time.Time{}, subs: map[chan string]struct{}{}}
	db.SetMaxOpenConns(1)
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS audit_events (id TEXT PRIMARY KEY, timestamp TEXT, user_id TEXT, role TEXT, agent TEXT, action TEXT, resource TEXT, decision TEXT, reasons TEXT, policy_version TEXT, risk REAL, semantic TEXT, tokens INTEGER, cost_usd REAL, latency_ms REAL, session_id TEXT, gateway_ms REAL DEFAULT 0, deterministic_ms REAL DEFAULT 0, semantic_ms REAL DEFAULT 0, semantic_escalated INTEGER DEFAULT 0, execution_status TEXT DEFAULT 'VERDICT_ONLY', actual_tokens INTEGER DEFAULT 0, approved_by TEXT DEFAULT '', explanation TEXT DEFAULT '{}', model TEXT DEFAULT '', controls TEXT DEFAULT '[]', trace TEXT DEFAULT '[]')`,
		`CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_events(timestamp DESC)`,
		`CREATE TABLE IF NOT EXISTS usage_daily (day TEXT, subject TEXT, tokens INTEGER NOT NULL DEFAULT 0, cost_usd REAL NOT NULL DEFAULT 0, PRIMARY KEY(day,subject))`,
		`CREATE TABLE IF NOT EXISTS request_window (subject TEXT, timestamp INTEGER)`,
		`CREATE INDEX IF NOT EXISTS idx_window ON request_window(subject, timestamp)`,
		`CREATE TABLE IF NOT EXISTS incident_state (id TEXT PRIMARY KEY, status TEXT NOT NULL, note TEXT DEFAULT '', updated_by TEXT DEFAULT '', updated_at TEXT)`,
		`CREATE TABLE IF NOT EXISTS approvals (id TEXT PRIMARY KEY, request_id TEXT, status TEXT, created_at TEXT, context TEXT)`,
		`CREATE TABLE IF NOT EXISTS demo_customers (id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL, status TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS demo_memory (owner TEXT, key TEXT, value TEXT, PRIMARY KEY(owner,key))`,
		`CREATE TABLE IF NOT EXISTS demo_outbox (id TEXT PRIMARY KEY, sender TEXT, recipient TEXT, body TEXT, created_at TEXT)`,
	}
	for _, q := range stmts {
		if _, err = db.Exec(q); err != nil {
			db.Close()
			return nil, err
		}
	}
	for _, migration := range []string{
		`ALTER TABLE audit_events ADD COLUMN gateway_ms REAL DEFAULT 0`,
		`ALTER TABLE audit_events ADD COLUMN deterministic_ms REAL DEFAULT 0`,
		`ALTER TABLE audit_events ADD COLUMN semantic_ms REAL DEFAULT 0`,
		`ALTER TABLE audit_events ADD COLUMN semantic_escalated INTEGER DEFAULT 0`,
		`ALTER TABLE audit_events ADD COLUMN execution_status TEXT DEFAULT 'VERDICT_ONLY'`,
		`ALTER TABLE audit_events ADD COLUMN actual_tokens INTEGER DEFAULT 0`,
		`ALTER TABLE audit_events ADD COLUMN approved_by TEXT DEFAULT ''`,
		`ALTER TABLE audit_events ADD COLUMN explanation TEXT DEFAULT '{}'`,
		`ALTER TABLE audit_events ADD COLUMN model TEXT DEFAULT ''`,
		`ALTER TABLE audit_events ADD COLUMN controls TEXT DEFAULT '[]'`,
		`ALTER TABLE audit_events ADD COLUMN trace TEXT DEFAULT '[]'`,
	} {
		_, _ = db.Exec(migration)
	}
	_, _ = db.Exec(`INSERT OR IGNORE INTO demo_customers(id,name,email,status) VALUES('123','Anna Kowalska','anna@example.pl','active'),('456','Piotr Nowak','piotr@example.pl','active')`)
	// Approvals live in memory; after a restart old pending rows can never run.
	_, _ = db.Exec(`UPDATE approvals SET status='EXPIRED' WHERE status='PENDING'`)
	return s, nil
}
func (s *Store) Close() error { return s.db.Close() }

// Subscribe receives the id of every audit event that is written or updated.
// Slow subscribers miss notifications instead of blocking the gateway.
func (s *Store) Subscribe() (chan string, func()) {
	ch := make(chan string, 256)
	s.subsMu.Lock()
	s.subs[ch] = struct{}{}
	s.subsMu.Unlock()
	return ch, func() {
		s.subsMu.Lock()
		delete(s.subs, ch)
		s.subsMu.Unlock()
	}
}

func (s *Store) publish(id string) {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	for ch := range s.subs {
		select {
		case ch <- id:
		default:
		}
	}
}

// SetIncidentState records the analyst workflow state of an incident.
func (s *Store) SetIncidentState(id, status, note, by string) error {
	_, err := s.db.Exec(`INSERT INTO incident_state(id,status,note,updated_by,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,note=excluded.note,updated_by=excluded.updated_by,updated_at=excluded.updated_at`, id, status, note, by, time.Now().UTC().Format(time.RFC3339))
	return err
}

func (s *Store) IncidentStates() (map[string][3]string, error) {
	rows, err := s.db.Query(`SELECT id,status,note,updated_by FROM incident_state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][3]string{}
	for rows.Next() {
		var id, status, note, by string
		if err := rows.Scan(&id, &status, &note, &by); err != nil {
			return nil, err
		}
		out[id] = [3]string{status, note, by}
	}
	return out, rows.Err()
}

func durationOr(seconds int, fallback time.Duration) time.Duration {
	if seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return fallback
}

// AcquireSession returns a copy of the session and, when count is true,
// atomically increments its step counter so parallel calls cannot share a
// step. Unknown sessions are created unless registration is required or the
// user+agent is rotating sessions faster than sessions.max_new_per_minute.
func (s *Store) AcquireSession(key, principal, intent string, pol SessionPolicy, count bool) (SessionState, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	ttl := durationOr(pol.TTLSeconds, defaultSessionTTL)
	st := s.sessions[key]
	if st != nil && now.Sub(st.UpdatedAt) > ttl {
		delete(s.sessions, key)
		st = nil
	}
	transient := func(reason string) (SessionState, string) {
		out := SessionState{Key: key, OriginalIntent: intent}
		s.attachPrincipal(&out, principal, pol, now)
		return out, reason
	}
	if st == nil {
		if pol.RequireRegistered {
			return transient("session is not registered: open it with POST /v1/sessions")
		}
		if !count {
			return transient("")
		}
		if reason := s.allowNewSession(principal, pol, now); reason != "" {
			return transient(reason)
		}
		st = &SessionState{Key: key, OriginalIntent: intent, CreatedAt: now, UpdatedAt: now}
		s.sessions[key] = st
		s.evict(now, ttl)
	} else if st.OriginalIntent == "" && intent != "" && !st.Registered {
		// The first stated intent is locked; later requests cannot rewrite it.
		st.OriginalIntent = intent
	}
	if count {
		st.Steps++
		st.UpdatedAt = now
	}
	out := *st
	out.History = append([]string{}, st.History...)
	out.Sensitivity = append([]float64{}, st.Sensitivity...)
	s.attachPrincipal(&out, principal, pol, now)
	return out, ""
}

// RegisterSession lets the user-facing application fix the original intent
// before handing the session id to an agent.
func (s *Store) RegisterSession(key, principal, intent string, pol SessionPolicy) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if reason := s.allowNewSession(principal, pol, now); reason != "" {
		return reason
	}
	s.sessions[key] = &SessionState{Key: key, OriginalIntent: intent, Registered: true, CreatedAt: now, UpdatedAt: now}
	s.evict(now, durationOr(pol.TTLSeconds, defaultSessionTTL))
	return ""
}

func (s *Store) allowNewSession(principal string, pol SessionPolicy, now time.Time) string {
	if pol.MaxNewPerMinute <= 0 {
		return ""
	}
	recent := s.newSessions[principal][:0]
	for _, t := range s.newSessions[principal] {
		if now.Sub(t) < time.Minute {
			recent = append(recent, t)
		}
	}
	if len(recent) >= pol.MaxNewPerMinute {
		s.newSessions[principal] = recent
		return "new session rate exceeded: session rotation is limited per user and agent"
	}
	s.newSessions[principal] = append(recent, now)
	return ""
}

func (s *Store) attachPrincipal(st *SessionState, principal string, pol SessionPolicy, now time.Time) {
	window := durationOr(pol.DriftWindowSeconds, defaultDriftWindow)
	for _, r := range s.principals[principal] {
		if now.Sub(r.At) <= window {
			st.PrincipalHistory = append(st.PrincipalHistory, r.Entry)
			st.PrincipalSensitivity = append(st.PrincipalSensitivity, r.Sensitivity)
		}
	}
}

// RecordStep appends an evaluated action to the session and to the
// user+agent history used for cross-session Privilege Drift.
func (s *Store) RecordStep(key, principal, entry string, sensitivity float64, pol SessionPolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if st := s.sessions[key]; st != nil {
		st.History = appendTrim(st.History, entry, sessionHistoryCap)
		st.Sensitivity = appendSensitivity(st.Sensitivity, sensitivity, sessionHistoryCap)
		st.UpdatedAt = now
	}
	window := durationOr(pol.DriftWindowSeconds, defaultDriftWindow)
	kept := []stepRecord{}
	for _, r := range s.principals[principal] {
		if now.Sub(r.At) <= window {
			kept = append(kept, r)
		}
	}
	kept = append(kept, stepRecord{At: now, Entry: entry, Sensitivity: sensitivity})
	if len(kept) > sessionHistoryCap {
		kept = kept[len(kept)-sessionHistoryCap:]
	}
	s.principals[principal] = kept
	if len(s.principals) > maxSessions {
		for p, records := range s.principals {
			if len(records) == 0 || now.Sub(records[len(records)-1].At) > window {
				delete(s.principals, p)
			}
		}
	}
}

// evict bounds memory: expired sessions go first, then arbitrary old ones.
func (s *Store) evict(now time.Time, ttl time.Duration) {
	if len(s.sessions) <= maxSessions {
		return
	}
	for k, st := range s.sessions {
		if now.Sub(st.UpdatedAt) > ttl {
			delete(s.sessions, k)
		}
	}
	for k := range s.sessions {
		if len(s.sessions) <= maxSessions*9/10 {
			break
		}
		delete(s.sessions, k)
	}
}

func appendTrim(xs []string, v string, n int) []string {
	xs = append(xs, v)
	if len(xs) > n {
		xs = xs[len(xs)-n:]
	}
	return xs
}
func appendSensitivity(xs []float64, v float64, n int) []float64 {
	xs = append(xs, v)
	if len(xs) > n {
		xs = xs[len(xs)-n:]
	}
	return xs
}

// CheckAndReserve atomically checks every budget scope and, when all pass,
// reserves the usage. Above budget_alerts.warn_at it adds a warning; above
// throttle_at it lowers the allowed request rate; above 100% it blocks.
func (s *Store) CheckAndReserve(scopes []BudgetScope, u Usage, alerts BudgetAlerts) (BudgetResult, error) {
	if u.Tokens < 0 || u.CostUSD < 0 || u.ToolCalls < 0 || u.Steps < 0 || u.RuntimeMS < 0 {
		return BudgetResult{Reason: "invalid negative resource usage"}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return BudgetResult{}, err
	}
	defer tx.Rollback()
	day := time.Now().UTC().Format("2006-01-02")
	cutoff := time.Now().Add(-time.Minute).Unix()
	if _, err = tx.Exec(`DELETE FROM request_window WHERE timestamp < ?`, cutoff); err != nil {
		return BudgetResult{}, err
	}
	var result BudgetResult
	for _, scope := range scopes {
		var tokens, count int
		var cost float64
		err = tx.QueryRow(`SELECT tokens,cost_usd FROM usage_daily WHERE day=? AND subject=?`, day, scope.Subject).Scan(&tokens, &cost)
		if err != nil && err != sql.ErrNoRows {
			return BudgetResult{}, err
		}
		lim := scope.Limits
		if lim.DailyTokens > 0 && tokens+u.Tokens > lim.DailyTokens {
			return BudgetResult{Reason: scope.Subject + ": daily token budget exceeded"}, nil
		}
		if lim.DailyCostUSD > 0 && cost+u.CostUSD > lim.DailyCostUSD {
			return BudgetResult{Reason: scope.Subject + ": daily cost budget exceeded"}, nil
		}
		if lim.MaxToolCalls > 0 && u.ToolCalls > lim.MaxToolCalls {
			return BudgetResult{Reason: "maximum tool calls exceeded (runaway agent stopped)"}, nil
		}
		if lim.MaxSteps > 0 && u.Steps > lim.MaxSteps {
			return BudgetResult{Reason: "maximum execution steps exceeded (runaway agent stopped)"}, nil
		}
		if lim.MaxRuntimeMS > 0 && u.RuntimeMS > lim.MaxRuntimeMS {
			return BudgetResult{Reason: "maximum runtime exceeded"}, nil
		}
		if err = tx.QueryRow(`SELECT COUNT(*) FROM request_window WHERE subject=?`, scope.Subject).Scan(&count); err != nil {
			return BudgetResult{}, err
		}
		if lim.RequestsPerMinute > 0 && count >= lim.RequestsPerMinute {
			return BudgetResult{Reason: scope.Subject + ": request rate exceeded", Throttle: true}, nil
		}
		ratio := 0.0
		if lim.DailyTokens > 0 {
			ratio = float64(tokens+u.Tokens) / float64(lim.DailyTokens)
		}
		if lim.DailyCostUSD > 0 {
			ratio = maxFloatMS(ratio, (cost+u.CostUSD)/lim.DailyCostUSD)
		}
		if alerts.ThrottleAt > 0 && ratio >= alerts.ThrottleAt {
			base := lim.RequestsPerMinute
			if base <= 0 {
				base = 60
			}
			factor := alerts.ThrottleRPMFactor
			if factor <= 0 {
				factor = 0.25
			}
			allowed := maxInt(1, int(float64(base)*factor))
			if count >= allowed {
				return BudgetResult{Reason: fmt.Sprintf("%s: %.0f%% of daily budget used, throttled to %d requests/min", scope.Subject, ratio*100, allowed), Throttle: true}, nil
			}
			result.Warnings = append(result.Warnings, fmt.Sprintf("%s: %.0f%% of daily budget used (throttling active)", scope.Subject, ratio*100))
		} else if alerts.WarnAt > 0 && ratio >= alerts.WarnAt {
			result.Warnings = append(result.Warnings, fmt.Sprintf("%s: %.0f%% of daily budget used", scope.Subject, ratio*100))
		}
	}
	for _, scope := range scopes {
		if _, err = tx.Exec(`INSERT INTO usage_daily(day,subject,tokens,cost_usd) VALUES(?,?,?,?) ON CONFLICT(day,subject) DO UPDATE SET tokens=tokens+excluded.tokens,cost_usd=cost_usd+excluded.cost_usd`, day, scope.Subject, u.Tokens, u.CostUSD); err != nil {
			return BudgetResult{}, err
		}
		if _, err = tx.Exec(`INSERT INTO request_window(subject,timestamp) VALUES(?,?)`, scope.Subject, time.Now().Unix()); err != nil {
			return BudgetResult{}, err
		}
	}
	return result, tx.Commit()
}

// Adjust refunds (negative delta) or reconciles (positive delta) reserved usage.
func (s *Store) Adjust(scopes []BudgetScope, tokens int, cost float64) error {
	if tokens == 0 && cost == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	day := time.Now().UTC().Format("2006-01-02")
	for _, scope := range scopes {
		if _, err := s.db.Exec(`INSERT INTO usage_daily(day,subject,tokens,cost_usd) VALUES(?,?,MAX(0,?),MAX(0,?)) ON CONFLICT(day,subject) DO UPDATE SET tokens=MAX(0,tokens+?),cost_usd=MAX(0,cost_usd+?)`, day, scope.Subject, tokens, cost, tokens, cost); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) AddAudit(e AuditEvent) error {
	r, _ := json.Marshal(e.Reasons)
	sem, _ := json.Marshal(e.Semantic)
	xai, _ := json.Marshal(e.Explanation)
	if e.Controls == nil {
		e.Controls = []string{}
	}
	ctl, _ := json.Marshal(e.Controls)
	trace, _ := json.Marshal(e.Trace)
	if e.ExecutionStatus == "" {
		e.ExecutionStatus = "VERDICT_ONLY"
	}
	_, err := s.db.Exec(`INSERT INTO audit_events(id,timestamp,user_id,role,agent,action,resource,decision,reasons,policy_version,risk,semantic,tokens,cost_usd,latency_ms,session_id,gateway_ms,deterministic_ms,semantic_ms,semantic_escalated,explanation,execution_status,model,controls,trace) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, e.ID, e.Timestamp, e.User, e.Role, e.Agent, e.Action, e.Resource, string(e.Decision), string(r), e.PolicyVersion, e.Risk, string(sem), e.Tokens, e.CostUSD, e.LatencyMS, e.SessionID, e.GatewayMS, e.DeterministicMS, e.SemanticMS, e.SemanticEscalated, string(xai), e.ExecutionStatus, e.Model, string(ctl), string(trace))
	if err == nil {
		s.publish(e.ID)
	}
	return err
}
func (s *Store) UpdateExecution(id, status string, actualTokens int, approver string) error {
	_, err := s.db.Exec(`UPDATE audit_events SET execution_status=?,actual_tokens=?,approved_by=? WHERE id=?`, status, actualTokens, approver, id)
	if err == nil {
		s.publish(id)
	}
	return err
}

// AnnotateAudit adds reasons and controls found after the verdict and can
// re-label the stored decision (e.g. an attack captured inside Ghost Shell).
func (s *Store) AnnotateAudit(id, decision string, reasons, controls []string) error {
	var rawReasons, rawControls string
	if err := s.db.QueryRow(`SELECT reasons,controls FROM audit_events WHERE id=?`, id).Scan(&rawReasons, &rawControls); err != nil {
		return err
	}
	var rs, cs []string
	_ = json.Unmarshal([]byte(rawReasons), &rs)
	_ = json.Unmarshal([]byte(rawControls), &cs)
	if len(reasons) > 0 {
		kept := []string{}
		for _, r := range rs {
			if r != "policy checks passed" {
				kept = append(kept, r)
			}
		}
		rs = uniqueSorted(append(kept, reasons...))
	}
	rb, _ := json.Marshal(rs)
	cb, _ := json.Marshal(uniqueSorted(append(cs, controls...)))
	var err error
	if decision != "" {
		_, err = s.db.Exec(`UPDATE audit_events SET reasons=?,controls=?,decision=? WHERE id=?`, string(rb), string(cb), decision, id)
	} else {
		_, err = s.db.Exec(`UPDATE audit_events SET reasons=?,controls=? WHERE id=?`, string(rb), string(cb), id)
	}
	if err == nil {
		s.publish(id)
	}
	return err
}

// AddControls records controls that acted after the verdict (output guard).
func (s *Store) AddControls(id string, extra []string) error {
	if len(extra) == 0 {
		return nil
	}
	var raw string
	if err := s.db.QueryRow(`SELECT controls FROM audit_events WHERE id=?`, id).Scan(&raw); err != nil {
		return err
	}
	var list []string
	_ = json.Unmarshal([]byte(raw), &list)
	b, _ := json.Marshal(uniqueSorted(append(list, extra...)))
	_, err := s.db.Exec(`UPDATE audit_events SET controls=? WHERE id=?`, string(b), id)
	return err
}

func (s *Store) UpdateExplanation(id string, ex Explanation) error {
	b, _ := json.Marshal(ex)
	_, err := s.db.Exec(`UPDATE audit_events SET explanation=? WHERE id=?`, string(b), id)
	if err == nil {
		s.publish(id)
	}
	return err
}

type AuditFilter struct {
	Limit    int
	User     string
	Decision string
	Since    string
}

const auditColumns = `id,timestamp,user_id,role,agent,action,resource,decision,reasons,policy_version,risk,semantic,tokens,cost_usd,latency_ms,session_id,gateway_ms,deterministic_ms,semantic_ms,semantic_escalated,execution_status,actual_tokens,approved_by,explanation,model,controls,trace`

func (s *Store) Audits(f AuditFilter) ([]AuditEvent, error) {
	if f.Limit <= 0 || f.Limit > 5000 {
		f.Limit = 100
	}
	where, args := []string{"1=1"}, []any{}
	if f.User != "" {
		where, args = append(where, "user_id=?"), append(args, f.User)
	}
	if f.Decision != "" {
		where, args = append(where, "decision=?"), append(args, strings.ToUpper(f.Decision))
	}
	if f.Since != "" {
		where, args = append(where, "timestamp>=?"), append(args, f.Since)
	}
	args = append(args, f.Limit)
	rows, err := s.db.Query(`SELECT `+auditColumns+` FROM audit_events WHERE `+strings.Join(where, " AND ")+` ORDER BY timestamp DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEvent{}
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) AuditByID(id string) (AuditEvent, error) {
	return scanAudit(s.db.QueryRow(`SELECT `+auditColumns+` FROM audit_events WHERE id=?`, id))
}

type scanner interface{ Scan(...any) error }

func scanAudit(row scanner) (AuditEvent, error) {
	var e AuditEvent
	var d, rs, sem, xai, ctl, trace string
	if err := row.Scan(&e.ID, &e.Timestamp, &e.User, &e.Role, &e.Agent, &e.Action, &e.Resource, &d, &rs, &e.PolicyVersion, &e.Risk, &sem, &e.Tokens, &e.CostUSD, &e.LatencyMS, &e.SessionID, &e.GatewayMS, &e.DeterministicMS, &e.SemanticMS, &e.SemanticEscalated, &e.ExecutionStatus, &e.ActualTokens, &e.ApprovedBy, &xai, &e.Model, &ctl, &trace); err != nil {
		return e, err
	}
	e.Decision = Decision(d)
	_ = json.Unmarshal([]byte(rs), &e.Reasons)
	_ = json.Unmarshal([]byte(sem), &e.Semantic)
	_ = json.Unmarshal([]byte(xai), &e.Explanation)
	_ = json.Unmarshal([]byte(ctl), &e.Controls)
	_ = json.Unmarshal([]byte(trace), &e.Trace)
	if e.Controls == nil {
		e.Controls = []string{}
	}
	return e, nil
}

func (s *Store) CreateApproval(id, requestID string, ctx any) error {
	b, _ := json.Marshal(ctx)
	_, err := s.db.Exec(`INSERT INTO approvals VALUES(?,?,?,?,?)`, id, requestID, "PENDING", time.Now().UTC().Format(time.RFC3339Nano), string(b))
	return err
}
func (s *Store) SetApprovalStatus(id, from, to string) (bool, error) {
	res, err := s.db.Exec(`UPDATE approvals SET status=? WHERE id=? AND status=?`, to, id, from)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (s *Store) DB() *sql.DB { return s.db }
func dbErr(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("storage: %w", err)
}
