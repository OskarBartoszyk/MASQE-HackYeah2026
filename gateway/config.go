package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type Control struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Action  string `yaml:"action" json:"action"`
	// Threshold is an optional explicit override. When it is 0 the value from
	// the active strictness profile is used, so changing `mode` still matters.
	Threshold float64 `yaml:"threshold" json:"threshold"`
}

type SecurityPolicy struct {
	PII              Control `yaml:"pii" json:"pii"`
	Secrets          Control `yaml:"secrets" json:"secrets"`
	PromptInjection  Control `yaml:"prompt_injection" json:"prompt_injection"`
	DataExfiltration Control `yaml:"data_exfiltration" json:"data_exfiltration"`
	IntentLock       Control `yaml:"intent_lock" json:"intent_lock"`
	PrivilegeDrift   Control `yaml:"privilege_drift" json:"privilege_drift"`
	MemoryPoisoning  Control `yaml:"memory_poisoning" json:"memory_poisoning"`
	OutputInjection  Control `yaml:"output_injection" json:"output_injection"`
}

type Limits struct {
	DailyTokens       int     `yaml:"daily_tokens" json:"daily_tokens"`
	DailyCostUSD      float64 `yaml:"daily_cost_usd" json:"daily_cost_usd"`
	RequestsPerMinute int     `yaml:"requests_per_minute" json:"requests_per_minute"`
	MaxToolCalls      int     `yaml:"max_tool_calls" json:"max_tool_calls"`
	MaxSteps          int     `yaml:"max_steps" json:"max_steps"`
	MaxRuntimeMS      int     `yaml:"max_runtime_ms" json:"max_runtime_ms"`
}

type RolePolicy struct {
	Permissions []string `yaml:"permissions" json:"permissions"`
	// Console controls access to the reporting API, separately from the
	// permissions an agent may inherit.
	Console []string `yaml:"console" json:"console"`
}
type AgentPolicy struct {
	Permissions  []string `yaml:"permissions" json:"permissions"`
	AllowedTools []string `yaml:"allowed_tools" json:"allowed_tools"`
	Limits       Limits   `yaml:"limits" json:"limits"`
}
type ActionPolicy struct {
	Permission      string  `yaml:"permission" json:"permission"`
	Risk            float64 `yaml:"risk" json:"risk"`
	Sensitivity     float64 `yaml:"sensitivity" json:"sensitivity"`
	RequireApproval bool    `yaml:"require_approval" json:"require_approval"`
}
type RiskPolicy struct {
	Medium   float64 `yaml:"medium" json:"medium"`
	High     float64 `yaml:"high" json:"high"`
	Critical float64 `yaml:"critical" json:"critical"`
}
type StrictnessProfile struct {
	PromptInjectionThreshold  float64    `yaml:"prompt_injection_threshold" json:"prompt_injection_threshold"`
	DataExfiltrationThreshold float64    `yaml:"data_exfiltration_threshold" json:"data_exfiltration_threshold"`
	IntentMinAlignment        float64    `yaml:"intent_min_alignment" json:"intent_min_alignment"`
	PrivilegeDriftThreshold   float64    `yaml:"privilege_drift_threshold" json:"privilege_drift_threshold"`
	MemoryPoisoningThreshold  float64    `yaml:"memory_poisoning_threshold" json:"memory_poisoning_threshold"`
	OutputInjectionThreshold  float64    `yaml:"output_injection_threshold" json:"output_injection_threshold"`
	Risk                      RiskPolicy `yaml:"risk" json:"risk"`
}
type GhostPolicy struct {
	Enabled        bool     `yaml:"enabled" json:"enabled"`
	TTLSeconds     int      `yaml:"ttl_seconds" json:"ttl_seconds"`
	AllowedTools   []string `yaml:"allowed_tools" json:"allowed_tools"`
	AllowedActions []string `yaml:"allowed_actions" json:"allowed_actions"`
}
type RedactionPolicy struct {
	Language  string `yaml:"language" json:"language"`
	ModelPath string `yaml:"model_path" json:"model_path"`
	UseModel  bool   `yaml:"use_model" json:"use_model"`
}
type ClientPolicy struct {
	UserID     string   `yaml:"user_id" json:"user_id"`
	Role       string   `yaml:"role" json:"role"`
	Agents     []string `yaml:"agents" json:"agents"`
	CanApprove bool     `yaml:"can_approve" json:"can_approve"`
}

// ResourceRule is the RESOURCE POLICY part of the permission intersection.
// Pattern is a case-insensitive glob where `*` matches any characters.
type ResourceRule struct {
	ID          string   `yaml:"id" json:"id"`
	Pattern     string   `yaml:"pattern" json:"pattern"`
	Actions     []string `yaml:"actions" json:"actions,omitempty"`
	Decision    string   `yaml:"decision" json:"decision,omitempty"`
	Permission  string   `yaml:"permission" json:"permission,omitempty"`
	Sensitivity float64  `yaml:"sensitivity" json:"sensitivity,omitempty"`
	Reason      string   `yaml:"reason" json:"reason,omitempty"`
	compiled    *regexp.Regexp
}

type SessionPolicy struct {
	// RequireRegistered forces callers to open a session via POST /v1/sessions
	// so the user-facing application, not the agent, fixes the original intent.
	RequireRegistered bool `yaml:"require_registered" json:"require_registered"`
	TTLSeconds        int  `yaml:"ttl_seconds" json:"ttl_seconds"`
	// MaxNewPerMinute limits session rotation per user+agent, so a runaway
	// agent cannot reset its step counter by inventing new session ids.
	MaxNewPerMinute int `yaml:"max_new_per_minute" json:"max_new_per_minute"`
	// DriftWindowSeconds keeps Privilege Drift history per user+agent across
	// sessions for this long.
	DriftWindowSeconds int `yaml:"drift_window_seconds" json:"drift_window_seconds"`
}

type BudgetAlerts struct {
	WarnAt            float64 `yaml:"warn_at" json:"warn_at"`
	ThrottleAt        float64 `yaml:"throttle_at" json:"throttle_at"`
	ThrottleRPMFactor float64 `yaml:"throttle_rpm_factor" json:"throttle_rpm_factor"`
}

type RemoteFeedPolicy struct {
	URL            string `yaml:"url" json:"url"`
	RefreshSeconds int    `yaml:"refresh_seconds" json:"refresh_seconds"`
}

type Policy struct {
	Version           string                       `yaml:"version" json:"version"`
	Mode              string                       `yaml:"mode" json:"mode"`
	Clients           map[string]ClientPolicy      `yaml:"clients" json:"-"`
	AllowedModels     []string                     `yaml:"allowed_models" json:"allowed_models"`
	Security          SecurityPolicy               `yaml:"security" json:"security"`
	Budgets           Limits                       `yaml:"budgets" json:"budgets"`
	BudgetAlerts      BudgetAlerts                 `yaml:"budget_alerts" json:"budget_alerts"`
	UserDefaultBudget Limits                       `yaml:"user_default_budget" json:"user_default_budget"`
	Roles             map[string]RolePolicy        `yaml:"roles" json:"roles"`
	Agents            map[string]AgentPolicy       `yaml:"agents" json:"agents"`
	ModelBudgets      map[string]Limits            `yaml:"model_budgets" json:"model_budgets"`
	UserBudgets       map[string]Limits            `yaml:"user_budgets" json:"user_budgets"`
	ModelProviders    map[string]ModelProvider     `yaml:"model_providers" json:"model_providers"`
	Actions           map[string]ActionPolicy      `yaml:"actions" json:"actions"`
	Resources         []ResourceRule               `yaml:"resources" json:"resources"`
	Risk              RiskPolicy                   `yaml:"risk" json:"risk"`
	Strictness        map[string]StrictnessProfile `yaml:"strictness_modes" json:"strictness_modes"`
	Sessions          SessionPolicy                `yaml:"sessions" json:"sessions"`
	Ghost             GhostPolicy                  `yaml:"ghost" json:"ghost"`
	Redaction         RedactionPolicy              `yaml:"redaction" json:"redaction"`
	ThreatFeedRemote  RemoteFeedPolicy             `yaml:"threat_feed_remote" json:"threat_feed_remote"`
}
type ModelProvider struct {
	Kind            string  `yaml:"kind" json:"kind"`
	URL             string  `yaml:"url" json:"url"`
	CostPer1KTokens float64 `yaml:"cost_per_1k_tokens" json:"cost_per_1k_tokens"`
	MaxOutputTokens int     `yaml:"max_output_tokens" json:"max_output_tokens"`
}

type ThreatSignature struct {
	ID          string `yaml:"id" json:"id"`
	Pattern     string `yaml:"pattern" json:"pattern"`
	Action      string `yaml:"action" json:"action"`
	Severity    string `yaml:"severity" json:"severity,omitempty"`
	Description string `yaml:"description" json:"description,omitempty"`
	Reference   string `yaml:"reference" json:"reference,omitempty"`
	Source      string `yaml:"-" json:"source,omitempty"`
}
type ThreatFeed struct {
	Version    string            `yaml:"version" json:"version"`
	Signatures []ThreatSignature `yaml:"signatures" json:"signatures"`
}

type compiledSignature struct {
	ThreatSignature
	re *regexp.Regexp
}

type ConfigSnapshot struct {
	Policy     Policy
	Threats    ThreatFeed
	Hash       string
	ReloadedAt time.Time
	// Error is set when the latest edit was rejected. The previous valid
	// snapshot keeps serving traffic instead of taking the gateway offline.
	Error      string
	ErrorAt    time.Time
	RemoteFeed string
	compiled   []compiledSignature
	raw        rawConfig
}

type ConfigManager struct {
	policyPath, threatPath string
	mu                     sync.RWMutex
	snapshot               ConfigSnapshot
	policyMod, threatMod   time.Time
	triedPolicy, triedFeed time.Time
	remote                 []ThreatSignature
	remoteHash             string
	remoteStatus           string
	logger                 *slog.Logger
}

func NewConfigManager(policyPath, threatPath string) (*ConfigManager, error) {
	m := &ConfigManager{policyPath: policyPath, threatPath: threatPath, logger: slog.Default()}
	if err := m.reload(true); err != nil {
		return nil, err
	}
	return m, nil
}

// Snapshot returns the active configuration. A rejected edit never replaces
// the last valid snapshot; it is reported through snapshot.Error.
func (m *ConfigManager) Snapshot() (ConfigSnapshot, error) {
	_ = m.reload(false)
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.snapshot, nil
}

func (m *ConfigManager) reload(force bool) error {
	ps, perr := os.Stat(m.policyPath)
	ts, terr := os.Stat(m.threatPath)
	if perr != nil || terr != nil {
		err := perr
		if err == nil {
			err = terr
		}
		if force {
			return fmt.Errorf("config: %w", err)
		}
		m.fail(fmt.Errorf("config file unavailable: %w", err), time.Time{}, time.Time{})
		return err
	}
	m.mu.RLock()
	loaded := ps.ModTime().Equal(m.policyMod) && ts.ModTime().Equal(m.threatMod)
	alreadyRejected := ps.ModTime().Equal(m.triedPolicy) && ts.ModTime().Equal(m.triedFeed)
	m.mu.RUnlock()
	if !force && (loaded || alreadyRejected) {
		return nil
	}
	pb, err := os.ReadFile(m.policyPath)
	if err != nil {
		return m.failOrReturn(force, err, ps.ModTime(), ts.ModTime())
	}
	tb, err := os.ReadFile(m.threatPath)
	if err != nil {
		return m.failOrReturn(force, err, ps.ModTime(), ts.ModTime())
	}
	var p Policy
	if err := yaml.Unmarshal(pb, &p); err != nil {
		return m.failOrReturn(force, fmt.Errorf("invalid policy.yaml: %w", err), ps.ModTime(), ts.ModTime())
	}
	var t ThreatFeed
	if err := yaml.Unmarshal(tb, &t); err != nil {
		return m.failOrReturn(force, fmt.Errorf("invalid threat-feed.yaml: %w", err), ps.ModTime(), ts.ModTime())
	}
	if err := validatePolicy(p); err != nil {
		return m.failOrReturn(force, err, ps.ModTime(), ts.ModTime())
	}
	if err := compileResources(p.Resources); err != nil {
		return m.failOrReturn(force, err, ps.ModTime(), ts.ModTime())
	}
	if err := validateFeed(t.Signatures); err != nil {
		return m.failOrReturn(force, fmt.Errorf("threat-feed.yaml: %w", err), ps.ModTime(), ts.ModTime())
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.install(p, t, pb, tb)
	m.policyMod, m.threatMod = ps.ModTime(), ts.ModTime()
	m.triedPolicy, m.triedFeed = time.Time{}, time.Time{}
	return nil
}

// install must be called with m.mu held.
func (m *ConfigManager) install(p Policy, t ThreatFeed, pb, tb []byte) {
	for i := range t.Signatures {
		t.Signatures[i].Source = "local"
	}
	merged := ThreatFeed{Version: t.Version, Signatures: append(append([]ThreatSignature{}, t.Signatures...), m.remote...)}
	compiled := make([]compiledSignature, 0, len(merged.Signatures))
	for _, sig := range merged.Signatures {
		compiled = append(compiled, compiledSignature{ThreatSignature: sig, re: regexp.MustCompile("(?i)" + sig.Pattern)})
	}
	h := sha256.New()
	h.Write(pb)
	h.Write(tb)
	h.Write([]byte(m.remoteHash))
	m.snapshot = ConfigSnapshot{Policy: p, Threats: merged, Hash: hex.EncodeToString(h.Sum(nil)[:8]), ReloadedAt: time.Now().UTC(), RemoteFeed: m.remoteStatus, compiled: compiled}
	m.snapshot.raw = rawConfig{policy: pb, feed: tb, policyObj: p, feedObj: t}
}

type rawConfig struct {
	policy, feed []byte
	policyObj    Policy
	feedObj      ThreatFeed
}

func (m *ConfigManager) failOrReturn(force bool, err error, pm, tm time.Time) error {
	if force {
		return err
	}
	m.fail(err, pm, tm)
	return err
}

func (m *ConfigManager) fail(err error, pm, tm time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.triedPolicy, m.triedFeed = pm, tm
	if m.snapshot.Error != err.Error() {
		m.logger.Error("configuration rejected; keeping last valid snapshot", "error", err)
	}
	m.snapshot.Error = err.Error()
	m.snapshot.ErrorAt = time.Now().UTC()
}

var validControlActions = map[string]bool{"block": true, "redact": true, "require_approval": true, "ghost": true, "throttle": true, "log": true}
var validThreatActions = map[string]bool{"block": true, "require_approval": true, "ghost": true, "throttle": true, "log": true}
var validResourceDecisions = map[string]bool{"": true, "block": true, "require_approval": true, "ghost": true}
var validConsole = map[string]bool{"telemetry.read": true, "policy.read": true, "audit.read_own": true, "audit.read_all": true, "audit.export": true}

func inUnit(v float64) bool { return v >= 0 && v <= 1 }

func validatePolicy(p Policy) error {
	if p.Version == "" {
		return fmt.Errorf("policy version is required")
	}
	if p.Redaction.UseModel {
		return fmt.Errorf("redaction.use_model cannot be enabled: the supplied Polish NER checkpoint has no model weights")
	}
	if len(p.Strictness) > 0 {
		if _, ok := p.Strictness[p.Mode]; !ok {
			return fmt.Errorf("mode %q is not defined under strictness_modes", p.Mode)
		}
	}
	for name, prof := range p.Strictness {
		for field, v := range map[string]float64{"prompt_injection_threshold": prof.PromptInjectionThreshold, "data_exfiltration_threshold": prof.DataExfiltrationThreshold, "intent_min_alignment": prof.IntentMinAlignment, "privilege_drift_threshold": prof.PrivilegeDriftThreshold, "memory_poisoning_threshold": prof.MemoryPoisoningThreshold, "output_injection_threshold": prof.OutputInjectionThreshold} {
			if !inUnit(v) {
				return fmt.Errorf("strictness_modes.%s.%s must be between 0 and 1", name, field)
			}
		}
		if prof.Risk != (RiskPolicy{}) && !validRisk(prof.Risk) {
			return fmt.Errorf("strictness_modes.%s.risk must satisfy 0 < medium < high < critical <= 1", name)
		}
	}
	if p.Risk != (RiskPolicy{}) && !validRisk(p.Risk) {
		return fmt.Errorf("risk thresholds must satisfy 0 < medium < high < critical <= 1")
	}
	if eff := applyStrictness(p); !validRisk(eff.Risk) {
		return fmt.Errorf("no valid risk thresholds: define risk or strictness_modes.%s.risk", p.Mode)
	}
	controls := map[string]Control{"pii": p.Security.PII, "secrets": p.Security.Secrets, "prompt_injection": p.Security.PromptInjection, "data_exfiltration": p.Security.DataExfiltration, "intent_lock": p.Security.IntentLock, "privilege_drift": p.Security.PrivilegeDrift, "memory_poisoning": p.Security.MemoryPoisoning, "output_injection": p.Security.OutputInjection}
	for name, c := range controls {
		action := strings.ToLower(c.Action)
		if c.Enabled && action == "" {
			return fmt.Errorf("security.%s.action is required when the control is enabled", name)
		}
		if action != "" && !validControlActions[action] {
			return fmt.Errorf("security.%s.action %q is invalid (use block, redact, require_approval, ghost, throttle or log)", name, c.Action)
		}
		if action == "redact" && name != "pii" && name != "secrets" {
			return fmt.Errorf("security.%s.action redact is only supported for pii and secrets", name)
		}
		if !inUnit(c.Threshold) {
			return fmt.Errorf("security.%s.threshold must be between 0 and 1", name)
		}
	}
	if len(p.Clients) == 0 {
		return fmt.Errorf("at least one authenticated client is required")
	}
	for key, client := range p.Clients {
		if len(key) < 8 || client.UserID == "" || client.Role == "" || len(client.Agents) == 0 {
			return fmt.Errorf("client credentials must define a key of at least 8 characters, user_id, role, and agents")
		}
		if _, ok := p.Roles[client.Role]; !ok {
			return fmt.Errorf("client %s has unknown role %s", client.UserID, client.Role)
		}
		for _, a := range client.Agents {
			if _, ok := p.Agents[a]; !ok {
				return fmt.Errorf("client %s references unknown agent %s", client.UserID, a)
			}
		}
	}
	for name, role := range p.Roles {
		for _, c := range role.Console {
			if !validConsole[c] {
				return fmt.Errorf("roles.%s.console has unknown entry %q", name, c)
			}
		}
	}
	for name, a := range p.Actions {
		if a.Permission == "" {
			return fmt.Errorf("actions.%s.permission is required", name)
		}
		if !inUnit(a.Risk) || !inUnit(a.Sensitivity) {
			return fmt.Errorf("actions.%s risk and sensitivity must be between 0 and 1", name)
		}
	}
	limits := map[string]Limits{"budgets": p.Budgets, "user_default_budget": p.UserDefaultBudget}
	for n, l := range p.Agents {
		limits["agents."+n+".limits"] = l.Limits
	}
	for n, l := range p.UserBudgets {
		limits["user_budgets."+n] = l
	}
	for n, l := range p.ModelBudgets {
		limits["model_budgets."+n] = l
	}
	for n, l := range limits {
		if l.DailyTokens < 0 || l.DailyCostUSD < 0 || l.RequestsPerMinute < 0 || l.MaxToolCalls < 0 || l.MaxSteps < 0 || l.MaxRuntimeMS < 0 {
			return fmt.Errorf("%s must not contain negative limits", n)
		}
	}
	a := p.BudgetAlerts
	if !inUnit(a.WarnAt) || !inUnit(a.ThrottleAt) || a.ThrottleRPMFactor < 0 || a.ThrottleRPMFactor > 1 {
		return fmt.Errorf("budget_alerts values must be between 0 and 1")
	}
	if a.WarnAt > 0 && a.ThrottleAt > 0 && a.WarnAt >= a.ThrottleAt {
		return fmt.Errorf("budget_alerts.warn_at must be lower than throttle_at")
	}
	for name, mp := range p.ModelProviders {
		if mp.Kind == "ollama" {
			if err := localModelURL(mp.URL); err != nil {
				return fmt.Errorf("model_providers.%s: %w", name, err)
			}
		}
	}
	if p.Ghost.TTLSeconds < 0 || p.Sessions.TTLSeconds < 0 || p.Sessions.MaxNewPerMinute < 0 || p.Sessions.DriftWindowSeconds < 0 {
		return fmt.Errorf("ghost and sessions values must not be negative")
	}
	for i, r := range p.Resources {
		if r.Pattern == "" {
			return fmt.Errorf("resources[%d].pattern is required", i)
		}
		if !validResourceDecisions[strings.ToLower(r.Decision)] {
			return fmt.Errorf("resources[%d].decision %q is invalid (use block, require_approval or ghost)", i, r.Decision)
		}
		if !inUnit(r.Sensitivity) {
			return fmt.Errorf("resources[%d].sensitivity must be between 0 and 1", i)
		}
	}
	return nil
}

func validRisk(r RiskPolicy) bool {
	return r.Medium > 0 && r.Medium < r.High && r.High < r.Critical && r.Critical <= 1
}

func validateFeed(sigs []ThreatSignature) error {
	seen := map[string]bool{}
	for _, sig := range sigs {
		if sig.ID == "" || sig.Pattern == "" {
			return fmt.Errorf("threat signature requires id and pattern")
		}
		if seen[sig.ID] {
			return fmt.Errorf("duplicate threat signature id %s", sig.ID)
		}
		seen[sig.ID] = true
		if !validThreatActions[strings.ToLower(sig.Action)] {
			return fmt.Errorf("threat signature %s has invalid action %q (use block, require_approval, ghost, throttle or log)", sig.ID, sig.Action)
		}
		if _, err := regexp.Compile("(?i)" + sig.Pattern); err != nil {
			return fmt.Errorf("invalid threat signature %s: %w", sig.ID, err)
		}
	}
	return nil
}

func compileResources(rules []ResourceRule) error {
	for i := range rules {
		quoted := regexp.QuoteMeta(strings.ToLower(rules[i].Pattern))
		re, err := regexp.Compile("^" + strings.ReplaceAll(quoted, `\*`, ".*") + "$")
		if err != nil {
			return fmt.Errorf("resources[%d]: %w", i, err)
		}
		rules[i].compiled = re
	}
	return nil
}

// applyStrictness resolves effective thresholds: an explicit value in the
// security section wins; otherwise the active strictness profile supplies it.
func applyStrictness(p Policy) Policy {
	profile, ok := p.Strictness[p.Mode]
	if !ok {
		return p
	}
	fill := func(c *Control, v float64) {
		if c.Threshold == 0 && v > 0 {
			c.Threshold = v
		}
	}
	fill(&p.Security.PromptInjection, profile.PromptInjectionThreshold)
	fill(&p.Security.DataExfiltration, profile.DataExfiltrationThreshold)
	fill(&p.Security.IntentLock, profile.IntentMinAlignment)
	fill(&p.Security.PrivilegeDrift, profile.PrivilegeDriftThreshold)
	fill(&p.Security.MemoryPoisoning, profile.MemoryPoisoningThreshold)
	fill(&p.Security.OutputInjection, profile.OutputInjectionThreshold)
	if p.Risk == (RiskPolicy{}) {
		p.Risk = profile.Risk
	}
	return p
}

func localModelURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Port() == "" {
		return fmt.Errorf("model endpoint must be http://<local-host>:<port>")
	}
	switch u.Hostname() {
	case "127.0.0.1", "localhost", "host.docker.internal", "::1":
		return nil
	}
	return fmt.Errorf("model endpoint host %q is not local", u.Hostname())
}

// StartRemoteFeed periodically pulls an externally managed signature feed
// configured in policy.threat_feed_remote. Invalid downloads are rejected and
// the last good remote feed stays active.
func (m *ConfigManager) StartRemoteFeed(ctx context.Context, client *http.Client) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	go func() {
		for {
			snap, _ := m.Snapshot()
			cfg := snap.Policy.ThreatFeedRemote
			wait := time.Duration(maxInt(10, cfg.RefreshSeconds)) * time.Second
			if cfg.URL != "" {
				if err := m.RefreshRemoteFeed(ctx, client, cfg.URL); err != nil {
					m.logger.Warn("remote threat feed rejected", "error", err)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
		}
	}()
}

func (m *ConfigManager) RefreshRemoteFeed(ctx context.Context, client *http.Client, feedURL string) error {
	u, err := url.Parse(feedURL)
	if err != nil || (u.Scheme != "https" && !(u.Scheme == "http" && localModelURL(feedURL) == nil)) {
		m.setRemoteStatus("rejected: remote feed must use https")
		return fmt.Errorf("remote feed must use https")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		m.setRemoteStatus("unreachable; last good feed kept")
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		m.setRemoteStatus(fmt.Sprintf("HTTP %d; last good feed kept", resp.StatusCode))
		return fmt.Errorf("remote feed returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var feed ThreatFeed
	if err := yaml.Unmarshal(body, &feed); err != nil {
		m.setRemoteStatus("invalid YAML; last good feed kept")
		return err
	}
	for i := range feed.Signatures {
		feed.Signatures[i].ID = "REMOTE:" + feed.Signatures[i].ID
		feed.Signatures[i].Source = "remote"
	}
	if err := validateFeed(feed.Signatures); err != nil {
		m.setRemoteStatus("invalid signature; last good feed kept")
		return err
	}
	h := sha256.Sum256(body)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.remote = feed.Signatures
	m.remoteHash = hex.EncodeToString(h[:8])
	m.remoteStatus = fmt.Sprintf("ok: %d signatures from %s at %s", len(feed.Signatures), u.Host, time.Now().UTC().Format(time.RFC3339))
	raw := m.snapshot.raw
	keepErr, keepErrAt := m.snapshot.Error, m.snapshot.ErrorAt
	m.install(raw.policyObj, raw.feedObj, raw.policy, raw.feed)
	m.snapshot.Error, m.snapshot.ErrorAt = keepErr, keepErrAt
	return nil
}

func (m *ConfigManager) setRemoteStatus(s string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.remoteStatus = s
	m.snapshot.RemoteFeed = s
}

func uniqueSorted(values []string) []string {
	m := map[string]bool{}
	for _, v := range values {
		if v != "" {
			m[v] = true
		}
	}
	out := make([]string, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
