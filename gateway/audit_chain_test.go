package gateway

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func chainStore(t *testing.T, path string) *Store {
	t.Helper()
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// seedAudit writes events through every sealed write path.
func seedAudit(t *testing.T, s *Store) {
	t.Helper()
	for i, d := range []Decision{Allow, Block, Redact, Ghost} {
		id := "req-" + string(rune('a'+i))
		ts := time.Now().UTC().Add(time.Duration(i) * time.Millisecond).Format(time.RFC3339Nano)
		if err := s.AddAudit(AuditEvent{ID: id, Timestamp: ts, User: "alice", Role: "analyst", Agent: "corporate-agent", Action: "reports.read", Resource: "reports/Q4.pdf", Decision: d, Reasons: []string{"policy checks passed"}, Risk: .1 * float64(i)}); err != nil {
			t.Fatal(err)
		}
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.UpdateExecution("req-a", "EXECUTED", 120, ""))
	must(s.AnnotateAudit("req-d", string(Block), []string{"honeytoken exfiltration"}, []string{"ghost_shell"}))
	must(s.AddControls("req-c", []string{"output_guard"}))
	must(s.UpdateExplanation("req-b", Explanation{Status: "generated", Title: "Action stopped"}))
	must(s.SetIncidentState("req-b", "investigating", "checking", "secops"))
}

func verify(t *testing.T, s *Store) AuditIntegrity {
	t.Helper()
	got, err := s.VerifyAudit()
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func hasProblem(got AuditIntegrity, kind, record string) bool {
	for _, p := range got.Problems {
		if p.Kind == kind && (record == "" || p.Record == record) {
			return true
		}
	}
	return false
}

func TestAuditChainIntactAfterEveryWritePath(t *testing.T) {
	s := chainStore(t, filepath.Join(t.TempDir(), "audit.db"))
	seedAudit(t, s)
	got := verify(t, s)
	if got.Status != "intact" || got.Events != 4 || got.Incidents != 1 || got.Entries != 9 || got.Baseline != 0 {
		t.Fatalf("expected an intact chain with 9 entries: %+v", got)
	}
	if got.KeySource != "file" || len(got.HeadHash) != 64 {
		t.Fatalf("unexpected key source or head: %+v", got)
	}
}

func TestAuditChainDetectsTampering(t *testing.T) {
	cases := map[string]struct {
		sql    string
		kind   string
		record string
	}{
		"decision rewritten":         {`UPDATE audit_events SET decision='ALLOW' WHERE id='req-b'`, "record_modified", "event:req-b"},
		"execution status rewritten": {`UPDATE audit_events SET execution_status='VERDICT_ONLY' WHERE id='req-a'`, "record_modified", "event:req-a"},
		"evidence deleted":           {`DELETE FROM audit_events WHERE id='req-d'`, "record_deleted", "event:req-d"},
		"fake event inserted":        {`INSERT INTO audit_events(id,timestamp,user_id,decision) VALUES('fake','2026-01-01T00:00:00Z','bob','ALLOW')`, "record_unsealed", "event:fake"},
		"incident closed silently":   {`UPDATE incident_state SET status='resolved' WHERE id='req-b'`, "record_modified", "incident:req-b"},
		"seal forged for an edit":    {`UPDATE audit_chain SET record_hash='` + strings.Repeat("a", 64) + `' WHERE seq=2`, "chain_broken", "event:req-b"},
		"chain entry removed":        {`DELETE FROM audit_chain WHERE seq=3`, "sequence_gap", ""},
		"chain tail truncated":       {`DELETE FROM audit_chain WHERE seq>=8`, "truncated", ""},
		"NULL written into a column": {`UPDATE audit_events SET reasons=NULL WHERE id='req-c'`, "record_modified", "event:req-c"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.db")
			s := chainStore(t, path)
			seedAudit(t, s)
			// An attacker with file access edits the database directly.
			raw, err := sql.Open("sqlite3", path)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			if _, err := raw.Exec(tc.sql); err != nil {
				t.Fatal(err)
			}
			got := verify(t, s)
			if got.Status != "broken" || !hasProblem(got, tc.kind, tc.record) {
				t.Fatalf("tampering not detected as %s %s: %+v", tc.kind, tc.record, got)
			}
		})
	}
}

func TestLaterWriteCannotLaunderTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	s := chainStore(t, path)
	seedAudit(t, s)
	raw, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`UPDATE audit_events SET decision='ALLOW' WHERE id='req-b'`); err != nil {
		t.Fatal(err)
	}
	// The async explanation arrives after the edit and re-seals the row.
	if err := s.UpdateExplanation("req-b", Explanation{Status: "unavailable"}); err != nil {
		t.Fatal(err)
	}
	got := verify(t, s)
	if got.Status != "broken" || !hasProblem(got, "tamper_recorded", "event:req-b") {
		t.Fatalf("a later write laundered the tampering: %+v", got)
	}
	// Evidence is permanent: putting the old value back does not erase it.
	if _, err := raw.Exec(`UPDATE audit_events SET decision='BLOCK' WHERE id='req-b'`); err != nil {
		t.Fatal(err)
	}
	if got := verify(t, s); !hasProblem(got, "tamper_recorded", "event:req-b") {
		t.Fatalf("tamper record disappeared: %+v", got)
	}
}

func TestAuditChainCannotBeRecomputedWithoutTheKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	s := chainStore(t, path)
	seedAudit(t, s)
	s.Close()
	// Rewriting history and re-sealing it with a different key is detected.
	if err := os.Remove(path + ".audit-key"); err != nil {
		t.Fatal(err)
	}
	reopened := chainStore(t, path)
	if got := verify(t, reopened); got.Status != "broken" || !hasProblem(got, "chain_broken", "") {
		t.Fatalf("chain verified with a different key: %+v", got)
	}
}

func TestAuditChainSurvivesRestartAndSealsLegacyRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	s := chainStore(t, path)
	seedAudit(t, s)
	s.Close()
	if got := verify(t, chainStore(t, path)); got.Status != "intact" || got.Entries != 9 {
		t.Fatalf("chain broken after restart: %+v", got)
	}

	// A database from before the chain existed: rows are sealed as baseline.
	legacy := filepath.Join(t.TempDir(), "legacy.db")
	l := chainStore(t, legacy)
	seedAudit(t, l)
	if _, err := l.DB().Exec(`DELETE FROM audit_chain`); err != nil {
		t.Fatal(err)
	}
	l.Close()
	got := verify(t, chainStore(t, legacy))
	if got.Status != "intact" || got.Baseline != 5 || got.Entries != 5 {
		t.Fatalf("legacy rows were not sealed as baseline: %+v", got)
	}
}

func TestAuditVerifyEndpointIsSecurityOnly(t *testing.T) {
	e, _ := testEngine(t, SemanticScores{})
	evaluate(t, e, baseRequest())
	h := NewServer(e, "").Handler()
	if code, _ := getJSON(t, h, "demo-key", "/v1/audit/verify"); code != 403 {
		t.Fatalf("analyst could verify the full audit chain: %d", code)
	}
	code, got := getJSON(t, h, "secops-demo-key", "/v1/audit/verify")
	if code != 200 || got["status"] != "intact" || got["events"].(float64) < 1 {
		t.Fatalf("verify failed: %d %v", code, got)
	}
	_, export := getJSON(t, h, "secops-demo-key", "/v1/audit/export.json")
	if integrity, ok := export["integrity"].(map[string]any); !ok || integrity["status"] != "intact" {
		t.Fatalf("JSON export carries no integrity proof: %v", export["integrity"])
	}
}
