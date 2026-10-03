package gateway

// Tamper-evident audit log. Every write to an audit event or to an incident's
// workflow state appends one entry to audit_chain in the same transaction.
// An entry holds the SHA-256 of the record's new state and an HMAC-SHA256
// linking it to the previous entry, so VerifyAudit detects a row edited,
// deleted or inserted outside the gateway, an edited or removed chain entry,
// and a truncated chain tail. Recomputing the chain needs the audit key,
// which is kept outside the database (MASQE_AUDIT_KEY or <db>.audit-key).

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	chainGenesis        = "0000000000000000000000000000000000000000000000000000000000000000"
	maxIntegrityReports = 50
)

// AuditIntegrity is the result of verifying the whole audit chain.
type AuditIntegrity struct {
	Status       string         `json:"status"` // intact | broken
	Entries      int64          `json:"entries"`
	Events       int            `json:"events"`
	Incidents    int            `json:"incidents"`
	HeadSeq      int64          `json:"head_seq"`
	HeadHash     string         `json:"head_hash"`
	Baseline     int            `json:"baseline_sealed"`
	KeySource    string         `json:"key_source"` // env | file | ephemeral
	VerifiedAt   string         `json:"verified_at"`
	DurationMS   float64        `json:"duration_ms"`
	ProblemCount int            `json:"problem_count"`
	Problems     []AuditProblem `json:"problems"`
}

// AuditProblem is one integrity violation. Kind is chain_broken,
// sequence_gap, truncated, record_modified, record_deleted, record_unsealed
// or tamper_recorded (found and preserved when the gateway next wrote it).
type AuditProblem struct {
	Kind   string `json:"kind"`
	Seq    int64  `json:"seq,omitempty"`
	Record string `json:"record"`
	Detail string `json:"detail"`
}

type queryer interface {
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
}

// loadAuditKey returns the HMAC key: MASQE_AUDIT_KEY, else a key file next to
// the database (created on first start), else a per-process key for
// in-memory databases.
func loadAuditKey(dbPath string) ([]byte, string, error) {
	if k := os.Getenv("MASQE_AUDIT_KEY"); k != "" {
		if len(k) < 16 {
			return nil, "", errors.New("MASQE_AUDIT_KEY must be at least 16 characters")
		}
		return []byte(k), "env", nil
	}
	if dbPath == "" || dbPath == ":memory:" || strings.HasPrefix(dbPath, "file:") {
		key := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, "", err
		}
		return key, "ephemeral", nil
	}
	path := dbPath + ".audit-key"
	if b, err := os.ReadFile(path); err == nil {
		key := strings.TrimSpace(string(b))
		if len(key) < 32 {
			return nil, "", fmt.Errorf("audit key %s is too short", path)
		}
		return []byte(key), "file", nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	}
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return nil, "", err
	}
	key := hex.EncodeToString(raw)
	if err := os.WriteFile(path, []byte(key+"\n"), 0o600); err != nil {
		return nil, "", err
	}
	return []byte(key), "file", nil
}

func (s *Store) chainHash(seq int64, record, kind, at, recordHash, prev string) string {
	mac := hmac.New(sha256.New, s.chainKey)
	fmt.Fprintf(mac, "%d\x00%s\x00%s\x00%s\x00%s\x00%s", seq, record, kind, at, recordHash, prev)
	return hex.EncodeToString(mac.Sum(nil))
}

// digestRow hashes the raw stored column values of one row, independent of
// the Go structs and JSON field names.
func digestRow(cols []string, vals []any) string {
	h := sha256.New()
	for i, c := range cols {
		io.WriteString(h, c)
		switch v := vals[i].(type) {
		case nil:
			io.WriteString(h, "=null")
		case []byte:
			fmt.Fprintf(h, "=s%d:%s", len(v), v)
		case string:
			fmt.Fprintf(h, "=s%d:%s", len(v), v)
		case int64:
			fmt.Fprintf(h, "=i%d", v)
		case float64:
			io.WriteString(h, "=f"+strconv.FormatFloat(v, 'g', -1, 64))
		case bool:
			fmt.Fprintf(h, "=i%d", map[bool]int{false: 0, true: 1}[v])
		case time.Time:
			io.WriteString(h, "=t"+v.UTC().Format(time.RFC3339Nano))
		default:
			fmt.Fprintf(h, "=?%v", v)
		}
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// scanDigests calls fn with the record id (first column) and digest of every row.
func scanDigests(q queryer, query string, fn func(id, digest string), args ...any) error {
	rows, err := q.Query(query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return err
	}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		id := ""
		switch v := vals[0].(type) {
		case string:
			id = v
		case []byte:
			id = string(v)
		}
		fn(id, digestRow(cols, vals))
	}
	return rows.Err()
}

const (
	sealEventQuery    = `SELECT ` + auditColumns + ` FROM audit_events`
	sealIncidentQuery = `SELECT id,status,note,updated_by,updated_at FROM incident_state`
)

func recordDigest(q queryer, record string) (string, error) {
	kind, id, _ := strings.Cut(record, ":")
	query := sealEventQuery
	if kind == "incident" {
		query = sealIncidentQuery
	}
	digest := ""
	if err := scanDigests(q, query+` WHERE id=?`, func(_, d string) { digest = d }, id); err != nil {
		return "", err
	}
	if digest == "" {
		return "", sql.ErrNoRows
	}
	return digest, nil
}

// writeSealed runs write and appends the chain entry for the record's new
// state in one transaction: a row is never stored without its seal. A row
// that no longer matches its last seal was changed outside the gateway; that
// is recorded permanently first, so a legitimate later write (an async
// explanation, an approval) cannot launder the edit into a fresh seal.
func (s *Store) writeSealed(record, kind string, write func(*sql.Tx) error) error {
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	before, err := recordDigest(tx, record)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var sealed string
	if err := tx.QueryRow(`SELECT record_hash FROM audit_chain WHERE record=? ORDER BY seq DESC LIMIT 1`, record).Scan(&sealed); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if before != sealed {
		observed := before
		if observed == "" {
			observed = "deleted"
		}
		if _, err := s.appendChain(tx, record, "tampered", observed); err != nil {
			return err
		}
	}
	if err := write(tx); err != nil {
		return err
	}
	digest, err := recordDigest(tx, record)
	if err != nil {
		return err
	}
	seq, err := s.appendChain(tx, record, kind, digest)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.chainHead = seq
	return nil
}

func (s *Store) appendChain(tx *sql.Tx, record, kind, digest string) (int64, error) {
	seq, prev := int64(0), chainGenesis
	if err := tx.QueryRow(`SELECT seq,hash FROM audit_chain ORDER BY seq DESC LIMIT 1`).Scan(&seq, &prev); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	seq++
	at := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := tx.Exec(`INSERT INTO audit_chain(seq,record,kind,at,record_hash,prev_hash,hash) VALUES(?,?,?,?,?,?,?)`, seq, record, kind, at, digest, prev, s.chainHash(seq, record, kind, at, digest, prev))
	return seq, err
}

// sealExisting seals rows written before the chain existed (upgrade of an
// older database). They are marked "baseline": protected from now on, but
// their earlier history cannot be vouched for.
func (s *Store) sealExisting() error {
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var entries int64
	if err := tx.QueryRow(`SELECT COUNT(*) FROM audit_chain`).Scan(&entries); err != nil {
		return err
	}
	if entries == 0 {
		type pending struct{ record, digest string }
		var rows []pending
		collect := func(prefix string) func(id, digest string) {
			return func(id, digest string) { rows = append(rows, pending{prefix + id, digest}) }
		}
		if err := scanDigests(tx, sealEventQuery+` ORDER BY timestamp, id`, collect("event:")); err != nil {
			return err
		}
		if err := scanDigests(tx, sealIncidentQuery+` ORDER BY id`, collect("incident:")); err != nil {
			return err
		}
		for _, r := range rows {
			if _, err := s.appendChain(tx, r.record, "baseline", r.digest); err != nil {
				return err
			}
		}
	}
	if err := tx.QueryRow(`SELECT COALESCE(MAX(seq),0) FROM audit_chain`).Scan(&s.chainHead); err != nil {
		return err
	}
	return tx.Commit()
}

// VerifyAudit recomputes the chain and compares it with the stored rows,
// inside one read transaction on a separate read-only connection so it
// sees a consistent snapshot and does not block the gateway's writes.
func (s *Store) VerifyAudit() (AuditIntegrity, error) {
	started := time.Now()
	out := AuditIntegrity{Status: "intact", KeySource: s.chainKeySource, Problems: []AuditProblem{}}
	report := func(p AuditProblem) {
		out.ProblemCount++
		if len(out.Problems) < maxIntegrityReports {
			out.Problems = append(out.Problems, p)
		}
	}
	s.chainMu.Lock()
	writtenHead := s.chainHead
	s.chainMu.Unlock()

	tx, err := s.readDB.Begin()
	if err != nil {
		return out, err
	}
	defer tx.Rollback()

	latest := map[string]string{}
	rows, err := tx.Query(`SELECT seq,record,kind,at,record_hash,prev_hash,hash FROM audit_chain ORDER BY seq`)
	if err != nil {
		return out, err
	}
	expectSeq, prev := int64(1), chainGenesis
	for rows.Next() {
		var seq int64
		var record, kind, at, digest, prevHash, hash string
		if err := rows.Scan(&seq, &record, &kind, &at, &digest, &prevHash, &hash); err != nil {
			rows.Close()
			return out, err
		}
		if seq != expectSeq {
			report(AuditProblem{Kind: "sequence_gap", Seq: seq, Record: record, Detail: fmt.Sprintf("entries %d–%d are missing", expectSeq, seq-1)})
		}
		if prevHash != prev {
			report(AuditProblem{Kind: "chain_broken", Seq: seq, Record: record, Detail: "link to the previous entry does not match"})
		}
		if !hmac.Equal([]byte(hash), []byte(s.chainHash(seq, record, kind, at, digest, prevHash))) {
			report(AuditProblem{Kind: "chain_broken", Seq: seq, Record: record, Detail: "entry was altered or the audit key changed"})
		}
		switch kind {
		case "baseline":
			out.Baseline++
		case "tampered":
			report(AuditProblem{Kind: "tamper_recorded", Seq: seq, Record: record, Detail: "changed outside the gateway; caught and preserved when the gateway next wrote this record"})
		}
		latest[record] = digest
		out.Entries++
		out.HeadSeq, out.HeadHash = seq, hash
		expectSeq, prev = seq+1, hash
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}
	if out.HeadSeq < writtenHead {
		report(AuditProblem{Kind: "truncated", Seq: out.HeadSeq + 1, Record: "audit_chain", Detail: fmt.Sprintf("chain ends at entry %d but this gateway wrote up to %d", out.HeadSeq, writtenHead)})
	}

	compare := func(prefix string, count *int) func(id, digest string) {
		return func(id, digest string) {
			*count++
			record := prefix + id
			sealed, ok := latest[record]
			delete(latest, record)
			switch {
			case !ok:
				report(AuditProblem{Kind: "record_unsealed", Record: record, Detail: "row exists but was never written by the gateway"})
			case sealed != digest:
				report(AuditProblem{Kind: "record_modified", Record: record, Detail: "row differs from its last sealed state"})
			}
		}
	}
	if err := scanDigests(tx, sealEventQuery+` ORDER BY timestamp, id`, compare("event:", &out.Events)); err != nil {
		return out, err
	}
	if err := scanDigests(tx, sealIncidentQuery+` ORDER BY id`, compare("incident:", &out.Incidents)); err != nil {
		return out, err
	}
	deleted := make([]string, 0, len(latest))
	for record := range latest {
		deleted = append(deleted, record)
	}
	for _, record := range uniqueSorted(deleted) {
		report(AuditProblem{Kind: "record_deleted", Record: record, Detail: "sealed row is missing"})
	}
	if out.ProblemCount > 0 {
		out.Status = "broken"
	}
	out.VerifiedAt = time.Now().UTC().Format(time.RFC3339)
	out.DurationMS = ms(time.Since(started))
	return out, nil
}
