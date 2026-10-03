package gateway

import (
	"encoding/base64"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

type Finding struct {
	Kind, Value string
	Start, End  int
}

type detector struct {
	kind string
	re   *regexp.Regexp
	// valid optionally rejects a candidate; text is the full input so context
	// (e.g. "tel." before a bare number) can be inspected.
	valid func(text string, start, end int) bool
}

var secretKinds = map[string]bool{"SECRET": true, "JWT": true, "API_KEY": true, "PASSWORD": true, "PRIVATE_KEY": true, "AWS_ACCESS_KEY": true, "AWS_SECRET": true, "GITHUB_TOKEN": true, "SLACK_TOKEN": true, "GOOGLE_API_KEY": true, "BEARER_TOKEN": true, "CONNECTION_STRING": true, "ENCODED_SECRET": true}

func isSecretKind(kind string) bool { return secretKinds[kind] }

var deterministicPatterns = []detector{
	{"PRIVATE_KEY", regexp.MustCompile(`-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----(?:[\s\S]*?-----END (?:[A-Z]+ )*PRIVATE KEY-----)?`), nil},
	{"JWT", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), nil},
	{"AWS_ACCESS_KEY", regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b`), nil},
	{"AWS_SECRET", regexp.MustCompile(`(?i)aws_?secret_?access_?key["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}`), nil},
	{"GITHUB_TOKEN", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b`), nil},
	{"SLACK_TOKEN", regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}\b`), nil},
	{"GOOGLE_API_KEY", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`), nil},
	{"CONNECTION_STRING", regexp.MustCompile(`(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|mssql|sqlserver)://[^\s:/@]+:[^\s@]+@\S+`), nil},
	{"BEARER_TOKEN", regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{20,}=*`), nil},
	{"API_KEY", regexp.MustCompile(`(?i)\b(?:sk|pk|rk|api|key)[-_][a-z0-9_-]{16,}\b`), nil},
	{"PASSWORD", regexp.MustCompile(`(?i)\b(?:password|passwd|pwd|hasło|haslo|secret|api[_ -]?key|token)\s*(?:[:=]|\bis\b|\bto\b|\bjest\b|\bwynosi\b)\s*["']?([^\s,;"']{4,})`), validPasswordValue},
	{"EMAIL", regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`), nil},
	{"IBAN", regexp.MustCompile(`\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b`), validIBANMatch},
	{"PESEL", regexp.MustCompile(`\b\d(?:[ -]?\d){10}\b`), func(t string, s, e int) bool { return validPESEL(digitsOnly(t[s:e])) }},
	{"CREDIT_CARD", regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`), func(t string, s, e int) bool { return validLuhn(t[s:e]) }},
	{"NIP", regexp.MustCompile(`\b\d{3}-?\d{3}-?\d{2}-?\d{2}\b|\b\d{3}-\d{2}-\d{2}-\d{3}\b`), validNIPMatch},
	{"ID_CARD", regexp.MustCompile(`\b[A-Z]{3} ?\d{6}\b`), func(t string, s, e int) bool { return validIDCard(strings.ReplaceAll(t[s:e], " ", "")) }},
	{"POLISH_PHONE", regexp.MustCompile(`(?:\+48|\b0048)[ -]?\d{3}[ -]?\d{3}[ -]?\d{3}\b|\b\d{3}[ -]\d{3}[ -]\d{3}\b|\b\d{9}\b`), validPhoneMatch},
}

// Canonicalize removes invisible characters and folds full-width forms so
// that zero-width or look-alike tricks cannot split a signature or identifier.
// The canonical text is what the gateway inspects and forwards downstream.
func Canonicalize(text string) string {
	if text == "" {
		return text
	}
	var b strings.Builder
	b.Grow(len(text))
	for _, r := range text {
		switch {
		case r == '\u00AD' || r == '\u180E' || (r >= '\u200B' && r <= '\u200F') || (r >= '\u202A' && r <= '\u202E') || (r >= '\u2060' && r <= '\u2064') || (r >= '\u2066' && r <= '\u2069') || r == '\uFEFF':
			continue
		case r >= '\uFF01' && r <= '\uFF5E':
			b.WriteRune(r - 0xFEE0)
		case r == '\u3000' || r == '\u00A0' || (r >= '\u2000' && r <= '\u200A') || r == '\u202F' || r == '\u205F':
			b.WriteByte(' ')
		case r == '\u2010' || r == '\u2011' || r == '\u2012' || r == '\u2013' || r == '\u2014' || r == '\u2212' || r == '\uFE63':
			b.WriteByte('-')
		case unicode.IsControl(r) && r != '\n' && r != '\t' && r != '\r':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

var homoglyphs = map[rune]rune{'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ɡ': 'g', 'һ': 'h', 'ⅼ': 'l', 'ο': 'o', 'α': 'a', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'τ': 't', 'Α': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X'}

// skeleton folds Cyrillic/Greek look-alikes for signature matching only; it
// is never forwarded, so legitimate non-Latin text is not altered.
func skeleton(text string) string {
	return strings.Map(func(r rune) rune {
		if v, ok := homoglyphs[r]; ok {
			return v
		}
		return r
	}, text)
}

var base64Blob = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)
var percentBlob = regexp.MustCompile(`(?:%[0-9A-Fa-f]{2}){3,}`)

type decodedBlob struct {
	Start, End int
	Text       string
}

// DecodedPayloads returns printable base64 / URL-encoded payloads hidden in
// text, so signatures and secret detectors also see what an agent would run.
func DecodedPayloads(text string) []decodedBlob {
	var out []decodedBlob
	for _, loc := range base64Blob.FindAllStringIndex(text, 20) {
		raw := text[loc[0]:loc[1]]
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
			decoded, err := enc.DecodeString(raw)
			if err == nil && printable(decoded) {
				out = append(out, decodedBlob{loc[0], loc[1], string(decoded)})
				break
			}
		}
	}
	for _, loc := range percentBlob.FindAllStringIndex(text, 20) {
		if decoded, err := url.PathUnescape(text[loc[0]:loc[1]]); err == nil && printable([]byte(decoded)) {
			out = append(out, decodedBlob{loc[0], loc[1], decoded})
		}
	}
	return out
}

func printable(b []byte) bool {
	if len(b) < 6 || !utf8.Valid(b) {
		return false
	}
	ok := 0
	total := 0
	for _, r := range string(b) {
		total++
		if unicode.IsPrint(r) || r == '\n' || r == '\t' {
			ok++
		}
	}
	return total > 0 && float64(ok)/float64(total) >= 0.95
}

func ScanSensitive(text string) []Finding {
	var out []Finding
	for _, p := range deterministicPatterns {
		for _, loc := range p.re.FindAllStringSubmatchIndex(text, -1) {
			start, end := loc[0], loc[1]
			if p.valid != nil && !p.valid(text, start, end) {
				continue
			}
			out = append(out, Finding{p.kind, text[start:end], start, end})
		}
	}
	// Secrets hidden in base64 / URL encoding are reported over the encoded span.
	for _, blob := range DecodedPayloads(text) {
		for _, f := range ScanSensitive(blob.Text) {
			if isSecretKind(f.Kind) {
				out = append(out, Finding{"ENCODED_SECRET", text[blob.Start:blob.End], blob.Start, blob.End})
				break
			}
		}
	}
	return nonOverlapping(out)
}

func RedactText(text string, findings []Finding) string {
	if len(findings) == 0 {
		return text
	}
	var b strings.Builder
	pos := 0
	for _, f := range findings {
		if f.Start < pos || f.End > len(text) {
			continue
		}
		b.WriteString(text[pos:f.Start])
		b.WriteString("[REDACTED:")
		b.WriteString(f.Kind)
		b.WriteByte(']')
		pos = f.End
	}
	b.WriteString(text[pos:])
	return b.String()
}

// RedactAll is used for audit metadata and explanation inputs.
func RedactAll(text string) string { return RedactText(text, ScanSensitive(Canonicalize(text))) }

func digitsOnly(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)
}

func validPESEL(value string) bool {
	if len(value) != 11 {
		return false
	}
	w := []int{1, 3, 7, 9, 1, 3, 7, 9, 1, 3}
	sum := 0
	for i := 0; i < 10; i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
		sum += int(value[i]-'0') * w[i]
	}
	if int(value[10]-'0') != (10-sum%10)%10 {
		return false
	}
	month := int(value[2]-'0')*10 + int(value[3]-'0')
	day := int(value[4]-'0')*10 + int(value[5]-'0')
	monthOK := (month >= 1 && month <= 12) || (month >= 21 && month <= 32) || (month >= 41 && month <= 52) || (month >= 61 && month <= 72) || (month >= 81 && month <= 92)
	return monthOK && day >= 1 && day <= 31
}

func validLuhn(value string) bool {
	var digits []int
	for _, r := range value {
		if unicode.IsDigit(r) {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	parity := len(digits) % 2
	for i, d := range digits {
		if i%2 == parity {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

func validIBANMatch(text string, s, e int) bool {
	iban := strings.ReplaceAll(text[s:e], " ", "")
	if len(iban) < 15 || len(iban) > 34 {
		return false
	}
	rearranged := iban[4:] + iban[:4]
	var num strings.Builder
	for _, r := range rearranged {
		switch {
		case r >= '0' && r <= '9':
			num.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			num.WriteString(fmt.Sprint(int(r-'A') + 10))
		default:
			return false
		}
	}
	n, ok := new(big.Int).SetString(num.String(), 10)
	return ok && new(big.Int).Mod(n, big.NewInt(97)).Int64() == 1
}

func validNIPMatch(text string, s, e int) bool {
	d := digitsOnly(text[s:e])
	if len(d) != 10 {
		return false
	}
	w := []int{6, 5, 7, 2, 3, 4, 5, 6, 7}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(d[i]-'0') * w[i]
	}
	if sum%11 == 10 || sum%11 != int(d[9]-'0') {
		return false
	}
	// A bare 10-digit number is only a NIP when the text says so or when it
	// uses the official dashed layout; this avoids masking order numbers.
	return strings.Contains(text[s:e], "-") || hasContext(text, s, []string{"nip", "tax id", "vat"})
}

func validIDCard(v string) bool {
	if len(v) != 9 {
		return false
	}
	val := func(r byte) int {
		if r >= 'A' && r <= 'Z' {
			return int(r-'A') + 10
		}
		return int(r - '0')
	}
	w := []int{7, 3, 1, 0, 7, 3, 1, 7, 3}
	sum := 0
	for i := 0; i < 9; i++ {
		if i != 3 {
			sum += val(v[i]) * w[i]
		}
	}
	return sum%10 == int(v[3]-'0')
}

func validPhoneMatch(text string, s, e int) bool {
	m := text[s:e]
	if strings.HasPrefix(m, "+") || strings.HasPrefix(m, "0048") || strings.ContainsAny(m, " -") {
		return true
	}
	return hasContext(text, s, []string{"tel", "phone", "mobile", "komórk", "komork", "zadzwoń", "zadzwon", "call", "numer telefonu", "nr kontaktowy"})
}

func validPasswordValue(text string, s, e int) bool {
	m := text[s:e]
	if strings.ContainsAny(m, ":=") {
		return true
	}
	// "password is X" style: only flag values that look like a credential.
	fields := strings.Fields(m)
	v := strings.Trim(fields[len(fields)-1], `"'`)
	hasDigit, hasOther := false, false
	for _, r := range v {
		if unicode.IsDigit(r) {
			hasDigit = true
		} else if !unicode.IsLetter(r) {
			hasOther = true
		}
	}
	return len(v) >= 6 && (hasDigit || hasOther)
}

func hasContext(text string, start int, words []string) bool {
	from := start - 24
	if from < 0 {
		from = 0
	}
	ctx := strings.ToLower(text[from:start])
	for _, w := range words {
		if strings.Contains(ctx, w) {
			return true
		}
	}
	return false
}

type ThreatHit struct {
	ID, Action, Severity, Description string
}

// MatchThreats evaluates the pre-compiled signature feed against the given
// texts, their homoglyph skeleton and any decoded payload they contain.
func MatchThreats(texts []string, sigs []compiledSignature) []ThreatHit {
	var corpus []string
	for _, t := range texts {
		if t == "" {
			continue
		}
		corpus = append(corpus, t, skeleton(t))
		for _, blob := range DecodedPayloads(t) {
			corpus = append(corpus, blob.Text)
		}
	}
	var hits []ThreatHit
	for _, sig := range sigs {
		for _, t := range corpus {
			if sig.re.MatchString(t) {
				hits = append(hits, ThreatHit{ID: sig.ID, Action: strings.ToLower(sig.Action), Severity: sig.Severity, Description: sig.Description})
				break
			}
		}
	}
	return hits
}

// Deterministic memory-poisoning patterns: persistent instructions that try
// to weaken authentication, approval or policy for future sessions.
var memoryPoisonPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:don'?t|do not|doesn'?t|does not|no longer|never)\s+(?:need|require|ask for|check)\w*\s+(?:any\s+)?(?:authentication|authorization|approval|verification|password|mfa|2fa|login)`),
	regexp.MustCompile(`(?i)\b(?:from now on|always|in future|od teraz|zawsze|w przyszłości)\b.{0,60}\b(?:ignore|skip|bypass|disable|trust|approve|without|ignoruj|pomijaj|pomiń|wyłącz|ufaj|zatwierdzaj|bez)\b`),
	regexp.MustCompile(`(?i)\bnie\s+(?:wymaga|potrzebuj|sprawdzaj|pytaj)\w*\s+(?:o\s+)?(?:uwierzytelni|autoryzacj|zgod|weryfikacj|hasł|logowani)`),
	regexp.MustCompile(`(?i)\b(?:admins?|administrators?|administrator\w*|root|superuser)\b.{0,40}\b(?:no|without|bez|nie|don'?t)\b.{0,30}\b(?:auth\w*|password|hasł\w*|login|approval|zgod\w*|uwierzytelni\w*)`),
	regexp.MustCompile(`(?i)\b(?:remember|zapamiętaj|zapamietaj)\b.{0,40}\b(?:system prompt|instructions?|instrukcj\w*|policy|polityk\w*)\b`),
}

func memoryPoisonScore(text string) float64 {
	for _, re := range memoryPoisonPatterns {
		if re.MatchString(text) {
			return 0.92
		}
	}
	return 0
}

func contains(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}

func intersection(a, b []string) []string {
	bm := map[string]bool{}
	for _, v := range b {
		bm[v] = true
	}
	var out []string
	for _, v := range a {
		if bm[v] {
			out = append(out, v)
		}
	}
	return uniqueSorted(out)
}

func maxFloat(vs ...float64) float64 {
	m := 0.0
	for _, v := range vs {
		if v > m {
			m = v
		}
	}
	if m > 1 {
		return 1
	}
	return m
}
