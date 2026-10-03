package gateway

import "testing"

func TestPolishPESELValidation(t *testing.T) {
	if !validPESEL("44051401458") {
		t.Fatal("known valid PESEL rejected")
	}
	if validPESEL("99010112345") {
		t.Fatal("invalid checksum accepted")
	}
}
func TestLuhnValidation(t *testing.T) {
	if !validLuhn("4111 1111 1111 1111") {
		t.Fatal("test card rejected")
	}
	if validLuhn("4111 1111 1111 1112") {
		t.Fatal("bad card accepted")
	}
}
func TestRedactionDoesNotLeak(t *testing.T) {
	text := "E-mail jan@example.pl, PESEL 44051401458"
	out := RedactText(text, ScanSensitive(text))
	if out == text {
		t.Fatal("nothing redacted")
	}
}
