package main

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func testTincPublicKey() string {
	return base64.StdEncoding.EncodeToString(make([]byte, tincPublicKeyLength))
}

func requireValidationCode(t *testing.T, err error, field, code string) {
	t.Helper()
	var vErr *ValidationError
	if !errors.As(err, &vErr) {
		t.Fatalf("expected ValidationError, got %T: %v", err, err)
	}
	if vErr.Field != field || vErr.Code != code {
		t.Fatalf("expected %s:%s, got %s:%s", field, code, vErr.Field, vErr.Code)
	}
}

func TestValidatePeerRemoveDoesNotRequirePublicKeyOrAllowedIP(t *testing.T) {
	err := ValidatePeer(&upconf{
		nodename: "ualice",
		status:   false,
	})
	if err != nil {
		t.Fatalf("expected remove peer without public key or allowed IP to be valid, got %v", err)
	}
}

func TestValidatePeerAddRequiresAllowedIP(t *testing.T) {
	err := ValidatePeer(&upconf{
		nodename:   "ualice",
		userpublic: testTincPublicKey(),
		status:     true,
	})
	requireValidationCode(t, err, "allowed_ip", "missing")
}

func TestValidatePeerRejectsBroadSubnet(t *testing.T) {
	err := ValidatePeer(&upconf{
		nodename:   "ualice",
		userpublic: testTincPublicKey(),
		userip:     "10.0.0.0/24",
		status:     true,
	})
	requireValidationCode(t, err, "allowed_ip", "ipv4_too_wide")
}

func TestNormalizePeerIP(t *testing.T) {
	got, err := NormalizePeerIP("10.0.0.2")
	if err != nil {
		t.Fatalf("expected plain IP to be valid, got %v", err)
	}
	if got != "10.0.0.2/32" {
		t.Fatalf("expected normalized IPv4 host route, got %q", got)
	}
}

func TestValidatePeerAddRequiresValidNodeName(t *testing.T) {
	err := ValidatePeer(&upconf{
		nodename:   "bad-name",
		userpublic: testTincPublicKey(),
		userip:     "10.0.0.2/32",
		status:     true,
	})
	requireValidationCode(t, err, "tinc_name", "invalid_format")
}

func TestValidatePeerNil(t *testing.T) {
	err := ValidatePeer(nil)
	requireValidationCode(t, err, "request", "nil")
}

func TestTincNodeNameIsStableAndValid(t *testing.T) {
	name := tincNodeName("alice.smith-prod")
	if name != tincNodeName("alice.smith-prod") {
		t.Fatal("expected stable tinc node name")
	}
	if err := ValidateTincName(name); err != nil {
		t.Fatalf("expected valid tinc node name, got %v", err)
	}
}

func TestValidateTimestampRejectsSignedValues(t *testing.T) {
	_, err := ValidateTimestamp("+123", time.Unix(123, 0))
	requireValidationCode(t, err, "timestamp", "invalid_format")

	_, err = ValidateTimestamp("-123", time.Unix(123, 0))
	requireValidationCode(t, err, "timestamp", "invalid_format")
}

func TestValidatePubKeyTrimsSpace(t *testing.T) {
	if err := ValidatePubKey(" \t" + testTincPublicKey() + "\n"); err != nil {
		t.Fatalf("expected trimmed public key to be valid, got %v", err)
	}
}

func TestValidatePubKeyAllowsTincUnpaddedKey(t *testing.T) {
	if err := ValidatePubKey(strings.TrimRight(testTincPublicKey(), "=")); err != nil {
		t.Fatalf("expected unpadded tinc public key to be valid, got %v", err)
	}
}

func TestValidationMessagesCoverSanitizeErrors(t *testing.T) {
	tests := []struct {
		field string
		code  string
	}{
		{field: "pubkey", code: "invalid_format"},
		{field: "pubkey", code: "invalid_utf8"},
		{field: "pubkey", code: "invalid_chars"},
		{field: "tinc_name", code: "invalid_format"},
		{field: "timestamp", code: "invalid_utf8"},
		{field: "timestamp", code: "invalid_chars"},
		{field: "signature", code: "invalid_utf8"},
		{field: "signature", code: "invalid_chars"},
	}

	for _, tt := range tests {
		err := NewValidationError(tt.field, tt.code)
		if strings.TrimSpace(err.Message) == "" {
			t.Fatalf("missing message for %s:%s", tt.field, tt.code)
		}
		if err.Status != http.StatusBadRequest {
			t.Fatalf("expected bad request status for %s:%s, got %d", tt.field, tt.code, err.Status)
		}
	}
}
