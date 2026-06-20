package main

import "testing"

func TestValidatePasswordHashFormatRejectsMalformedHashes(t *testing.T) {
	tests := []string{
		"",
		"$argon2i$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=16$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=65536,t=3,p=4x$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=65536,t=3,p=4$$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$",
	}

	for _, tt := range tests {
		if err := ValidatePasswordHashFormat(tt); err == nil {
			t.Fatalf("expected hash %q to be rejected", tt)
		}
	}
}

func TestVerifyPasswordRejectsWrongPassword(t *testing.T) {
	ok, err := verifyPassword("wrong-password", dummyPasswordHash)
	if err != nil {
		t.Fatalf("expected dummy hash format to be valid, got %v", err)
	}
	if ok {
		t.Fatal("expected wrong password to be rejected")
	}
}
