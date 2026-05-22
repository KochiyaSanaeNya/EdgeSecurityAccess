package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewParsesUsers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.txt")
	content := "# comment\nalice:secret\nbob,pass\n// ignored\n\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write users file: %v", err)
	}

	auth := New(path)
	if got := auth.db["alice"]; got != "secret" {
		t.Fatalf("alice password = %q, want %q", got, "secret")
	}
	if got := auth.db["bob"]; got != "pass" {
		t.Fatalf("bob password = %q, want %q", got, "pass")
	}
}

func TestServeHTTPRequiresPost(t *testing.T) {
	auth := &Auth{db: map[string]string{}, Jobs: make(chan *AuthJob, 1)}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	auth.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestServeHTTPSuccessAndFailure(t *testing.T) {
	auth := &Auth{
		db:   map[string]string{"alice": "secret"},
		Jobs: make(chan *AuthJob, 2),
	}

	go func() {
		successJob := <-auth.Jobs
		if !successJob.Ok {
			t.Errorf("expected successful auth")
		}
		successJob.Data <- "ok"
		close(successJob.Data)

		failureJob := <-auth.Jobs
		if failureJob.Ok {
			t.Errorf("expected failed auth")
		}
		failureJob.Data <- "fail"
		close(failureJob.Data)
	}()

	successReq := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("username=alice&password=secret"))
	successReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	successRec := httptest.NewRecorder()
	auth.ServeHTTP(successRec, successReq)
	if successRec.Body.String() != "ok" {
		t.Fatalf("success response = %q, want %q", successRec.Body.String(), "ok")
	}

	failureReq := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("username=alice&password=wrong"))
	failureReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	failureRec := httptest.NewRecorder()
	auth.ServeHTTP(failureRec, failureReq)
	if failureRec.Body.String() != "fail" {
		t.Fatalf("failure response = %q, want %q", failureRec.Body.String(), "fail")
	}
}
