package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAdminWriteRoutesRequireBoundSessionCSRFAndSameOrigin(t *testing.T) {
	server, store := testApp(t)
	server.cfg.SessionTTL = time.Hour
	password, err := passwordHash("a-secure-admin-password", 10_000)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := store.vault.Encrypt("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "admin-totp")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteAdminSetup(context.Background(), "secure-admin", password, secret, -1); err != nil {
		t.Fatal(err)
	}

	const adminIP = "203.0.113.241"
	session, csrf, err := store.NewAdminSession(context.Background(), adminIP, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		origin string
		csrf   string
	}{
		{name: "missing csrf"},
		{name: "wrong csrf", csrf: "not-the-session-token"},
		{name: "cross origin", origin: "https://attacker.invalid", csrf: csrf},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodDelete, "http://admin.local/api/keys/999", nil)
			request.RemoteAddr = adminIP + ":4321"
			request.AddCookie(&http.Cookie{Name: adminCookieName, Value: session})
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			if test.csrf != "" {
				request.Header.Set("X-CSRF-Token", test.csrf)
			}
			recorder := httptest.NewRecorder()
			server.adminHandler().ServeHTTP(recorder, request)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestPortalWriteRoutesRequireBoundSessionCSRFAndSameOrigin(t *testing.T) {
	server, store := testApp(t)
	user, err := store.CreateDesktopUser(context.Background(), "csrf@example.com", "CSRF User", "a-strong-desktop-password")
	if err != nil {
		t.Fatal(err)
	}

	const userIP = "203.0.113.242"
	session, csrf, err := store.NewUserSession(context.Background(), user.ID, userIP, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		origin string
		csrf   string
	}{
		{name: "missing csrf"},
		{name: "wrong csrf", csrf: "not-the-session-token"},
		{name: "cross origin", origin: "https://attacker.invalid", csrf: csrf},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodDelete, "http://portal.local/api/portal/devices/999", nil)
			request.RemoteAddr = userIP + ":4321"
			request.AddCookie(&http.Cookie{Name: userCookieName, Value: session})
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			if test.csrf != "" {
				request.Header.Set("X-CSRF-Token", test.csrf)
			}
			recorder := httptest.NewRecorder()
			server.portalHandler().ServeHTTP(recorder, request)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestGuideCrossOriginAuthIsRejectedWithoutPoisoningFailureCounter(t *testing.T) {
	server, _ := testApp(t)
	const clientIP = "203.0.113.243"

	for attempt := 0; attempt < 10; attempt++ {
		request := httptest.NewRequest(http.MethodPost, "http://guide.local/api/guide/auth/key", strings.NewReader(`{"key":"fg-test-key-that-is-not-valid"}`))
		request.RemoteAddr = clientIP + ":4321"
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "https://attacker.invalid")
		recorder := httptest.NewRecorder()
		server.guideHandler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("attempt=%d status=%d body=%s", attempt+1, recorder.Code, recorder.Body.String())
		}
	}

	request := httptest.NewRequest(http.MethodPost, "http://guide.local/api/guide/auth/key", strings.NewReader(`{"key":"fg-test-key-that-is-not-valid"}`))
	request.RemoteAddr = clientIP + ":4321"
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.guideHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("same-origin status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
