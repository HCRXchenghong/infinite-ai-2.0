package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func signedDesktopRequest(t *testing.T, method, target, token string, privateKey ed25519.PrivateKey, nonce string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, target, nil)
	request.RemoteAddr = "203.0.113.50:43210"
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Infinite-Content-SHA256", desktopBodyDigest(nil))
	request.Header.Set("X-Infinite-Device-MAC-Hash", tokenHash("02:42:ac:11:00:02"))
	request.Header.Set("X-Infinite-Device-Timestamp", timestamp)
	request.Header.Set("X-Infinite-Device-Nonce", nonce)
	request.Header.Set("X-Infinite-Device-Signature", base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(desktopCanonicalRequest(request, timestamp, nonce)))))
	return request
}

func TestDesktopSignatureBindsRequestBody(t *testing.T) {
	server, _ := testApp(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	original := []byte(`{"model":"gpt-5.6","input":"original"}`)
	tampered := []byte(`{"model":"gpt-5.6","input":"tampered"}`)
	request := httptest.NewRequest(http.MethodPost, "http://gateway/v1/responses", strings.NewReader(string(original)))
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "body-digest-nonce-with-enough-entropy"
	request.Header.Set("X-Infinite-Content-SHA256", desktopBodyDigest(original))
	request.Header.Set("X-Infinite-Device-Timestamp", timestamp)
	request.Header.Set("X-Infinite-Device-Nonce", nonce)
	request.Header.Set("X-Infinite-Device-Signature", base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(desktopCanonicalRequest(request, timestamp, nonce)))))
	request.Body = io.NopCloser(strings.NewReader(string(tampered)))

	if err := server.verifyDesktopRequest(request, base64.RawURLEncoding.EncodeToString(publicKey), 0); err != nil {
		t.Fatalf("valid signature was rejected before body read: %v", err)
	}
	if _, err := io.ReadAll(request.Body); !errors.Is(err, ErrDesktopBodyTampered) {
		t.Fatalf("tampered signed body err=%v", err)
	}
}

func TestDesktopSignatureRequiresBodyDigest(t *testing.T) {
	server, _ := testApp(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://gateway/api/desktop/session", nil)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "missing-digest-nonce-with-enough-entropy"
	request.Header.Set("X-Infinite-Device-Timestamp", timestamp)
	request.Header.Set("X-Infinite-Device-Nonce", nonce)
	request.Header.Set("X-Infinite-Device-Signature", base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(desktopCanonicalRequest(request, timestamp, nonce)))))
	if err := server.verifyDesktopRequest(request, base64.RawURLEncoding.EncodeToString(publicKey), 0); !errors.Is(err, ErrDesktopSessionInvalid) {
		t.Fatalf("missing body digest err=%v", err)
	}
}

func TestDesktopRefreshTokenRotatesAtomically(t *testing.T) {
	server, store := testApp(t)
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.CreateDesktopUser(context.Background(), "refresh@example.com", "Refresh User", "a-strong-desktop-password")
	if err != nil {
		t.Fatal(err)
	}
	deviceCode := "refresh-device-code-with-enough-entropy"
	userCode := "8765-4321"
	if err := store.CreateDesktopAuthFlow(context.Background(), deviceCode, userCode, base64.RawURLEncoding.EncodeToString(publicKey), "Refresh Device", "linux", "02:42:ac:11:00:03", "203.0.113.50", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := store.ApproveDesktopAuthFlow(context.Background(), userCode, user.ID, "203.0.113.50"); err != nil {
		t.Fatal(err)
	}
	_, refresh, auth, err := store.ConsumeApprovedDesktopFlow(context.Background(), deviceCode, server.cfg.DesktopAccessTTL, server.cfg.DesktopRefreshTTL)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := store.RotateDesktopSession(context.Background(), auth.SessionID, refresh, server.cfg.DesktopAccessTTL, server.cfg.DesktopRefreshTTL); err != nil {
		t.Fatalf("first refresh failed: %v", err)
	}
	if _, _, _, _, err := store.RotateDesktopSession(context.Background(), auth.SessionID, refresh, server.cfg.DesktopAccessTTL, server.cfg.DesktopRefreshTTL); !errors.Is(err, ErrDesktopSessionInvalid) {
		t.Fatalf("old refresh token was reusable: %v", err)
	}
}

func createAuthorizedDesktopSession(t *testing.T, server *Server, store *Store) (string, ed25519.PrivateKey, int64, int64) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.CreateDesktopUser(context.Background(), "friend@example.com", "王同学", "a-strong-desktop-password")
	if err != nil {
		t.Fatal(err)
	}
	_, key := createTestAccountAndKey(t, store, "desktop-user", "sk-fg_desktop-user", "198.51.100.31")
	if err := store.UpdateDesktopUser(context.Background(), user.ID, key.ID, "active"); err != nil {
		t.Fatal(err)
	}
	deviceCode := "desktop-device-code-with-enough-entropy"
	userCode := "1234-5678"
	encodedPublicKey := base64.RawURLEncoding.EncodeToString(publicKey)
	if err := store.CreateDesktopAuthFlow(context.Background(), deviceCode, userCode, encodedPublicKey, "Ubuntu 工作站", "linux", "02:42:ac:11:00:02", "203.0.113.50", 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := store.ApproveDesktopAuthFlow(context.Background(), userCode, user.ID, "198.51.100.99"); err != nil {
		t.Fatal(err)
	}
	access, _, auth, err := store.ConsumeApprovedDesktopFlow(context.Background(), deviceCode, server.cfg.DesktopAccessTTL, server.cfg.DesktopRefreshTTL)
	if err != nil {
		t.Fatal(err)
	}
	return access, privateKey, auth.DeviceID, key.ID
}

func TestDesktopSessionUsesDeviceSignatureRejectsReplayAndRevokesImmediately(t *testing.T) {
	server, store := testApp(t)
	access, privateKey, deviceID, keyID := createAuthorizedDesktopSession(t, server, store)

	first := signedDesktopRequest(t, http.MethodGet, "http://gateway/api/desktop/session", access, privateKey, "nonce-value-that-is-at-least-twenty-one")
	auth, err := server.desktopSessionRequest(first)
	if err != nil || auth.APIKeyID != keyID {
		t.Fatalf("desktop auth=%+v err=%v", auth, err)
	}
	if _, err := server.desktopSessionRequest(first); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("replayed signed request err=%v", err)
	}

	second := signedDesktopRequest(t, http.MethodGet, "http://gateway/api/desktop/session", access, privateKey, "second-nonce-value-with-enough-entropy")
	if _, err := server.desktopSessionRequest(second); err != nil {
		t.Fatalf("fresh signed request rejected: %v", err)
	}
	if err := store.RevokeDesktopDevice(context.Background(), deviceID, 0); err != nil {
		t.Fatal(err)
	}
	third := signedDesktopRequest(t, http.MethodGet, "http://gateway/api/desktop/session", access, privateKey, "third-nonce-value-with-enough-entropy-")
	if _, err := server.desktopSessionRequest(third); !errors.Is(err, ErrDesktopSessionInvalid) {
		t.Fatalf("revoked device retained access: %v", err)
	}
}

func TestDesktopMACEncryptedAndPublicAPIPolicyIsImmediate(t *testing.T) {
	server, store := testApp(t)
	access, privateKey, _, _ := createAuthorizedDesktopSession(t, server, store)
	devices, err := store.ListDesktopDevices(context.Background(), 0)
	if err != nil || len(devices) != 1 || devices[0].MAC != "02:42:ac:11:00:02" || devices[0].RegisteredIP != "198.51.100.99" {
		t.Fatalf("devices=%+v err=%v", devices, err)
	}
	var rawMAC string
	if err := store.db.QueryRow("SELECT mac_enc FROM desktop_devices WHERE id=?", devices[0].ID).Scan(&rawMAC); err != nil {
		t.Fatal(err)
	}
	if rawMAC == devices[0].MAC || rawMAC == "" {
		t.Fatalf("MAC was not encrypted at rest: %q", rawMAC)
	}

	policy := server.currentDesktopPolicy()
	policy.PublicAPIEnabled = false
	policy.OfficialDesktopOnly = true
	if err := store.SaveDesktopPolicy(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	server.setDesktopPolicy(policy)
	ordinary := httptest.NewRequest(http.MethodGet, "http://gateway/v1/models", nil)
	ordinary.RemoteAddr = "198.51.100.31:1234"
	ordinary.Header.Set("Authorization", "Bearer sk-fg_desktop-user")
	recorder := httptest.NewRecorder()
	server.serveProxy(recorder, ordinary)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("ordinary API key status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	desktop := signedDesktopRequest(t, http.MethodGet, "http://gateway/api/desktop/session", access, privateKey, "policy-check-nonce-with-enough-entropy")
	if _, err := server.desktopSessionRequest(desktop); err != nil {
		t.Fatalf("official desktop session blocked with public API disabled: %v", err)
	}
}

func TestDesktopMACChangeRequiresFreshVerification(t *testing.T) {
	server, store := testApp(t)
	access, privateKey, deviceID, _ := createAuthorizedDesktopSession(t, server, store)
	request := httptest.NewRequest(http.MethodGet, "http://gateway/api/desktop/session", nil)
	request.RemoteAddr = "203.0.113.50:43210"
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "mac-change-nonce-with-enough-entropy"
	request.Header.Set("Authorization", "Bearer "+access)
	request.Header.Set("X-Infinite-Content-SHA256", desktopBodyDigest(nil))
	request.Header.Set("X-Infinite-Device-MAC-Hash", tokenHash("02:42:ac:11:00:ff"))
	request.Header.Set("X-Infinite-Device-Timestamp", timestamp)
	request.Header.Set("X-Infinite-Device-Nonce", nonce)
	request.Header.Set("X-Infinite-Device-Signature", base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(desktopCanonicalRequest(request, timestamp, nonce)))))
	if _, err := server.desktopSessionRequest(request); !errors.Is(err, ErrDesktopSessionInvalid) {
		t.Fatalf("changed MAC retained session access: %v", err)
	}
	var status string
	if err := store.db.QueryRow("SELECT status FROM desktop_devices WHERE id=?", deviceID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "reverify_required" {
		t.Fatalf("device status=%q, want reverify_required", status)
	}
}

func TestDesktopAuthorizationFlowCanOnlyBeConsumedOnce(t *testing.T) {
	server, store := testApp(t)
	access, _, _, _ := createAuthorizedDesktopSession(t, server, store)
	if access == "" {
		t.Fatal("missing access token")
	}
	if _, _, _, err := store.ConsumeApprovedDesktopFlow(context.Background(), "desktop-device-code-with-enough-entropy", server.cfg.DesktopAccessTTL, server.cfg.DesktopRefreshTTL); !errors.Is(err, ErrDesktopFlowExpired) {
		t.Fatalf("authorization flow was reusable: %v", err)
	}
}

func TestManagedDesktopInstructionsPreserveToolJSONForMemoryAndSpillBodies(t *testing.T) {
	for _, padding := range []int{0, requestBodyMemory + 4096} {
		t.Run(strconv.Itoa(padding), func(t *testing.T) {
			toolJSON := `[{"type":"function","name":"shell","parameters":{"type":"object","properties":{"command":{"type":"string"}}}}]`
			body := `{"model":"gpt-5.6","instructions":"client value","tools":` + toolJSON + `,"input":"` + strings.Repeat("x", padding) + `"}`
			request := httptest.NewRequest(http.MethodPost, "http://gateway/v1/responses", strings.NewReader(body))
			replay, _, err := spoolRequestBody(httptest.NewRecorder(), request, int64(len(body)+4096), "后台统一提示词")
			if err != nil {
				t.Fatal(err)
			}
			defer replay.Close()
			rewritten, err := io.ReadAll(replay)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(rewritten), `"tools":`+toolJSON) {
				t.Fatalf("tool JSON bytes changed")
			}
			var decoded struct {
				Instructions string `json:"instructions"`
			}
			if err := json.Unmarshal(rewritten, &decoded); err != nil {
				t.Fatalf("rewritten request is invalid JSON: %v", err)
			}
			if decoded.Instructions != "后台统一提示词" {
				t.Fatalf("managed instructions were not authoritative: %q", decoded.Instructions)
			}
		})
	}
}

func TestDesktopDeviceRevocationCancelsAndDrainsInflightRequest(t *testing.T) {
	server, store := testApp(t)
	access, privateKey, _, deviceID := createAuthorizedDesktopSession(t, server, store)
	request := signedDesktopRequest(t, http.MethodGet, "http://gateway/v1/models", access, privateKey, "desktop-inflight-nonce-with-enough-entropy")
	auth, key, err := server.desktopProvisionedKey(request)
	if err != nil {
		t.Fatal(err)
	}
	request = request.WithContext(context.WithValue(request.Context(), desktopProxyContextKey{}, true))
	request = request.WithContext(context.WithValue(request.Context(), desktopSessionContextKey{}, *auth))
	admitted, finish, err := server.beginDesktopMetadataRequest(request, key.ID, "203.0.113.50")
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		cancelled int
		err       error
	}
	revoked := make(chan result, 1)
	go func() {
		cancelled, revokeErr := server.revokeDesktopDevice(context.Background(), deviceID, 0)
		revoked <- result{cancelled: cancelled, err: revokeErr}
	}()
	select {
	case outcome := <-revoked:
		t.Fatalf("device revoke returned before in-flight request drained: %+v", outcome)
	case <-time.After(100 * time.Millisecond):
	}
	if !errors.Is(context.Cause(admitted.Context()), errDesktopSessionRevoked) {
		t.Fatalf("in-flight request was not cancelled with desktop cause: %v", context.Cause(admitted.Context()))
	}
	finish()
	outcome := <-revoked
	if outcome.err != nil || outcome.cancelled != 1 {
		t.Fatalf("revoke result=%+v", outcome)
	}
}
