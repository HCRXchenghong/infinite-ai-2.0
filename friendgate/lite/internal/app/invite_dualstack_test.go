package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestInvitationDualStackWhitelistBanAndUnban(t *testing.T) {
	server, store := testApp(t)
	createTestAccount(t, store, "dual-account", "access", "acct-dual")
	token := "dual-stack-invitation-token-long-enough"
	claim := "dual-stack-claim-session-long-enough"
	probe := "dual-stack-probe-token-long-enough"
	ipv4 := "198.51.100.40"
	ipv6 := "2001:db8::40"
	if _, err := store.CreateInvitation(context.Background(), "dual friend", token, "123456", 0, 0, time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyInvitation(context.Background(), token, "123456", ipv4, claim, probe); err != nil {
		t.Fatal(err)
	}
	ips, err := store.RecordInvitationProbe(context.Background(), token, probe, ipv6)
	if err != nil || len(ips) != 2 {
		t.Fatalf("probe ips=%+v err=%v", ips, err)
	}
	if err := store.SaveInviteDevice(context.Background(), token, claim, ipv6, "dual-stack workstation"); err != nil {
		t.Fatal(err)
	}
	key, _, err := store.GenerateInvitedKey(context.Background(), token, claim, ipv6, "sk-fg_dual-stack", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{ipv4, ipv6} {
		if authorized, err := store.AuthorizeKey(context.Background(), "sk-fg_dual-stack", ip); err != nil || authorized.ID != key.ID {
			t.Fatalf("authorize %s: key=%+v err=%v", ip, authorized, err)
		}
	}
	keys, err := store.ListAPIKeys(context.Background())
	if err != nil || len(keys) != 1 || len(keys[0].AllowedIPs) != 2 || keys[0].AllowedIPs[0].DeviceGroup != keys[0].AllowedIPs[1].DeviceGroup {
		t.Fatalf("key ips=%+v err=%v", keys, err)
	}
	for index := 0; index < server.cfg.BanThreshold; index++ {
		if _, err := store.RecordUnauthorized(context.Background(), ipv4, "invalid_key", "/v1/responses", "test", server.cfg.BanThreshold, server.cfg.BanWindow, server.cfg.BanDuration); err != nil {
			t.Fatal(err)
		}
	}
	for _, ip := range []string{ipv4, ipv6} {
		if banned, err := store.IsBanned(context.Background(), ip); err != nil || !banned {
			t.Fatalf("paired IP %s banned=%v err=%v", ip, banned, err)
		}
	}
	// Destroy the original ACL relationship before unbanning. Durable
	// ban-group membership must still remove both addresses.
	if err := store.DeleteAPIKey(context.Background(), key.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.Unban(context.Background(), ipv6); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{ipv4, ipv6} {
		if banned, err := store.IsBanned(context.Background(), ip); err != nil || banned {
			t.Fatalf("paired IP %s banned after unban=%v err=%v", ip, banned, err)
		}
	}
}

func TestInvitationPageBecomesHTTPGoneAfterClaimWindow(t *testing.T) {
	server, store := testApp(t)
	server.cfg.PublicIPv4ProbeURL = "https://invite4.example.com"
	server.cfg.PublicIPv6ProbeURL = "https://invite6.example.com"
	createTestAccount(t, store, "invite-account", "access", "acct-invite")
	token := "one-time-invitation-token-long-enough"
	claim := "one-time-claim-session-long-enough"
	ip := "203.0.113.70"
	if _, err := store.CreateInvitation(context.Background(), "one-time friend", token, "123456", 0, 0, time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyInvitation(context.Background(), token, "123456", ip, claim, "one-time-probe-token-long-enough"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveInviteDevice(context.Background(), token, claim, ip, "one-time device"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.GenerateInvitedKey(context.Background(), token, claim, ip, "sk-fg_one-time", time.Minute); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "http://invite.local/?invite="+token, nil)
	request.RemoteAddr = ip + ":31000"
	request.AddCookie(&http.Cookie{Name: claimCookieName, Value: claim})
	recorder := httptest.NewRecorder()
	server.inviteHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Header().Get("Content-Security-Policy"), "https://invite4.example.com https://invite6.example.com") {
		t.Fatalf("active invite status=%d csp=%q", recorder.Code, recorder.Header().Get("Content-Security-Policy"))
	}

	if _, err := store.db.Exec(`UPDATE invitations SET reveal_until=? WHERE token_hash=?`, time.Now().Add(-time.Second).Unix(), tokenHash(token)); err != nil {
		t.Fatal(err)
	}
	expiredRequest := httptest.NewRequest(http.MethodGet, "http://invite.local/?invite="+token, nil)
	expiredRequest.RemoteAddr = ip + ":31000"
	expiredRequest.AddCookie(&http.Cookie{Name: claimCookieName, Value: claim})
	expiredRecorder := httptest.NewRecorder()
	server.inviteHandler().ServeHTTP(expiredRecorder, expiredRequest)
	if expiredRecorder.Code != http.StatusGone || !strings.Contains(expiredRecorder.Body.String(), "invite_expired") {
		t.Fatalf("expired invite status=%d body=%s", expiredRecorder.Code, expiredRecorder.Body.String())
	}

	outsiderRequest := httptest.NewRequest(http.MethodGet, "http://invite.local/?invite="+token, nil)
	outsiderRequest.RemoteAddr = "203.0.113.71:31000"
	outsiderRecorder := httptest.NewRecorder()
	server.inviteHandler().ServeHTTP(outsiderRecorder, outsiderRequest)
	if outsiderRecorder.Code != http.StatusGone {
		t.Fatalf("outsider status=%d", outsiderRecorder.Code)
	}
}

func TestInvitationProbeCORSAndOneTimeToken(t *testing.T) {
	server, store := testApp(t)
	server.cfg.PublicInviteURL = "https://invite.example.com"
	token := "cors-invitation-token-long-enough"
	claim := "cors-claim-session-long-enough"
	probe := "cors-probe-token-long-enough"
	if _, err := store.CreateInvitation(context.Background(), "cors friend", token, "123456", 0, 0, time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyInvitation(context.Background(), token, "123456", "198.51.100.80", claim, probe); err != nil {
		t.Fatal(err)
	}

	badRequest := httptest.NewRequest(http.MethodPost, "/api/invitations/"+token+"/probe", strings.NewReader(`{"probe_token":"`+probe+`"}`))
	badRequest.Header.Set("Origin", "https://evil.example")
	badRequest.Header.Set("Content-Type", "application/json")
	badRecorder := httptest.NewRecorder()
	server.inviteHandler().ServeHTTP(badRecorder, badRequest)
	if badRecorder.Code != http.StatusForbidden {
		t.Fatalf("bad origin status=%d", badRecorder.Code)
	}

	goodRequest := httptest.NewRequest(http.MethodPost, "/api/invitations/"+token+"/probe", strings.NewReader(`{"probe_token":"`+probe+`"}`))
	goodRequest.RemoteAddr = "[2001:db8::80]:32000"
	goodRequest.Header.Set("Origin", "https://invite.example.com")
	goodRequest.Header.Set("Content-Type", "application/json")
	goodRecorder := httptest.NewRecorder()
	server.inviteHandler().ServeHTTP(goodRecorder, goodRequest)
	if goodRecorder.Code != http.StatusOK || goodRecorder.Header().Get("Access-Control-Allow-Origin") != "https://invite.example.com" {
		t.Fatalf("good probe status=%d body=%s", goodRecorder.Code, goodRecorder.Body.String())
	}
	if err := store.SaveInviteDevice(context.Background(), token, claim, "2001:db8::80", "cors device"); err != nil {
		t.Fatal(err)
	}
	createTestAccount(t, store, "cors-account", "access", "acct-cors")
	if _, _, err := store.GenerateInvitedKey(context.Background(), token, claim, "2001:db8::80", "sk-fg_cors", time.Minute); err != nil {
		t.Fatal(err)
	}
	againRequest := httptest.NewRequest(http.MethodPost, "/api/invitations/"+token+"/probe", strings.NewReader(`{"probe_token":"`+probe+`"}`))
	againRequest.RemoteAddr = "[2001:db8::81]:32000"
	againRequest.Header.Set("Origin", "https://invite.example.com")
	againRequest.Header.Set("Content-Type", "application/json")
	againRecorder := httptest.NewRecorder()
	server.inviteHandler().ServeHTTP(againRecorder, againRequest)
	if againRecorder.Code != http.StatusGone {
		t.Fatalf("claimed probe status=%d", againRecorder.Code)
	}
}

func TestTerminalInvitationsReturnGoneForEveryPublicAction(t *testing.T) {
	server, store := testApp(t)
	server.cfg.PublicInviteURL = "https://invite.example.com"
	now := time.Now()

	tests := []struct {
		name       string
		token      string
		ip         string
		wantStatus string
		expiresAt  int64
		finish     func(int64) error
	}{
		{
			name: "revoked", token: "terminal-revoked-invitation-token", ip: "203.0.113.91", wantStatus: "revoked", expiresAt: now.Add(time.Hour).Unix(),
			finish: func(id int64) error { return store.RevokeInvitation(context.Background(), id) },
		},
		{
			name: "expired", token: "terminal-expired-invitation-token", ip: "203.0.113.92", wantStatus: "expired", expiresAt: now.Add(-time.Minute).Unix(),
			finish: func(int64) error { return nil },
		},
		{
			name: "deleted", token: "terminal-deleted-invitation-token", ip: "203.0.113.93", wantStatus: "", expiresAt: now.Add(time.Hour).Unix(),
			finish: func(id int64) error {
				if err := store.RevokeInvitation(context.Background(), id); err != nil {
					return err
				}
				return store.DeleteInvitation(context.Background(), id)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			id, err := store.CreateInvitation(context.Background(), test.name, test.token, "123456", 0, 0, test.expiresAt)
			if err != nil {
				t.Fatal(err)
			}
			if err := test.finish(id); err != nil {
				t.Fatal(err)
			}

			requests := []*http.Request{
				httptest.NewRequest(http.MethodGet, "http://invite.local/?invite="+test.token, nil),
				httptest.NewRequest(http.MethodGet, "http://invite.local/api/invitations/"+test.token, nil),
				httptest.NewRequest(http.MethodPost, "http://invite.local/api/invitations/"+test.token+"/verify", strings.NewReader(`{"code":"123456"}`)),
				httptest.NewRequest(http.MethodOptions, "http://invite.local/api/invitations/"+test.token+"/probe", nil),
				httptest.NewRequest(http.MethodPost, "http://invite.local/api/invitations/"+test.token+"/probe", strings.NewReader(`{"probe_token":"terminal-probe-token"}`)),
				httptest.NewRequest(http.MethodPost, "http://invite.local/api/invitations/"+test.token+"/device", strings.NewReader(`{"device_note":"terminal device"}`)),
				httptest.NewRequest(http.MethodPost, "http://invite.local/api/invitations/"+test.token+"/generate", strings.NewReader(`{}`)),
				httptest.NewRequest(http.MethodGet, "http://invite.local/api/invitations/"+test.token+"/key", nil),
			}
			for _, request := range requests {
				request.RemoteAddr = test.ip + ":33000"
				if request.Method == http.MethodPost {
					request.Header.Set("Content-Type", "application/json")
				}
				if strings.HasSuffix(request.URL.Path, "/probe") {
					request.Header.Set("Origin", "https://invite.example.com")
				}
				recorder := httptest.NewRecorder()
				server.inviteHandler().ServeHTTP(recorder, request)
				if recorder.Code != http.StatusGone || !strings.Contains(recorder.Body.String(), "invite_expired") {
					t.Fatalf("%s %s status=%d body=%s", request.Method, request.URL.Path, recorder.Code, recorder.Body.String())
				}
			}
			var attempts int
			if err := store.db.QueryRow("SELECT attempts FROM ip_failures WHERE ip=?", test.ip).Scan(&attempts); err != nil {
				t.Fatal(err)
			}
			if attempts != len(requests) {
				t.Fatalf("persistent invalid-invitation attempts=%d want=%d", attempts, len(requests))
			}
			if banned, err := store.IsBanned(context.Background(), test.ip); err != nil || !banned {
				t.Fatalf("terminal invitation attacker banned=%v err=%v", banned, err)
			}
			var invitationRows int
			var status string
			if err := store.db.QueryRow("SELECT COUNT(*),COALESCE(MAX(status),'') FROM invitations WHERE token_hash=?", tokenHash(test.token)).Scan(&invitationRows, &status); err != nil {
				t.Fatal(err)
			}
			wantRows := 1
			if test.wantStatus == "" {
				wantRows = 0
			}
			if invitationRows != wantRows || status != test.wantStatus {
				t.Fatalf("terminal state changed by abuse accounting: rows=%d status=%q want_rows=%d want_status=%q", invitationRows, status, wantRows, test.wantStatus)
			}
		})
	}
}

func TestInvalidInvitationTokensTriggerPersistentPublicBan(t *testing.T) {
	server, store := testApp(t)
	ip := "198.51.100.130"
	handler := server.commonHeaders("invite", server.inviteHandler())

	for attempt := 0; attempt < server.cfg.BanThreshold; attempt++ {
		token := fmt.Sprintf("invalid-invitation-token-%02d-long-enough", attempt)
		request := httptest.NewRequest(http.MethodGet, "http://invite.local/api/invitations/"+token, nil)
		request.RemoteAddr = ip + ":36000"
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusGone || !strings.Contains(recorder.Body.String(), "invite_expired") {
			t.Fatalf("attempt=%d status=%d body=%s", attempt+1, recorder.Code, recorder.Body.String())
		}
	}

	var attempts int
	if err := store.db.QueryRow("SELECT attempts FROM ip_failures WHERE ip=?", ip).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != server.cfg.BanThreshold {
		t.Fatalf("persistent attempts=%d want=%d", attempts, server.cfg.BanThreshold)
	}
	if banned, err := store.IsBanned(context.Background(), ip); err != nil || !banned {
		t.Fatalf("public ban persisted=%v err=%v", banned, err)
	}
	if !server.isBannedCached(ip, "invite") || !server.isBannedCached(ip, "api") || server.isBannedCached(ip, "admin") {
		t.Fatalf("unexpected ban scope: invite=%v api=%v admin=%v", server.isBannedCached(ip, "invite"), server.isBannedCached(ip, "api"), server.isBannedCached(ip, "admin"))
	}

	blocked := httptest.NewRequest(http.MethodGet, "http://invite.local/favicon.svg", nil)
	blocked.RemoteAddr = ip + ":36000"
	blockedRecorder := httptest.NewRecorder()
	handler.ServeHTTP(blockedRecorder, blocked)
	if blockedRecorder.Code != http.StatusForbidden || !strings.Contains(blockedRecorder.Body.String(), "ip_banned") {
		t.Fatalf("post-threshold public status=%d body=%s", blockedRecorder.Code, blockedRecorder.Body.String())
	}
	apiRecorder := httptest.NewRecorder()
	apiRequest := httptest.NewRequest(http.MethodPost, "http://api.local/v1/responses", nil)
	apiRequest.RemoteAddr = ip + ":36000"
	server.commonHeaders("api", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(apiRecorder, apiRequest)
	if apiRecorder.Code != http.StatusForbidden || !strings.Contains(apiRecorder.Body.String(), "ip_banned") {
		t.Fatalf("public ban did not cover API surface: status=%d body=%s", apiRecorder.Code, apiRecorder.Body.String())
	}

	adminRecorder := httptest.NewRecorder()
	adminRequest := httptest.NewRequest(http.MethodGet, "http://admin.local/health-check", nil)
	adminRequest.RemoteAddr = ip + ":36000"
	server.commonHeaders("admin", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(adminRecorder, adminRequest)
	if adminRecorder.Code != http.StatusNoContent {
		t.Fatalf("public-only ban blocked admin recovery surface: status=%d body=%s", adminRecorder.Code, adminRecorder.Body.String())
	}
}

func TestInvalidRecognitionCodesTriggerPersistentPublicBanWithoutConsumingInvite(t *testing.T) {
	server, store := testApp(t)
	token := "recognition-code-ban-invitation-token"
	attackerIP := "198.51.100.131"
	legitimateIP := "198.51.100.132"
	if _, err := store.CreateInvitation(context.Background(), "recognition code target", token, "123456", 0, 0, time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	handler := server.commonHeaders("invite", server.inviteHandler())

	for attempt := 0; attempt < server.cfg.BanThreshold; attempt++ {
		request := httptest.NewRequest(http.MethodPost, "http://invite.local/api/invitations/"+token+"/verify", strings.NewReader(`{"code":"000000"}`))
		request.RemoteAddr = attackerIP + ":37000"
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized || !strings.Contains(recorder.Body.String(), "invalid_code") {
			t.Fatalf("attempt=%d status=%d body=%s", attempt+1, recorder.Code, recorder.Body.String())
		}
	}

	var attempts int
	if err := store.db.QueryRow("SELECT attempts FROM ip_failures WHERE ip=?", attackerIP).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != server.cfg.BanThreshold || !server.isBannedCached(attackerIP, "invite") {
		t.Fatalf("attempts=%d cached_ban=%v", attempts, server.isBannedCached(attackerIP, "invite"))
	}

	blocked := httptest.NewRequest(http.MethodGet, "http://invite.local/?invite="+token, nil)
	blocked.RemoteAddr = attackerIP + ":37000"
	blockedRecorder := httptest.NewRecorder()
	handler.ServeHTTP(blockedRecorder, blocked)
	if blockedRecorder.Code != http.StatusForbidden {
		t.Fatalf("attacker remained on public surface: status=%d body=%s", blockedRecorder.Code, blockedRecorder.Body.String())
	}

	legitimate := httptest.NewRequest(http.MethodPost, "http://invite.local/api/invitations/"+token+"/verify", strings.NewReader(`{"code":"123456"}`))
	legitimate.RemoteAddr = legitimateIP + ":37000"
	legitimate.Header.Set("Content-Type", "application/json")
	legitimateRecorder := httptest.NewRecorder()
	handler.ServeHTTP(legitimateRecorder, legitimate)
	if legitimateRecorder.Code != http.StatusOK || !strings.Contains(legitimateRecorder.Body.String(), `"verified":true`) {
		t.Fatalf("legitimate one-time claim status=%d body=%s", legitimateRecorder.Code, legitimateRecorder.Body.String())
	}
	var legitimateFailures int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM ip_failures WHERE ip=?", legitimateIP).Scan(&legitimateFailures); err != nil || legitimateFailures != 0 {
		t.Fatalf("legitimate IP failure rows=%d err=%v", legitimateFailures, err)
	}
}

func TestInvitationFaviconRoutesAreRealAssets(t *testing.T) {
	server, _ := testApp(t)
	handler := server.inviteHandler()
	for _, path := range []string{"/favicon.ico", "/favicon.svg"} {
		request := httptest.NewRequest(http.MethodGet, "http://invite.local"+path, nil)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Header().Get("Content-Type"), "image/svg+xml") {
			t.Fatalf("%s status=%d content-type=%q body=%s", path, recorder.Code, recorder.Header().Get("Content-Type"), recorder.Body.String())
		}
	}
}

func TestInvitationSourceHTMLCannotBypassValidatedEntryPoint(t *testing.T) {
	server, store := testApp(t)
	token := "source-html-bypass-invitation-token"
	if _, err := store.CreateInvitation(context.Background(), "source bypass", token, "123456", 0, 0, time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://invite.local/invite.html?invite="+token, nil)
	recorder := httptest.NewRecorder()
	server.inviteHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusGone || strings.Contains(strings.ToLower(recorder.Body.String()), "<!doctype html>") {
		t.Fatalf("source HTML bypass status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestInvitationFirstVerificationAtomicallyLocksClaimAndIPs(t *testing.T) {
	_, store := testApp(t)
	token := "atomic-first-verification-invitation-token"
	if _, err := store.CreateInvitation(context.Background(), "atomic claim", token, "123456", 0, 0, time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyInvitation(context.Background(), token, "000000", "198.51.100.100", "wrong-code-claim", "wrong-code-probe"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("wrong recognition code error=%v", err)
	}

	type verifyResult struct {
		claim string
		ip    string
		err   error
	}
	start := make(chan struct{})
	results := make(chan verifyResult, 2)
	var workers sync.WaitGroup
	for index, ip := range []string{"198.51.100.101", "198.51.100.102"} {
		index, ip := index, ip
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			claim := "atomic-claim-session-" + string(rune('a'+index))
			_, err := store.VerifyInvitation(context.Background(), token, "123456", ip, claim, "atomic-probe-token-"+string(rune('a'+index)))
			results <- verifyResult{claim: claim, ip: ip, err: err}
		}()
	}
	close(start)
	workers.Wait()
	close(results)

	var winner verifyResult
	successes, rejected := 0, 0
	for result := range results {
		switch {
		case result.err == nil:
			successes++
			winner = result
		case errors.Is(result.err, ErrInvalidInvite):
			rejected++
		default:
			t.Fatalf("unexpected verification error=%v", result.err)
		}
	}
	if successes != 1 || rejected != 1 {
		t.Fatalf("successes=%d rejected=%d", successes, rejected)
	}
	item, err := store.PublicInvitation(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if item.ClaimSessionHash != tokenHash(winner.claim) || len(item.ObservedIPs) != 1 || item.ObservedIPs[0].IP != winner.ip {
		t.Fatalf("locked invitation=%+v winner=%+v", item, winner)
	}
	if _, err := store.VerifyInvitation(context.Background(), token, "123456", "198.51.100.103", "late-claim", "late-probe"); !errors.Is(err, ErrInvalidInvite) {
		t.Fatalf("late claim error=%v", err)
	}
}

func TestInvitationProbeAndRevokeSerialize(t *testing.T) {
	_, store := testApp(t)
	token := "atomic-probe-revoke-invitation-token"
	claim := "atomic-probe-revoke-claim"
	probe := "atomic-probe-revoke-token"
	id, err := store.CreateInvitation(context.Background(), "probe revoke", token, "123456", 0, 0, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyInvitation(context.Background(), token, "123456", "198.51.100.110", claim, probe); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var probeErr, revokeErr error
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		<-start
		_, probeErr = store.RecordInvitationProbe(context.Background(), token, probe, "2001:db8::110")
	}()
	go func() {
		defer workers.Done()
		<-start
		revokeErr = store.RevokeInvitation(context.Background(), id)
	}()
	close(start)
	workers.Wait()
	if revokeErr != nil {
		t.Fatalf("revoke error=%v", revokeErr)
	}
	if probeErr != nil && !errors.Is(probeErr, ErrInvalidInvite) {
		t.Fatalf("probe error=%v", probeErr)
	}
	if _, err := store.RecordInvitationProbe(context.Background(), token, probe, "2001:db8::111"); !errors.Is(err, ErrInvalidInvite) {
		t.Fatalf("post-revoke probe error=%v", err)
	}
}

func TestInvitationPlaintextKeyResponsesAreNeverCacheable(t *testing.T) {
	server, store := testApp(t)
	createTestAccount(t, store, "no-store-account", "access", "acct-no-store")
	token := "plaintext-no-store-invitation-token"
	claim := "plaintext-no-store-claim-token"
	ip := "203.0.113.120"
	if _, err := store.CreateInvitation(context.Background(), "no store", token, "123456", 0, 0, time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyInvitation(context.Background(), token, "123456", ip, claim, "plaintext-no-store-probe"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveInviteDevice(context.Background(), token, claim, ip, "no-store device"); err != nil {
		t.Fatal(err)
	}
	handler := server.inviteHandler()
	generate := httptest.NewRequest(http.MethodPost, "http://invite.local/api/invitations/"+token+"/generate", strings.NewReader(`{}`))
	generate.RemoteAddr = ip + ":34000"
	generate.Header.Set("Content-Type", "application/json")
	generate.AddCookie(&http.Cookie{Name: claimCookieName, Value: claim})
	generated := httptest.NewRecorder()
	handler.ServeHTTP(generated, generate)
	assertInvitationNoStore(t, generated, http.StatusCreated)

	reveal := httptest.NewRequest(http.MethodGet, "http://invite.local/api/invitations/"+token+"/key", nil)
	reveal.RemoteAddr = ip + ":34000"
	reveal.AddCookie(&http.Cookie{Name: claimCookieName, Value: claim})
	revealed := httptest.NewRecorder()
	handler.ServeHTTP(revealed, reveal)
	assertInvitationNoStore(t, revealed, http.StatusOK)
}

func assertInvitationNoStore(t *testing.T, recorder *httptest.ResponseRecorder, wantStatus int) {
	t.Helper()
	if recorder.Code != wantStatus || !strings.Contains(recorder.Header().Get("Cache-Control"), "no-store") || recorder.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("status=%d cache-control=%q pragma=%q body=%s", recorder.Code, recorder.Header().Get("Cache-Control"), recorder.Header().Get("Pragma"), recorder.Body.String())
	}
}
