package app

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testApp(t *testing.T) (*Server, *Store) {
	t.Helper()
	key := bytes.Repeat([]byte{0x42}, 32)
	vault, err := NewVault(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		DatabasePath:  filepath.Join(t.TempDir(), "friend gate.db"),
		AdminUsername: "admin", AdminPassword: "correct-horse-battery-staple",
		MasterKey: key, BanThreshold: 3, BanWindow: time.Minute, BanDuration: time.Hour,
		MaxBodyBytes: 4 << 20, RevealTTL: time.Minute, StickyTTL: time.Hour, AccountCooldown: 5 * time.Minute,
		UpstreamBaseURL: "https://chatgpt.invalid/backend-api/codex",
	}
	store, err := OpenStore(cfg, vault)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return NewServer(cfg, store, vault), store
}

func createTestAccountAndKey(t *testing.T, store *Store, role, plainKey, ip string) (int64, *APIKey) {
	t.Helper()
	accountID, err := store.CreateAccount(context.Background(), Account{Name: "account", AccessToken: "access-secret", RefreshToken: "refresh-secret", ChatGPTAccountID: "acct-1", ClientID: "client", MaxConcurrency: 4, ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	token := "invite-token-that-is-long-" + role
	if _, err = store.CreateInvitation(context.Background(), role, token, "123456", accountID, 2, time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	claim := "claim-session-that-is-long-" + role
	if _, err = store.VerifyInvitation(context.Background(), token, "123456", ip, claim, "probe-token-that-is-long-"+role); err != nil {
		t.Fatal(err)
	}
	if err = store.SaveInviteDevice(context.Background(), token, claim, ip, "test device"); err != nil {
		t.Fatal(err)
	}
	key, _, err := store.GenerateInvitedKey(context.Background(), token, claim, ip, plainKey, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return accountID, key
}

func createTestAccount(t *testing.T, store *Store, name, accessToken, chatGPTAccountID string) int64 {
	t.Helper()
	id, err := store.CreateAccount(context.Background(), Account{Name: name, AccessToken: accessToken, RefreshToken: "refresh-" + name, ChatGPTAccountID: chatGPTAccountID, ClientID: "client", MaxConcurrency: 4, ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestVaultAndPasswordHash(t *testing.T) {
	vault, _ := NewVault(bytes.Repeat([]byte{1}, 32))
	encrypted, err := vault.Encrypt("secret", "purpose")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := vault.Decrypt(encrypted, "purpose")
	if err != nil || plain != "secret" {
		t.Fatalf("decrypt=%q err=%v", plain, err)
	}
	if _, err = vault.Decrypt(encrypted, "other"); err == nil {
		t.Fatal("AAD mismatch must fail")
	}
	hash, err := passwordHash("six-characters", 10_000)
	if err != nil {
		t.Fatal(err)
	}
	if !passwordVerify(hash, "six-characters") || passwordVerify(hash, "wrong-password") {
		t.Fatal("password verification mismatch")
	}
}

func TestParseAuthJSONCodexShape(t *testing.T) {
	claims := map[string]any{"exp": float64(2_000_000_000), "https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "acct-from-jwt"}}
	payload, _ := json.Marshal(claims)
	jwt := "x." + base64.RawURLEncoding.EncodeToString(payload) + ".x"
	raw := json.RawMessage(`{"tokens":{"access_token":"` + jwt + `","refresh_token":"refresh","account_id":"acct-from-jwt"}}`)
	account, err := parseAuthJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if account.ChatGPTAccountID != "acct-from-jwt" || account.RefreshToken != "refresh" || account.ExpiresAt != 2_000_000_000 {
		t.Fatalf("unexpected account: %+v", account)
	}
}

func TestEarlyLiteDatabaseMigratesToAccountPool(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "early.db")
	db, err := sql.Open("sqlite", "file:"+databasePath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE accounts (
id INTEGER PRIMARY KEY AUTOINCREMENT,
name TEXT NOT NULL,
access_token_enc TEXT NOT NULL,
refresh_token_enc TEXT NOT NULL DEFAULT '',
chatgpt_account_id TEXT NOT NULL,
client_id TEXT NOT NULL DEFAULT 'client',
active INTEGER NOT NULL DEFAULT 1,
max_concurrency INTEGER NOT NULL DEFAULT 4,
expires_at INTEGER NOT NULL DEFAULT 0,
last_used_at INTEGER NOT NULL DEFAULT 0,
last_error TEXT NOT NULL DEFAULT '',
created_at INTEGER NOT NULL,
updated_at INTEGER NOT NULL
)`)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	vault, err := NewVault(bytes.Repeat([]byte{0x52}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{DatabasePath: databasePath, AdminUsername: "admin", AdminPassword: "correct-horse-battery-staple"}
	store, err := OpenStore(cfg, vault)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	createTestAccount(t, store, "migrated", "access", "acct-migrated")
	accounts, err := store.ListAccounts(context.Background())
	if err != nil || len(accounts) != 1 || accounts[0].CooldownUntil != 0 {
		t.Fatalf("migrated accounts=%+v err=%v", accounts, err)
	}
	var affinityTable string
	if err := store.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='session_affinities'`).Scan(&affinityTable); err != nil || affinityTable == "" {
		t.Fatalf("affinity table=%q err=%v", affinityTable, err)
	}
}

func TestLegacyBanScopeMigrationPreservesManualAndAutomaticSemantics(t *testing.T) {
	_, store := testApp(t)
	ctx := context.Background()
	now := time.Now().Unix()
	manualIP := "198.51.100.240"
	automaticIP := "198.51.100.241"
	unknownIP := "198.51.100.242"
	if _, err := store.db.ExecContext(ctx, `INSERT INTO banned_ips(ip,reason,attempts,created_at,expires_at,ban_group,scope)
VALUES(?,?,?,?,?,?,?)`, manualIP, "legacy manual ban", 0, now, 0, "legacy-manual", "public"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO security_events(ip,kind,path,detail,created_at)
VALUES(?,?,?,?,?)`, manualIP, "manual_ban", "", "legacy manual ban", now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO banned_ips(ip,reason,attempts,created_at,expires_at,ban_group,scope)
VALUES(?,?,?,?,?,?,?)`, automaticIP, "HTTP 404 exceeded threshold", 12, now, now+3600, "legacy-automatic", "all"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO banned_ips(ip,reason,attempts,created_at,expires_at,ban_group)
VALUES(?,?,?,?,?,?)`, unknownIP, "unknown legacy source", 0, now, 0, "legacy-unknown"); err != nil {
		t.Fatal(err)
	}
	if err := store.migrate(ctx); err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]string{manualIP: "all", automaticIP: "public", unknownIP: "all"} {
		var got string
		if err := store.db.QueryRowContext(ctx, "SELECT scope FROM banned_ips WHERE ip=?", ip).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("ban %s scope=%q want=%q", ip, got, want)
		}
	}
}

func TestStoreInvitationIPQuotaAndEncryptedCopy(t *testing.T) {
	_, store := testApp(t)
	_, key := createTestAccountAndKey(t, store, "friend", "sk-fg_test-secret", "203.0.113.8")
	authorized, err := store.AuthorizeKey(context.Background(), "sk-fg_test-secret", "203.0.113.8")
	if err != nil || authorized.ID != key.ID {
		t.Fatalf("authorize: %v", err)
	}
	if _, err = store.AuthorizeKey(context.Background(), "sk-fg_test-secret", "203.0.113.9"); err != ErrIPNotAllowed {
		t.Fatalf("wrong IP error=%v", err)
	}
	if err = store.ConsumeQuota(context.Background(), key.ID); err != nil {
		t.Fatal(err)
	}
	if err = store.ConsumeQuota(context.Background(), key.ID); err != nil {
		t.Fatal(err)
	}
	if err = store.ConsumeQuota(context.Background(), key.ID); err != ErrQuotaExceeded {
		t.Fatalf("quota error=%v", err)
	}
	copied, err := store.CopyAPIKey(context.Background(), key.ID)
	if err != nil || copied != "sk-fg_test-secret" {
		t.Fatalf("copy=%q err=%v", copied, err)
	}
	keys, err := store.ListAPIKeys(context.Background())
	if err != nil || len(keys) != 1 || len(keys[0].AllowedIPs) != 1 {
		t.Fatalf("list keys=%+v err=%v", keys, err)
	}
}

func TestDeleteTerminalInvitationPreservesGeneratedKey(t *testing.T) {
	_, store := testApp(t)
	_, key := createTestAccountAndKey(t, store, "delete-invite", "sk-fg_delete-preserves-key", "203.0.113.88")
	items, err := store.ListInvitations(context.Background())
	if err != nil || len(items) != 1 || items[0].Status != "claimed" {
		t.Fatalf("invitations=%+v err=%v", items, err)
	}
	if err := store.DeleteInvitation(context.Background(), items[0].ID); err != nil {
		t.Fatal(err)
	}
	if copied, err := store.CopyAPIKey(context.Background(), key.ID); err != nil || copied != "sk-fg_delete-preserves-key" {
		t.Fatalf("copied=%q err=%v", copied, err)
	}
	if _, err := store.AuthorizeKey(context.Background(), "sk-fg_delete-preserves-key", "203.0.113.88"); err != nil {
		t.Fatalf("generated key stopped working after invitation deletion: %v", err)
	}
}

func TestDeleteInvitationRequiresTerminalState(t *testing.T) {
	_, store := testApp(t)
	accountID := createTestAccount(t, store, "pending-delete", "access-pending", "acct-pending")
	id, err := store.CreateInvitation(context.Background(), "pending", "pending-delete-token-long-enough", "123456", accountID, 0, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteInvitation(context.Background(), id); err != ErrNotFound {
		t.Fatalf("pending delete error=%v", err)
	}
	if err := store.RevokeInvitation(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteInvitation(context.Background(), id); err != nil {
		t.Fatal(err)
	}
}

func TestDashboardUsesRecordedUsage(t *testing.T) {
	_, store := testApp(t)
	accountID, key := createTestAccountAndKey(t, store, "dashboard", "sk-fg_dashboard", "203.0.113.89")
	for _, item := range []UsageLog{
		{IP: "203.0.113.89", Method: "POST", Path: "/v1/responses", Model: "gpt-5.6-codex", Status: 200, TotalTokens: 120},
		{IP: "203.0.113.89", Method: "POST", Path: "/v1/responses", Model: "gpt-5.6-codex", Status: 500, TotalTokens: 30},
		{IP: "203.0.113.89", Method: "POST", Path: "/v1/responses", Model: "gpt-5.5", Status: 200, TotalTokens: 50},
	} {
		if err := store.LogUsage(context.Background(), key.ID, accountID, item); err != nil {
			t.Fatal(err)
		}
	}
	dashboard, err := store.Dashboard(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if dashboard["requests_today"] != int64(3) || dashboard["tokens_today"] != int64(200) || dashboard["errors_today"] != int64(1) || dashboard["calls_total"] != int64(3) {
		t.Fatalf("dashboard=%+v", dashboard)
	}
	ranking, ok := dashboard["model_ranking"].([]ModelUsageRank)
	if !ok || len(ranking) != 2 || ranking[0].Model != "gpt-5.6-codex" || ranking[0].Calls != 2 || ranking[0].TotalTokens != 150 {
		t.Fatalf("ranking=%+v", dashboard["model_ranking"])
	}
}

func TestAccountPoolStickyAffinityAndDistribution(t *testing.T) {
	_, store := testApp(t)
	firstID, key := createTestAccountAndKey(t, store, "friend", "sk-fg_pool", "203.0.113.18")
	secondID := createTestAccount(t, store, "account-2", "access-2", "acct-2")

	firstSession, err := store.SelectAccount(context.Background(), key.ID, tokenHash("session-a"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sameSession, err := store.SelectAccount(context.Background(), key.ID, tokenHash("session-a"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	secondSession, err := store.SelectAccount(context.Background(), key.ID, tokenHash("session-b"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if firstSession.ID != firstID || sameSession.ID != firstSession.ID || secondSession.ID != secondID {
		t.Fatalf("pool routing first=%d same=%d second=%d; want %d,%d,%d", firstSession.ID, sameSession.ID, secondSession.ID, firstID, firstID, secondID)
	}
}

func TestAccountPoolCooldownOnlyMovesNewSessions(t *testing.T) {
	_, store := testApp(t)
	firstID, key := createTestAccountAndKey(t, store, "friend", "sk-fg_cooldown", "203.0.113.19")
	secondID := createTestAccount(t, store, "account-2", "access-2", "acct-2")

	bound, err := store.SelectAccount(context.Background(), key.ID, tokenHash("existing"), time.Hour)
	if err != nil || bound.ID != firstID {
		t.Fatalf("initial selection=%+v err=%v", bound, err)
	}
	store.MarkAccountCooldown(context.Background(), firstID, time.Now().Add(time.Hour).Unix(), "upstream status 429")
	stillBound, err := store.SelectAccount(context.Background(), key.ID, tokenHash("existing"), time.Hour)
	if err != nil || stillBound.ID != firstID {
		t.Fatalf("existing session moved=%+v err=%v", stillBound, err)
	}
	newSession, err := store.SelectAccount(context.Background(), key.ID, tokenHash("new"), time.Hour)
	if err != nil || newSession.ID != secondID {
		t.Fatalf("new session selection=%+v err=%v", newSession, err)
	}
}

func TestConcurrentFirstRequestsShareOneAffinity(t *testing.T) {
	_, store := testApp(t)
	_, key := createTestAccountAndKey(t, store, "friend", "sk-fg_concurrent", "203.0.113.20")
	createTestAccount(t, store, "account-2", "access-2", "acct-2")

	const workers = 12
	ids := make(chan int64, workers)
	errs := make(chan error, workers)
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		go func() {
			<-start
			account, err := store.SelectAccount(context.Background(), key.ID, tokenHash("one-session"), time.Hour)
			if err != nil {
				errs <- err
				return
			}
			ids <- account.ID
		}()
	}
	close(start)
	var selected int64
	for i := 0; i < workers; i++ {
		select {
		case err := <-errs:
			t.Fatal(err)
		case id := <-ids:
			if selected == 0 {
				selected = id
			} else if selected != id {
				t.Fatalf("same session selected multiple accounts: %d and %d", selected, id)
			}
		}
	}
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM session_affinities WHERE key_id=?`, key.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("affinity rows=%d err=%v", count, err)
	}
}

func TestAdminSessionBindsIPAndAutoBan(t *testing.T) {
	server, store := testApp(t)
	token, _, err := store.NewAdminSession(context.Background(), "203.0.113.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.AdminSession(context.Background(), token, "203.0.113.1"); !ok {
		t.Fatal("session should be valid")
	}
	if _, ok := store.AdminSession(context.Background(), token, "203.0.113.2"); ok {
		t.Fatal("session must bind IP")
	}
	for i := 0; i < 3; i++ {
		_, err = store.RecordUnauthorized(context.Background(), "198.51.100.7", "invalid_key", "/v1/responses", "", server.cfg.BanThreshold, server.cfg.BanWindow, server.cfg.BanDuration)
		if err != nil {
			t.Fatal(err)
		}
	}
	if banned, err := store.IsBanned(context.Background(), "198.51.100.7"); err != nil || !banned {
		t.Fatalf("banned=%v err=%v", banned, err)
	}
}

func TestTopLevelJSONAndCodexIdentity(t *testing.T) {
	body := []byte(`{"model":"gpt-5.6-codex","input":[{"text":"prompt_cache_key fake"}],"prompt_cache_key":"cache-1","tail":`)
	if got := topLevelJSONString(body, "model"); got != "gpt-5.6-codex" {
		t.Fatalf("model=%q", got)
	}
	if got := topLevelJSONString(body, "prompt_cache_key"); got != "cache-1" {
		t.Fatalf("cache=%q", got)
	}
	origin, ua, ok := pairCodexIdentity("codex-tui/0.144.1 (Linux; x86_64)")
	if !ok || origin != "codex-tui" || !strings.HasPrefix(ua, "codex-tui/") {
		t.Fatalf("identity %q %q %v", origin, ua, ok)
	}
}

func TestCodexVersionComparison(t *testing.T) {
	if !codexVersionAtLeast("0.144.0", "0.144.0") || !codexVersionAtLeast("1.0.0", "0.144.0") || codexVersionAtLeast("0.143.9", "0.144.0") || codexVersionAtLeast("bad", "0.144.0") {
		t.Fatal("unexpected Codex version comparison")
	}
}

func TestModelsHeadersMatchCodexManifestProtocol(t *testing.T) {
	server, _ := testApp(t)
	request := httptest.NewRequest(http.MethodGet, "http://gateway/v1/models?client_version=0.200.1", nil)
	request.Header.Set("Session_ID", "must-not-leak")
	target, _ := url.Parse("https://chatgpt.com/backend-api/codex/models")
	server.prepareUpstreamRequest(request, target, &APIKey{ID: 7}, &Account{AccessToken: "token", ChatGPTAccountID: "acct"}, "/models", "", "")
	if request.Header.Get("Accept") != "application/json" || request.Header.Get("Version") != "0.200.1" || request.Header.Get("OpenAI-Beta") != "" || request.Header.Get("Session_ID") != "" {
		t.Fatalf("unexpected model headers: %#v", request.Header)
	}
}

func TestProxyBodySSEAndSessionIsolation(t *testing.T) {
	server, store := testApp(t)
	ip := "203.0.113.44"
	accountID, key1 := createTestAccountAndKey(t, store, "one", "sk-fg_key-one", ip)
	installOfficialManifest(t, store, accountID, `{"models":[{"slug":"gpt-5.6-codex"}]}`)
	// Add a second invited key on the same upstream account to prove that the
	// exact same downstream session value receives a different upstream value.
	token := "invite-token-that-is-long-two"
	if _, err := store.CreateInvitation(context.Background(), "two", token, "654321", accountID, 0, time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	claim := "claim-session-that-is-long-two"
	if _, err := store.VerifyInvitation(context.Background(), token, "654321", ip, claim, "probe-token-that-is-long-two"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveInviteDevice(context.Background(), token, claim, ip, "device two"); err != nil {
		t.Fatal(err)
	}
	key2, _, err := store.GenerateInvitedKey(context.Background(), token, claim, ip, "sk-fg_key-two", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	type seen struct{ body, session, auth, account string }
	seenCh := make(chan seen, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenCh <- seen{string(body), r.Header.Get("Session_ID"), r.Header.Get("Authorization"), r.Header.Get("ChatGPT-Account-ID")}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":3,\"output_tokens\":4,\"total_tokens\":7}}}\n\n")
	}))
	defer upstream.Close()
	server.cfg.UpstreamBaseURL = upstream.URL
	body := `{"model":"gpt-5.6-codex","tools":[{"type":"function","name":"shell","parameters":{"type":"object"}}],"prompt_cache_key":"same-cache","input":"unchanged"}`
	call := func(key string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "http://gateway/v1/responses", strings.NewReader(body))
		request.RemoteAddr = ip + ":32100"
		request.Header.Set("Authorization", "Bearer "+key)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Session_ID", "same-session")
		recorder := httptest.NewRecorder()
		server.proxyHandler().ServeHTTP(recorder, request)
		return recorder
	}
	r1 := call("sk-fg_key-one")
	r2 := call("sk-fg_key-two")
	if r1.Code != 200 || r2.Code != 200 {
		t.Fatalf("statuses %d %d: %s / %s", r1.Code, r2.Code, r1.Body.String(), r2.Body.String())
	}
	first, second := <-seenCh, <-seenCh
	if first.body != body || second.body != body {
		t.Fatal("tool/request JSON was modified")
	}
	if first.session == "" || second.session == "" || first.session == second.session {
		t.Fatalf("sessions not isolated: %q %q (keys %d %d)", first.session, second.session, key1.ID, key2.ID)
	}
	for _, item := range []seen{first, second} {
		if item.auth != "Bearer access-secret" || item.account != "acct-1" {
			t.Fatalf("bad upstream auth headers: %+v", item)
		}
	}
	if r1.Body.String() != "data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":3,\"output_tokens\":4,\"total_tokens\":7}}}\n\n" {
		t.Fatal("SSE response was modified")
	}
}

func TestProxyPool429KeepsExistingSessionAndMovesNewSession(t *testing.T) {
	server, store := testApp(t)
	ip := "203.0.113.45"
	firstID, key := createTestAccountAndKey(t, store, "pool", "sk-fg_pool-e2e", ip)
	secondID := createTestAccount(t, store, "account-2", "access-2", "acct-2")
	installOfficialManifest(t, store, firstID, `{"models":[{"slug":"gpt-5.6-codex"}]}`)
	installOfficialManifest(t, store, secondID, `{"models":[{"slug":"gpt-5.6-codex"}]}`)
	if err := store.UpdateAPIKey(context.Background(), key.ID, "active", 0); err != nil {
		t.Fatal(err)
	}

	var seen []string
	var seenMu sync.Mutex
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		seenMu.Lock()
		seen = append(seen, auth)
		seenMu.Unlock()
		if auth == "Bearer access-secret" {
			w.Header().Set("Retry-After", "600")
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "official quota"})
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\"}\n\n")
	}))
	defer upstream.Close()
	server.cfg.UpstreamBaseURL = upstream.URL

	call := func(session string) int {
		body := `{"model":"gpt-5.6-codex","prompt_cache_key":"` + session + `","input":"unchanged"}`
		request := httptest.NewRequest(http.MethodPost, "http://gateway/v1/responses", strings.NewReader(body))
		request.RemoteAddr = ip + ":32101"
		request.Header.Set("Authorization", "Bearer sk-fg_pool-e2e")
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		server.proxyHandler().ServeHTTP(recorder, request)
		return recorder.Code
	}
	if got := call("existing"); got != http.StatusTooManyRequests {
		t.Fatalf("first status=%d", got)
	}
	if got := call("existing"); got != http.StatusTooManyRequests {
		t.Fatalf("sticky retry status=%d", got)
	}
	if got := call("new-session"); got != http.StatusOK {
		t.Fatalf("new session status=%d", got)
	}
	seenMu.Lock()
	gotSeen := append([]string(nil), seen...)
	seenMu.Unlock()
	wantSeen := []string{"Bearer access-secret", "Bearer access-secret", "Bearer access-2"}
	if len(gotSeen) != len(wantSeen) {
		t.Fatalf("upstream requests=%v", gotSeen)
	}
	for i := range wantSeen {
		if gotSeen[i] != wantSeen[i] {
			t.Fatalf("upstream routing=%v want=%v", gotSeen, wantSeen)
		}
	}
	first, err := store.GetAccount(context.Background(), firstID)
	if err != nil || first.CooldownUntil <= time.Now().Unix() {
		t.Fatalf("first account cooldown=%+v err=%v", first, err)
	}
	second, err := store.GetAccount(context.Background(), secondID)
	if err != nil || second.CooldownUntil != 0 {
		t.Fatalf("second account cooldown=%+v err=%v", second, err)
	}
}

func TestCodexSuffixRejectsTraversal(t *testing.T) {
	valid := []string{"/v1/responses", "/v1/responses/compact", "/backend-api/codex/models", "/responses", "/models", "/alpha/search"}
	for _, path := range valid {
		if _, ok := codexSuffix(path); !ok {
			t.Fatalf("valid path rejected: %s", path)
		}
	}
	invalid := []string{"/", "/v1", "/v1/../accounts", "/backend-api/accounts", "/v1\\responses"}
	for _, path := range invalid {
		if _, ok := codexSuffix(path); ok {
			t.Fatalf("invalid path accepted: %s", path)
		}
	}
}
