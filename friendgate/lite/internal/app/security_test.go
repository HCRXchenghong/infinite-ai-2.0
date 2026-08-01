package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAdminSetupHTTPFlowCreatesBoundSessionAndClosesChannel(t *testing.T) {
	server, store := testApp(t)
	server.cfg.SessionTTL = time.Hour
	startBody := []byte(`{"initialization_password":"correct-horse-battery-staple","username":"owner-admin","password":"a-brand-new-admin-password"}`)
	startRequest := httptest.NewRequest(http.MethodPost, "http://admin.local/api/setup/start", bytes.NewReader(startBody))
	startRequest.RemoteAddr = "203.0.113.210:4321"
	startRecorder := httptest.NewRecorder()
	server.adminSetupStart(startRecorder, startRequest)
	if startRecorder.Code != http.StatusOK {
		t.Fatalf("setup start status=%d body=%s", startRecorder.Code, startRecorder.Body.String())
	}
	var started struct {
		SetupToken string `json:"setup_token"`
		Secret     string `json:"secret"`
		QRDataURL  string `json:"qr_data_url"`
	}
	if err := json.Unmarshal(startRecorder.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	if started.SetupToken == "" || started.Secret == "" || len(started.QRDataURL) < 100 {
		t.Fatalf("incomplete setup payload: %+v", started)
	}
	code, ok := totpValue(started.Secret, time.Now().Unix()/30)
	if !ok {
		t.Fatal("failed to calculate setup TOTP")
	}
	completeBody, _ := json.Marshal(map[string]string{"setup_token": started.SetupToken, "code": code})
	completeRequest := httptest.NewRequest(http.MethodPost, "http://admin.local/api/setup/complete", bytes.NewReader(completeBody))
	completeRequest.RemoteAddr = startRequest.RemoteAddr
	completeRecorder := httptest.NewRecorder()
	server.adminSetupComplete(completeRecorder, completeRequest)
	if completeRecorder.Code != http.StatusCreated {
		t.Fatalf("setup complete status=%d body=%s", completeRecorder.Code, completeRecorder.Body.String())
	}
	required, err := store.AdminSetupRequired(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if required {
		t.Fatal("setup channel remained open")
	}
	cookies := completeRecorder.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != adminCookieName || cookies[0].Value == "" {
		t.Fatalf("setup did not create admin session: %+v", cookies)
	}
	secondRecorder := httptest.NewRecorder()
	server.adminSetupStart(secondRecorder, startRequest.Clone(context.Background()))
	if secondRecorder.Code != http.StatusGone {
		t.Fatalf("closed setup channel status=%d", secondRecorder.Code)
	}
}

func TestLegacyAdminSessionCannotBypassRequiredTOTPSetup(t *testing.T) {
	server, store := testApp(t)
	server.cfg.SessionTTL = time.Hour
	token, _, err := store.NewAdminSession(context.Background(), "203.0.113.211", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://admin.local/api/me", nil)
	request.RemoteAddr = "203.0.113.211:4321"
	request.AddCookie(&http.Cookie{Name: adminCookieName, Value: token})
	recorder := httptest.NewRecorder()
	server.adminMe(recorder, request)
	var response struct {
		Authenticated bool `json:"authenticated"`
		SetupRequired bool `json:"setup_required"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Authenticated || !response.SetupRequired {
		t.Fatalf("legacy session bypassed setup: %+v", response)
	}
}

func TestAdminTOTPSetupAuthenticationAndReplayProtection(t *testing.T) {
	_, store := testApp(t)
	required, err := store.AdminSetupRequired(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !required {
		t.Fatal("new database must require one-time administrator setup")
	}
	secret := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	encrypted, err := store.vault.Encrypt(secret, "admin-totp")
	if err != nil {
		t.Fatal(err)
	}
	hash, err := passwordHash("a-new-strong-password", 10_000)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteAdminSetup(context.Background(), "secure-admin", hash, encrypted, -1); err != nil {
		t.Fatal(err)
	}
	required, err = store.AdminSetupRequired(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if required {
		t.Fatal("completed setup channel must be closed")
	}
	if err := store.CompleteAdminSetup(context.Background(), "attacker", hash, encrypted, -1); err == nil {
		t.Fatal("administrator setup must be permanently one-time")
	}
	code, ok := totpValue(secret, time.Now().Unix()/30)
	if !ok {
		t.Fatal("failed to generate test TOTP")
	}
	if !store.AuthenticateAdmin(context.Background(), "secure-admin", "a-new-strong-password", code) {
		t.Fatal("valid password and TOTP were rejected")
	}
	if store.AuthenticateAdmin(context.Background(), "secure-admin", "a-new-strong-password", code) {
		t.Fatal("a consumed TOTP counter must not be replayable")
	}
	if store.AuthenticateAdmin(context.Background(), "secure-admin", "wrong-password", code) {
		t.Fatal("wrong password was accepted")
	}
}

func TestCompletedAdminSetupNeverReopensWhenTOTPStateIsDamaged(t *testing.T) {
	server, store := testApp(t)
	secret := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	encrypted, err := store.vault.Encrypt(secret, "admin-totp")
	if err != nil {
		t.Fatal(err)
	}
	hash, err := passwordHash("a-new-strong-password", 10_000)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteAdminSetup(context.Background(), "secure-admin", hash, encrypted, -1); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSetting(context.Background(), "admin_totp_secret_enc", ""); err != nil {
		t.Fatal(err)
	}
	required, err := store.AdminSetupRequired(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if required {
		t.Fatal("clearing a completed TOTP secret reopened administrator setup")
	}
	if err := store.CompleteAdminSetup(context.Background(), "attacker", hash, encrypted, -1); err == nil {
		t.Fatal("completion marker did not block administrator replacement")
	}
	request := httptest.NewRequest(http.MethodPost, "http://admin.local/api/setup/start", strings.NewReader(`{"initialization_password":"correct-horse-battery-staple","username":"attacker","password":"another-strong-password"}`))
	request.RemoteAddr = "203.0.113.213:4321"
	recorder := httptest.NewRecorder()
	server.adminSetupStart(recorder, request)
	if recorder.Code != http.StatusGone {
		t.Fatalf("damaged completed setup status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := store.CheckAdminTOTP(context.Background()); err == nil {
		t.Fatal("damaged TOTP state was reported healthy")
	}
}

func TestAdminPasswordChangeDistinguishesStorageFailureFromBadCredentials(t *testing.T) {
	server, store := testApp(t)
	secret := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	encrypted, err := store.vault.Encrypt(secret, "admin-totp")
	if err != nil {
		t.Fatal(err)
	}
	hash, err := passwordHash("current-strong-password", 10_000)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteAdminSetup(context.Background(), "secure-admin", hash, encrypted, -1); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSetting(context.Background(), "admin_totp_secret_enc", "corrupted-ciphertext"); err != nil {
		t.Fatal(err)
	}
	body := strings.NewReader(`{"current_password":"current-strong-password","new_password":"replacement-strong-password","totp_code":"123456"}`)
	request := httptest.NewRequest(http.MethodPost, "http://admin.local/api/system/password", body)
	request.RemoteAddr = "203.0.113.214:4321"
	recorder := httptest.NewRecorder()
	server.adminChangePassword(recorder, request)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("storage failure status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "cipher") || strings.Contains(recorder.Body.String(), "decrypt") {
		t.Fatalf("password endpoint exposed internal storage error: %s", recorder.Body.String())
	}
}

func TestSetupStateDatabaseFailureFailsClosed(t *testing.T) {
	server, store := testApp(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	required, err := store.AdminSetupRequired(context.Background())
	if err == nil {
		t.Fatal("closed database unexpectedly reported a readable setup state")
	}
	if required {
		t.Fatal("database failure must not reopen administrator setup")
	}

	startRequest := httptest.NewRequest(http.MethodPost, "http://admin.local/api/setup/start", strings.NewReader(`{"initialization_password":"correct-horse-battery-staple","username":"owner-admin","password":"a-brand-new-admin-password"}`))
	startRequest.RemoteAddr = "203.0.113.212:4321"
	startRecorder := httptest.NewRecorder()
	server.adminSetupStart(startRecorder, startRequest)
	if startRecorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("setup start status=%d body=%s", startRecorder.Code, startRecorder.Body.String())
	}
	if startRecorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("setup failure response is cacheable: %q", startRecorder.Header().Get("Cache-Control"))
	}
	server.setupMu.Lock()
	flowCount := len(server.setupFlows)
	server.setupMu.Unlock()
	if flowCount != 0 {
		t.Fatalf("setup flow was created while state was unavailable: %d", flowCount)
	}

	meRequest := httptest.NewRequest(http.MethodGet, "http://admin.local/api/me", nil)
	meRequest.RemoteAddr = "203.0.113.212:4321"
	meRecorder := httptest.NewRecorder()
	server.adminMe(meRecorder, meRequest)
	if meRecorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("admin me status=%d body=%s", meRecorder.Code, meRecorder.Body.String())
	}
	if meRecorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("admin me failure response is cacheable: %q", meRecorder.Header().Get("Cache-Control"))
	}

	status := server.securityStatus(context.Background())
	checks, ok := status["checks"].([]SecurityCheck)
	if !ok {
		t.Fatalf("unexpected checks payload: %#v", status["checks"])
	}
	foundTOTP := false
	for _, check := range checks {
		if check.Key != "totp" {
			continue
		}
		foundTOTP = true
		if check.Healthy || !strings.Contains(check.Detail, "创建渠道保持关闭") {
			t.Fatalf("setup database failure was not reported fail-closed: %+v", check)
		}
	}
	if !foundTOTP {
		t.Fatal("TOTP health check missing")
	}
}

func TestStatusThresholdAndPermanentManualBan(t *testing.T) {
	server, store := testApp(t)
	ip := "203.0.113.190"
	for attempt := 1; attempt <= 3; attempt++ {
		banned, err := store.RecordStatusFailure(context.Background(), ip, 404, 3, time.Minute, time.Hour, "api:/missing")
		if err != nil {
			t.Fatal(err)
		}
		if banned != (attempt == 3) {
			t.Fatalf("attempt %d banned=%v", attempt, banned)
		}
	}
	server.refreshBanCache(context.Background())
	if !server.isBannedCached(ip) {
		t.Fatal("threshold ban was not loaded into the fast path")
	}
	if err := store.Unban(context.Background(), ip); err != nil {
		t.Fatal(err)
	}
	if err := store.BanIP(context.Background(), ip, "manual permanent test", 0, true); err != nil {
		t.Fatal(err)
	}
	items, err := store.ListBans(context.Background())
	if err != nil || len(items) != 1 || items[0].ExpiresAt != 0 || items[0].Scope != "all" {
		t.Fatalf("permanent bans=%+v err=%v", items, err)
	}
}

func TestAutomaticStatusBanCoversGatewayButNeverLocksAdminSurface(t *testing.T) {
	server, store := testApp(t)
	config := SecurityConfig{ProtectionEnabled: true, Threshold404: 3, Threshold502: 3, WindowMinutes: 10, BanHours: 24}
	if err := store.SaveSecurityConfig(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	server.setSecurityConfig(config)
	notFound := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })

	adminHandler := server.commonHeaders("admin", notFound)
	for attempt := 0; attempt < 5; attempt++ {
		request := httptest.NewRequest(http.MethodGet, "http://admin.invalid/missing", nil)
		request.RemoteAddr = "203.0.113.201:1234"
		adminHandler.ServeHTTP(httptest.NewRecorder(), request)
	}
	if banned, err := store.IsBanned(context.Background(), "203.0.113.201"); err != nil || banned {
		t.Fatalf("admin surface was counted toward automatic status ban: banned=%v err=%v", banned, err)
	}

	apiHandler := server.commonHeaders("api", notFound)
	for attempt := 0; attempt < 3; attempt++ {
		request := httptest.NewRequest(http.MethodGet, "http://api.invalid/missing", nil)
		request.RemoteAddr = "203.0.113.202:1234"
		apiHandler.ServeHTTP(httptest.NewRecorder(), request)
	}
	if banned, err := store.IsBanned(context.Background(), "203.0.113.202"); err != nil || !banned {
		t.Fatalf("API status threshold did not ban: banned=%v err=%v", banned, err)
	}
	adminAfterBan := httptest.NewRequest(http.MethodGet, "http://admin.invalid/missing", nil)
	adminAfterBan.RemoteAddr = "203.0.113.202:1234"
	adminAfterBanRecorder := httptest.NewRecorder()
	adminHandler.ServeHTTP(adminAfterBanRecorder, adminAfterBan)
	if adminAfterBanRecorder.Code != http.StatusNotFound {
		t.Fatalf("public-scope automatic ban locked admin surface: status=%d body=%s", adminAfterBanRecorder.Code, adminAfterBanRecorder.Body.String())
	}
	apiAfterBan := httptest.NewRequest(http.MethodGet, "http://api.invalid/missing", nil)
	apiAfterBan.RemoteAddr = "203.0.113.202:1234"
	apiAfterBanRecorder := httptest.NewRecorder()
	apiHandler.ServeHTTP(apiAfterBanRecorder, apiAfterBan)
	if apiAfterBanRecorder.Code != http.StatusForbidden {
		t.Fatalf("automatic ban did not block API surface: status=%d body=%s", apiAfterBanRecorder.Code, apiAfterBanRecorder.Body.String())
	}
}

func TestAutomatic502UsesIndependentConfiguredThreshold(t *testing.T) {
	server, store := testApp(t)
	config := SecurityConfig{ProtectionEnabled: true, Threshold404: 20, Threshold502: 3, WindowMinutes: 10, BanHours: 24}
	if err := store.SaveSecurityConfig(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	server.setSecurityConfig(config)
	badGateway := server.commonHeaders("api", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusBadGateway, "upstream_error", "test")
	}))
	ip := "203.0.113.203"
	for attempt := 1; attempt <= 3; attempt++ {
		request := httptest.NewRequest(http.MethodPost, "http://api.invalid/v1/responses", nil)
		request.RemoteAddr = ip + ":1234"
		recorder := httptest.NewRecorder()
		badGateway.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadGateway {
			t.Fatalf("attempt %d status=%d body=%s", attempt, recorder.Code, recorder.Body.String())
		}
	}
	if banned, err := store.IsBanned(context.Background(), ip); err != nil || !banned {
		t.Fatalf("502 threshold did not ban: banned=%v err=%v", banned, err)
	}
}

func TestObservabilityProbeRollsBackAndDetectsBrokenPipeline(t *testing.T) {
	_, store := testApp(t)
	ctx := context.Background()
	counts := func() [3]int {
		t.Helper()
		var result [3]int
		for index, table := range []string{"usage_logs", "audit_logs", "security_events"} {
			if err := store.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&result[index]); err != nil {
				t.Fatal(err)
			}
		}
		return result
	}

	before := counts()
	if err := store.CheckObservability(ctx); err != nil {
		t.Fatalf("healthy observability probe failed: %v", err)
	}
	if after := counts(); after != before {
		t.Fatalf("observability probe manufactured visible rows: before=%v after=%v", before, after)
	}

	if _, err := store.db.Exec(`CREATE TRIGGER block_audit_observability
BEFORE INSERT ON audit_logs BEGIN SELECT RAISE(ABORT, 'audit pipeline blocked'); END`); err != nil {
		t.Fatal(err)
	}
	err := store.CheckObservability(ctx)
	if err == nil || !strings.Contains(err.Error(), "audit log write probe") || !strings.Contains(err.Error(), "audit pipeline blocked") {
		t.Fatalf("broken audit pipeline was not identified: %v", err)
	}
	if after := counts(); after != before {
		t.Fatalf("failed observability probe leaked rows: before=%v after=%v", before, after)
	}
	if _, err := store.db.Exec("DROP TRIGGER block_audit_observability"); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckObservability(ctx); err != nil {
		t.Fatalf("observability probe did not recover: %v", err)
	}
}

func TestRealLogWriteFailuresRemainVisibleUntilRealWritesRecover(t *testing.T) {
	server, store := testApp(t)
	ctx := context.Background()
	for _, statement := range []string{
		`CREATE TRIGGER block_usage_log BEFORE INSERT ON usage_logs BEGIN SELECT RAISE(ABORT, 'usage blocked'); END`,
		`CREATE TRIGGER block_audit_log BEFORE INSERT ON audit_logs BEGIN SELECT RAISE(ABORT, 'audit blocked'); END`,
		`CREATE TRIGGER block_security_log BEFORE INSERT ON security_events BEGIN SELECT RAISE(ABORT, 'security blocked'); END`,
	} {
		if _, err := store.db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}

	usage := UsageLog{IP: "203.0.113.230", Method: "POST", Path: "/v1/responses", Model: "gpt-test", Status: 200}
	if err := store.LogUsage(ctx, 1, 1, usage); err == nil {
		t.Fatal("blocked usage write unexpectedly succeeded")
	}
	if err := store.Audit(ctx, "admin", "test.audit", "target", usage.IP, map[string]bool{"real": true}); err == nil {
		t.Fatal("blocked audit write unexpectedly succeeded")
	}
	if err := store.RecordSecurityEvent(ctx, usage.IP, "test_security", "/test", "real event"); err == nil {
		t.Fatal("blocked security-event write unexpectedly succeeded")
	}
	for _, key := range []string{"usage_log", "audit_log", "security_log"} {
		if !server.hasSecurityRuntimeFailure(key) {
			t.Fatalf("%s failure was not exposed", key)
		}
	}
	status := server.securityStatus(ctx)
	for _, check := range status["checks"].([]SecurityCheck) {
		if check.Key == "observability" && check.Healthy {
			t.Fatalf("recent real log loss was hidden by a successful synthetic probe: %+v", check)
		}
	}
	visibleFailures := map[string]bool{}
	for _, failure := range status["runtime_errors"].([]securityRuntimeFailure) {
		visibleFailures[failure.Key] = true
	}
	for _, key := range []string{"usage_log", "audit_log", "security_log"} {
		if !visibleFailures[key] {
			t.Fatalf("%s failure was not included in the system status payload: %+v", key, status["runtime_errors"])
		}
	}

	for _, name := range []string{"block_usage_log", "block_audit_log", "block_security_log"} {
		if _, err := store.db.Exec("DROP TRIGGER " + name); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.LogUsage(ctx, 1, 1, usage); err != nil {
		t.Fatal(err)
	}
	if err := store.Audit(ctx, "admin", "test.audit.recovered", "target", usage.IP, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordSecurityEvent(ctx, usage.IP, "test_security_recovered", "/test", "real event"); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"usage_log", "audit_log", "security_log"} {
		if server.hasSecurityRuntimeFailure(key) {
			t.Fatalf("%s failure was not cleared by a successful real write", key)
		}
	}
}

func TestSecurityAnomalyReadFailureIsNeverSwallowed(t *testing.T) {
	server, store := testApp(t)
	ctx := context.Background()
	if _, err := store.db.Exec("ALTER TABLE security_events RENAME TO security_events_unavailable"); err != nil {
		t.Fatal(err)
	}
	restored := false
	defer func() {
		if !restored {
			_, _ = store.db.Exec("ALTER TABLE security_events_unavailable RENAME TO security_events")
		}
	}()

	status := server.securityStatus(ctx)
	if detail, ok := status["anomalies_error"].(string); !ok || detail == "" {
		t.Fatalf("security-event read error missing from response: %+v", status)
	}
	if !server.hasSecurityRuntimeFailure("security_log_read") {
		t.Fatal("security-event read error missing from runtime failures")
	}
	found := false
	for _, check := range status["checks"].([]SecurityCheck) {
		if check.Key == "observability" {
			found = true
			if check.Healthy {
				t.Fatalf("unreadable anomalies were reported healthy: %+v", check)
			}
		}
	}
	if !found {
		t.Fatal("observability check missing")
	}

	if _, err := store.db.Exec("ALTER TABLE security_events_unavailable RENAME TO security_events"); err != nil {
		t.Fatal(err)
	}
	restored = true
	recovered := server.securityStatus(ctx)
	if _, exists := recovered["anomalies_error"]; exists {
		t.Fatalf("stale anomaly error remained after a successful read: %+v", recovered)
	}
	if server.hasSecurityRuntimeFailure("security_log_read") {
		t.Fatal("security-event read runtime failure did not clear")
	}
}

func TestNginxPersistenceFailuresAreVisibleAndRecoverable(t *testing.T) {
	server, store := testApp(t)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "nginx.conf")
	original := []byte("events {}\nhttp {}\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	server.cfg.NginxMonitorPaths = []string{path}
	baseline := server.nginxFingerprint()
	config := SecurityConfig{ProtectionEnabled: true, NginxProtection: true, Threshold404: 12, Threshold502: 30, WindowMinutes: 10, BanHours: 24}
	if err := store.SaveSecurityConfig(ctx, config); err != nil {
		t.Fatal(err)
	}
	server.setSecurityConfig(config)
	if err := store.SetSetting(ctx, "security_nginx_baseline", baseline.Hash); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSetting(ctx, "security_nginx_baseline_version", nginxFingerprintVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("DELETE FROM settings WHERE key='security_nginx_last_alert_hash'"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("events {}\nhttp { server {} }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`CREATE TRIGGER block_nginx_alert_marker
BEFORE INSERT ON settings WHEN NEW.key='security_nginx_last_alert_hash'
BEGIN SELECT RAISE(ABORT, 'marker blocked'); END`); err != nil {
		t.Fatal(err)
	}
	server.nginxIntegrityStatus(ctx, true)
	if !server.hasSecurityRuntimeFailure("nginx_persistence") {
		t.Fatal("failed Nginx alert marker write was not exposed")
	}
	if _, err := store.db.Exec("DROP TRIGGER block_nginx_alert_marker"); err != nil {
		t.Fatal(err)
	}
	server.nginxIntegrityStatus(ctx, true)
	if server.hasSecurityRuntimeFailure("nginx_persistence") {
		t.Fatal("Nginx persistence failure did not clear after a successful retry")
	}
	if marker := store.Setting(ctx, "security_nginx_last_alert_hash"); marker == "" {
		t.Fatal("successful retry did not persist the Nginx alert marker")
	}

	if _, err := store.db.Exec("ALTER TABLE settings RENAME TO settings_unavailable"); err != nil {
		t.Fatal(err)
	}
	readStatus := server.nginxIntegrityStatus(ctx, false)
	if readStatus["state"] != "persistence_error" || readStatus["applicable"] != true || readStatus["persistence_error"] == "" {
		t.Fatalf("Nginx settings read failure was hidden: %+v", readStatus)
	}
	if !server.hasSecurityRuntimeFailure("nginx_persistence") {
		t.Fatal("Nginx settings read failure missing from runtime failures")
	}
	if _, err := store.db.Exec("ALTER TABLE settings_unavailable RENAME TO settings"); err != nil {
		t.Fatal(err)
	}
	server.nginxIntegrityStatus(ctx, false)
	if server.hasSecurityRuntimeFailure("nginx_persistence") {
		t.Fatal("Nginx settings read failure did not clear after successful reads")
	}
}

func TestNginxFingerprintDetectsRealFileModification(t *testing.T) {
	server, store := testApp(t)
	path := filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(path, []byte("events {}\nhttp {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	server.cfg.NginxMonitorPaths = []string{path}
	first := server.nginxFingerprint()
	if !first.Available || first.FileCount != 1 || first.Hash == "" {
		t.Fatalf("first fingerprint=%+v", first)
	}
	config := SecurityConfig{ProtectionEnabled: true, NginxProtection: true, Threshold404: 12, Threshold502: 30, WindowMinutes: 10, BanHours: 24}
	if err := store.SaveSecurityConfig(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	server.setSecurityConfig(config)
	if err := store.SetSetting(context.Background(), "security_nginx_baseline", first.Hash); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSetting(context.Background(), "security_nginx_baseline_version", nginxFingerprintVersion); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("events {}\nhttp { server {} }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second := server.nginxFingerprint()
	if !second.Available || first.Hash == second.Hash {
		t.Fatalf("configuration modification was not detected: first=%s second=%s", first.Hash, second.Hash)
	}
	status := server.nginxIntegrityStatus(context.Background(), true)
	if modified, _ := status["modified"].(bool); !modified {
		t.Fatalf("integrity status did not report modification: %+v", status)
	}
	events, err := store.ListSecurityEvents(context.Background(), 10)
	if err != nil || len(events) == 0 || events[0].Kind != "nginx_config_modified" {
		t.Fatalf("nginx alert was not persisted: events=%+v err=%v", events, err)
	}
}

func TestNginxFingerprintRejectsPartialOrUnsafeSnapshots(t *testing.T) {
	server, _ := testApp(t)

	t.Run("per-file byte limit", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "nginx.conf"), []byte("1234"), 0o600); err != nil {
			t.Fatal(err)
		}
		server.cfg.NginxMonitorPaths = []string{root}
		result := server.nginxFingerprintWithLimits(10, 3, 100)
		if result.Available || !result.Truncated || !strings.Contains(strings.Join(result.Errors, " "), "file exceeds") {
			t.Fatalf("oversized snapshot was accepted: %+v", result)
		}
	})

	t.Run("total byte limit", func(t *testing.T) {
		root := t.TempDir()
		for _, name := range []string{"a.conf", "b.conf"} {
			if err := os.WriteFile(filepath.Join(root, name), []byte("1234"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		server.cfg.NginxMonitorPaths = []string{root}
		result := server.nginxFingerprintWithLimits(10, 10, 6)
		if result.Available || !result.Truncated || !strings.Contains(strings.Join(result.Errors, " "), "total byte limit") {
			t.Fatalf("partial total-byte snapshot was accepted: %+v", result)
		}
	})

	t.Run("file count truncation", func(t *testing.T) {
		root := t.TempDir()
		for _, name := range []string{"a.conf", "b.conf"} {
			if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		server.cfg.NginxMonitorPaths = []string{root}
		result := server.nginxFingerprintWithLimits(1, 10, 10)
		if result.Available || !result.Truncated || !strings.Contains(strings.Join(result.Errors, " "), "file limit") {
			t.Fatalf("truncated file list was accepted: %+v", result)
		}
	})

	t.Run("non regular symlink target", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "nginx.conf"), []byte("events {}"), 0o600); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, "directory-target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(root, "unsafe-link")); err != nil {
			t.Fatal(err)
		}
		server.cfg.NginxMonitorPaths = []string{root}
		result := server.nginxFingerprintWithLimits(10, 1<<20, 1<<20)
		if result.Available || !strings.Contains(strings.Join(result.Errors, " "), "not a regular file") {
			t.Fatalf("non-regular target was accepted: %+v", result)
		}
	})
}

func TestNginxFingerprintIncludesPermissionsAndOwnershipMetadata(t *testing.T) {
	server, _ := testApp(t)
	path := filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(path, []byte("events {}"), 0o600); err != nil {
		t.Fatal(err)
	}
	server.cfg.NginxMonitorPaths = []string{path}
	first := server.nginxFingerprint()
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	second := server.nginxFingerprint()
	if !first.Available || !second.Available || first.Hash == second.Hash {
		t.Fatalf("mode change was not fingerprinted: first=%+v second=%+v", first, second)
	}
}

func TestNginxAlertRecordsUnavailableAndRealertsAfterRecovery(t *testing.T) {
	server, store := testApp(t)
	path := filepath.Join(t.TempDir(), "nginx.conf")
	original := []byte("events {}\nhttp {}\n")
	modified := []byte("events {}\nhttp { server {} }\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	server.cfg.NginxMonitorPaths = []string{path}
	baseline := server.nginxFingerprint()
	config := SecurityConfig{ProtectionEnabled: true, NginxProtection: true, Threshold404: 12, Threshold502: 30, WindowMinutes: 10, BanHours: 24}
	if err := store.SaveSecurityConfig(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	server.setSecurityConfig(config)
	if err := store.SetSetting(context.Background(), "security_nginx_baseline", baseline.Hash); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSetting(context.Background(), "security_nginx_baseline_version", nginxFingerprintVersion); err != nil {
		t.Fatal(err)
	}

	// A missing configuration has no content hash, but must still create the
	// first alert instead of colliding with the empty initial marker.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	server.nginxIntegrityStatus(context.Background(), true)
	server.nginxIntegrityStatus(context.Background(), true)
	assertSecurityEventCount(t, store, "nginx_config_modified", 1)

	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	server.nginxIntegrityStatus(context.Background(), true)
	assertSecurityEventCount(t, store, "nginx_config_recovered", 1)
	if marker := store.Setting(context.Background(), "security_nginx_last_alert_hash"); marker != "" {
		t.Fatalf("recovery did not clear alert marker: %q", marker)
	}

	if err := os.WriteFile(path, modified, 0o600); err != nil {
		t.Fatal(err)
	}
	server.nginxIntegrityStatus(context.Background(), true)
	assertSecurityEventCount(t, store, "nginx_config_modified", 2)
}

func TestUnavailableNginxIsNotApplicableAndCannotBeEnabled(t *testing.T) {
	server, store := testApp(t)
	server.cfg.NginxMonitorPaths = []string{filepath.Join(t.TempDir(), "missing-nginx.conf")}
	status := server.securityStatus(context.Background())
	nginxStatus := status["nginx"].(map[string]any)
	if nginxStatus["state"] != "not_installed_or_not_mounted" || nginxStatus["applicable"] != false {
		t.Fatalf("missing Nginx state=%+v", nginxStatus)
	}
	if errors, ok := nginxStatus["errors"].([]string); ok && len(errors) != 0 {
		t.Fatalf("expected missing Nginx paths were reported as integrity errors: %+v", errors)
	}
	if status["health_applicable_checks"] != 10 {
		t.Fatalf("Nginx N/A was counted in health denominator: %+v", status["health_applicable_checks"])
	}
	checks, ok := status["checks"].([]SecurityCheck)
	if !ok {
		t.Fatalf("unexpected checks payload: %#v", status["checks"])
	}
	found := false
	for _, check := range checks {
		if check.Key == "nginx" {
			found = true
			if check.Mode != "not_applicable" || check.Enabled || check.Healthy {
				t.Fatalf("unavailable Nginx check is misleading: %+v", check)
			}
		}
	}
	if !found {
		t.Fatal("Nginx health check missing")
	}

	body := []byte(`{"protection_enabled":true,"nginx_protection":true,"threshold_404":12,"threshold_502":30,"window_minutes":10,"ban_hours":24}`)
	request := httptest.NewRequest(http.MethodPut, "http://admin.local/api/system/security", bytes.NewReader(body))
	request.RemoteAddr = "203.0.113.200:1234"
	recorder := httptest.NewRecorder()
	server.adminUpdateSecurity(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("unavailable Nginx protection status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if store.SecurityConfig(context.Background()).ProtectionEnabled {
		t.Fatal("rejected protection update was persisted")
	}
}

func TestLegacyNginxBaselineIsOutdatedNotAFalseModification(t *testing.T) {
	server, store := testApp(t)
	path := filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(path, []byte("events {}\nhttp {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	server.cfg.NginxMonitorPaths = []string{path}
	config := SecurityConfig{ProtectionEnabled: true, NginxProtection: true, Threshold404: 12, Threshold502: 30, WindowMinutes: 10, BanHours: 24}
	if err := store.SaveSecurityConfig(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	server.setSecurityConfig(config)
	if err := store.SetSetting(context.Background(), "security_nginx_baseline", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	status := server.nginxIntegrityStatus(context.Background(), true)
	if outdated, _ := status["baseline_outdated"].(bool); !outdated {
		t.Fatalf("legacy baseline was not marked outdated: %+v", status)
	}
	if modified, _ := status["modified"].(bool); modified {
		t.Fatalf("legacy fingerprint algorithm caused a false modification: %+v", status)
	}
	assertSecurityEventCount(t, store, "nginx_config_modified", 0)
}

func TestManualBanRejectsCurrentAdminsPairedAddress(t *testing.T) {
	server, store := testApp(t)
	createTestAccount(t, store, "paired-ban-account", "access", "acct-paired-ban")
	ipv4 := "198.51.100.81"
	ipv6 := "2001:db8::81"
	token := "paired-ban-invitation-token-long-enough"
	claim := "paired-ban-claim-session-long-enough"
	probe := "paired-ban-probe-token-long-enough"
	if _, err := store.CreateInvitation(context.Background(), "paired admin", token, "123456", 0, 0, time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyInvitation(context.Background(), token, "123456", ipv4, claim, probe); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordInvitationProbe(context.Background(), token, probe, ipv6); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveInviteDevice(context.Background(), token, claim, ipv4, "administrator workstation"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.GenerateInvitedKey(context.Background(), token, claim, ipv4, "sk-fg_paired-admin", time.Minute); err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"ip":"2001:db8::81","reason":"must be rejected","permanent":true}`)
	request := httptest.NewRequest(http.MethodPost, "http://admin.local/api/system/bans", bytes.NewReader(body))
	request.RemoteAddr = ipv4 + ":4321"
	recorder := httptest.NewRecorder()
	server.adminBanIP(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("paired self-ban status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	for _, ip := range []string{ipv4, ipv6} {
		if banned, err := store.IsBanned(context.Background(), ip); err != nil || banned {
			t.Fatalf("paired IP %s banned=%v err=%v", ip, banned, err)
		}
	}
}

func TestCorruptEncryptedTOTPDegradesRealHealthCheck(t *testing.T) {
	server, store := testApp(t)
	secret := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	encrypted, err := store.vault.Encrypt(secret, "admin-totp")
	if err != nil {
		t.Fatal(err)
	}
	hash, err := passwordHash("a-new-strong-password", 10_000)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteAdminSetup(context.Background(), "secure-admin", hash, encrypted, -1); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSetting(context.Background(), "admin_totp_secret_enc", "corrupt-aes-gcm-ciphertext"); err != nil {
		t.Fatal(err)
	}
	status := server.securityStatus(context.Background())
	checks := status["checks"].([]SecurityCheck)
	for _, check := range checks {
		if check.Key == "totp" {
			if check.Healthy || !strings.Contains(check.Detail, "登录可能不可用") {
				t.Fatalf("corrupt TOTP was reported healthy: %+v", check)
			}
			return
		}
	}
	t.Fatal("TOTP health check missing")
}

func TestAdminLogoutReportsServerSessionRevocationFailure(t *testing.T) {
	server, store := testApp(t)
	token, _, err := store.NewAdminSession(context.Background(), "203.0.113.220", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://admin.local/api/logout", strings.NewReader(`{}`))
	request.RemoteAddr = "203.0.113.220:43000"
	request.AddCookie(&http.Cookie{Name: adminCookieName, Value: token})
	recorder := httptest.NewRecorder()
	server.adminLogout(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "logout_failed") {
		t.Fatalf("logout status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != adminCookieName || cookies[0].MaxAge >= 0 {
		t.Fatalf("failed logout did not clear browser cookie: %+v", cookies)
	}
}

func TestChangeAdminPasswordIsAtomicAndRevokesEverySession(t *testing.T) {
	_, store := testApp(t)
	secret := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	encrypted, err := store.vault.Encrypt(secret, "admin-totp")
	if err != nil {
		t.Fatal(err)
	}
	hash, err := passwordHash("old-strong-password", 10_000)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteAdminSetup(context.Background(), "secure-admin", hash, encrypted, -1); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"203.0.113.221", "203.0.113.222"} {
		if _, _, err := store.NewAdminSession(context.Background(), ip, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	counter := time.Now().Unix() / 30
	code, _ := totpValue(secret, counter)
	if err := store.ChangeAdminPassword(context.Background(), "old-strong-password", "new-strong-password", code); err != nil {
		t.Fatal(err)
	}
	var sessions int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM admin_sessions").Scan(&sessions); err != nil || sessions != 0 {
		t.Fatalf("sessions=%d err=%v", sessions, err)
	}
	nextCode, _ := totpValue(secret, counter+1)
	if store.AuthenticateAdmin(context.Background(), "secure-admin", "old-strong-password", nextCode) {
		t.Fatal("old password remained valid")
	}
	if !store.AuthenticateAdmin(context.Background(), "secure-admin", "new-strong-password", nextCode) {
		t.Fatal("new password was not usable")
	}
}

func TestSecurityConfigPersistsAndLoadsIntoNewServer(t *testing.T) {
	server, store := testApp(t)
	want := SecurityConfig{ProtectionEnabled: true, NginxProtection: false, Threshold404: 7, Threshold502: 9, WindowMinutes: 17, BanHours: 36}
	body, _ := json.Marshal(want)
	request := httptest.NewRequest(http.MethodPut, "http://admin.local/api/system/security", bytes.NewReader(body))
	request.RemoteAddr = "203.0.113.223:43000"
	recorder := httptest.NewRecorder()
	server.adminUpdateSecurity(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("save status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := store.SecurityConfig(context.Background()); got != want {
		t.Fatalf("persisted config=%+v want=%+v", got, want)
	}
	restarted := NewServer(server.cfg, store, server.vault)
	if got := restarted.currentSecurityConfig(); got != want {
		t.Fatalf("restarted runtime config=%+v want=%+v", got, want)
	}
}

func TestAttemptLimiterKeepsPerEntryWindowsAndFixedCapacity(t *testing.T) {
	server, _ := testApp(t)
	if !server.allowAttempt("setup-long-window", 1, time.Hour) || server.allowAttempt("setup-long-window", 1, time.Hour) {
		t.Fatal("basic setup limiter did not enforce its own window")
	}
	for index := 0; index < maxAttemptWindows-1; index++ {
		if !server.allowAttempt(fmt.Sprintf("attacker-%d", index), 1, 10*time.Minute) {
			t.Fatalf("capacity filled early at %d", index)
		}
	}
	if server.allowAttempt("overflow", 1, 10*time.Minute) {
		t.Fatal("limiter grew beyond its fixed capacity")
	}
	if server.allowAttempt("setup-long-window", 1, 10*time.Minute) {
		t.Fatal("10-minute traffic reset a live one-hour setup window")
	}
	server.limitMu.Lock()
	server.limits["attacker-0"].ExpiresAt = time.Now().Add(-time.Second)
	server.limitMu.Unlock()
	if !server.allowAttempt("replacement", 1, 10*time.Minute) {
		t.Fatal("expired capacity slot was not reclaimed")
	}
}

func assertSecurityEventCount(t *testing.T, store *Store, kind string, want int) {
	t.Helper()
	var got int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM security_events WHERE kind=?", kind).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("security event %s count=%d want=%d", kind, got, want)
	}
}
