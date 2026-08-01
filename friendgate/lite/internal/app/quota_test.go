package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestQuotaAutomationAndResetCredit(t *testing.T) {
	server, store := testApp(t)
	accountID := createTestAccount(t, store, "quota-account", "quota-access", "acct-quota")
	server.cfg.QuotaBaseURL = "https://quota.example/backend-api/wham"

	var mutex sync.Mutex
	var paths []string
	var redeemID string
	server.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bearer quota-access" || request.Header.Get("ChatGPT-Account-ID") != "acct-quota" || request.Header.Get("OpenAI-Beta") != "codex-1" {
			t.Fatalf("unexpected quota headers: %#v", request.Header)
		}
		mutex.Lock()
		paths = append(paths, request.Method+" "+request.URL.Path)
		mutex.Unlock()
		switch request.Method + " " + request.URL.Path {
		case "GET /backend-api/wham/usage":
			return jsonResponse(200, `{"plan_type":"plus","rate_limit":{"allowed":true,"limit_reached":false,"primary_window":{"used_percent":42.5,"limit_window_seconds":18000,"reset_after_seconds":120},"secondary_window":{"used_percent":73,"limit_window_seconds":604800,"reset_at":2000000000}},"rate_limit_reset_credits":{"available_count":7}}`), nil
		case "GET /backend-api/wham/rate-limit-reset-credits":
			return jsonResponse(200, `{"availableCount":"2","credits":[{"reset_type":"codex_rate_limits","status":"available","expires_at":"2026-07-28T00:00:00Z"},{"resetType":"codex_rate_limits","status":"available","expiresAt":"2026-08-01T00:00:00Z"},{"reset_type":"other","status":"available"}]}`), nil
		case "POST /backend-api/wham/rate-limit-reset-credits/consume":
			payload, _ := io.ReadAll(request.Body)
			var body map[string]string
			if err := json.Unmarshal(payload, &body); err != nil {
				t.Fatal(err)
			}
			redeemID = body["redeem_request_id"]
			return jsonResponse(200, `{"code":"success","windows_reset":2}`), nil
		default:
			return jsonResponse(404, `{}`), nil
		}
	})}

	snapshot, err := server.syncAccountQuota(context.Background(), accountID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.PlanType != "plus" || snapshot.FiveHourUsed != 42.5 || snapshot.SevenDayUsed != 73 || snapshot.ResetCredits != 2 || len(snapshot.ResetCreditTimes) != 2 {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
	if snapshot.FiveHourResetAt < time.Now().Unix()+100 || snapshot.SevenDayResetAt != 2_000_000_000 {
		t.Fatalf("unexpected reset times: %+v", snapshot)
	}
	stored, err := store.GetAccount(context.Background(), accountID)
	if err != nil || stored.Quota5HUsed != 42.5 || stored.Quota7DUsed != 73 || stored.ResetCredits != 2 || stored.QuotaUpdatedAt == 0 {
		t.Fatalf("stored quota=%+v err=%v", stored, err)
	}
	result, err := server.resetAccountQuota(context.Background(), accountID)
	if err != nil || result.Code != "success" || result.WindowsReset != 2 {
		t.Fatalf("reset result=%+v err=%v", result, err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(redeemID) {
		t.Fatalf("invalid redeem request id %q", redeemID)
	}
	mutex.Lock()
	joined := strings.Join(paths, "\n")
	mutex.Unlock()
	if !strings.Contains(joined, "POST /backend-api/wham/rate-limit-reset-credits/consume") {
		t.Fatalf("reset endpoint not called: %s", joined)
	}
}

func TestQuotaLimitAutomaticallyCoolsAccount(t *testing.T) {
	server, store := testApp(t)
	accountID := createTestAccount(t, store, "limited", "limited-access", "acct-limited")
	server.cfg.QuotaBaseURL = "https://quota.example"
	resetAt := time.Now().Add(45 * time.Minute).Unix()
	server.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/usage" {
			return jsonResponse(200, `{"rate_limit":{"allowed":false,"limit_reached":true,"primary_window":{"used_percent":100,"limit_window_seconds":18000,"reset_at":`+jsonNumber(resetAt)+`}}}`), nil
		}
		return jsonResponse(200, `{}`), nil
	})}
	if _, err := server.syncAccountQuota(context.Background(), accountID); err != nil {
		t.Fatal(err)
	}
	account, err := store.GetAccount(context.Background(), accountID)
	if err != nil || account.CooldownUntil != resetAt {
		t.Fatalf("cooldown=%+v err=%v", account, err)
	}
}

func TestAccountDeleteWaitsForQuotaSyncAndClearsPersistedResult(t *testing.T) {
	server, store := testApp(t)
	accountID := createTestAccount(t, store, "quota-delete", "quota-delete-access", "acct-quota-delete")
	server.cfg.QuotaBaseURL = "https://quota.example"
	started := make(chan struct{})
	release := make(chan struct{})
	var callsMu sync.Mutex
	calls := 0
	server.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		callsMu.Lock()
		calls++
		callsMu.Unlock()
		switch request.URL.Path {
		case "/usage":
			close(started)
			<-release
			return jsonResponse(http.StatusOK, `{"plan_type":"plus","rate_limit":{"allowed":true,"primary_window":{"used_percent":64,"limit_window_seconds":18000}}}`), nil
		case "/rate-limit-reset-credits":
			return jsonResponse(http.StatusOK, `{"available_count":1}`), nil
		default:
			return jsonResponse(http.StatusNotFound, `{}`), nil
		}
	})}
	syncDone := make(chan error, 1)
	go func() {
		_, err := server.syncAccountQuota(context.Background(), accountID)
		syncDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("quota sync did not start")
	}
	deleteDone := make(chan error, 1)
	go func() {
		_, err := server.deleteAccount(context.Background(), accountID)
		deleteDone <- err
	}()
	select {
	case err := <-deleteDone:
		t.Fatalf("account deletion returned while quota sync still used credentials: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-syncDone; err != nil {
		t.Fatal(err)
	}
	if err := <-deleteDone; err != nil {
		t.Fatal(err)
	}
	var active int
	var access, plan, quotaError string
	var used float64
	var updatedAt int64
	if err := store.db.QueryRow(`SELECT active,access_token_enc,plan_type,quota_5h_used,quota_updated_at,quota_error FROM accounts WHERE id=?`, accountID).
		Scan(&active, &access, &plan, &used, &updatedAt, &quotaError); err != nil {
		t.Fatal(err)
	}
	if active != 0 || access != "" || plan != "" || used != -1 || updatedAt != 0 || quotaError != "" {
		t.Fatalf("deleted quota tombstone was polluted: active=%d access=%q plan=%q used=%v updated=%d error=%q", active, access, plan, used, updatedAt, quotaError)
	}
	callsMu.Lock()
	callsBefore := calls
	callsMu.Unlock()
	if _, err := server.syncAccountQuota(context.Background(), accountID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("quota sync after deletion error=%v", err)
	}
	callsMu.Lock()
	callsAfter := calls
	callsMu.Unlock()
	if callsAfter != callsBefore {
		t.Fatalf("quota request used credentials after deletion: before=%d after=%d", callsBefore, callsAfter)
	}
}

func TestAccountDeleteWaitsForQuotaResetAndClearsFollowupSync(t *testing.T) {
	server, store := testApp(t)
	accountID := createTestAccount(t, store, "quota-reset-delete", "quota-reset-delete-access", "acct-quota-reset-delete")
	server.cfg.QuotaBaseURL = "https://quota.example"
	started := make(chan struct{})
	release := make(chan struct{})
	server.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.Method + " " + request.URL.Path {
		case "POST /rate-limit-reset-credits/consume":
			close(started)
			<-release
			return jsonResponse(http.StatusOK, `{"code":"success","windows_reset":2}`), nil
		case "GET /usage":
			return jsonResponse(http.StatusOK, `{"plan_type":"plus","rate_limit":{"allowed":true,"primary_window":{"used_percent":1,"limit_window_seconds":18000}}}`), nil
		case "GET /rate-limit-reset-credits":
			return jsonResponse(http.StatusOK, `{"available_count":0}`), nil
		default:
			return jsonResponse(http.StatusNotFound, `{}`), nil
		}
	})}
	resetDone := make(chan error, 1)
	go func() {
		_, err := server.resetAccountQuota(context.Background(), accountID)
		resetDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("quota reset did not start")
	}
	deleteDone := make(chan error, 1)
	go func() {
		_, err := server.deleteAccount(context.Background(), accountID)
		deleteDone <- err
	}()
	select {
	case err := <-deleteDone:
		t.Fatalf("account deletion returned while quota reset still used credentials: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-resetDone; err != nil {
		t.Fatal(err)
	}
	if err := <-deleteDone; err != nil {
		t.Fatal(err)
	}
	var plan, quotaError string
	var used float64
	if err := store.db.QueryRow(`SELECT plan_type,quota_5h_used,quota_error FROM accounts WHERE id=?`, accountID).Scan(&plan, &used, &quotaError); err != nil {
		t.Fatal(err)
	}
	if plan != "" || used != -1 || quotaError != "" {
		t.Fatalf("quota reset follow-up polluted deleted account: plan=%q used=%v error=%q", plan, used, quotaError)
	}
}

func jsonNumber(value int64) string {
	buffer := bytes.NewBuffer(nil)
	_ = json.NewEncoder(buffer).Encode(value)
	return strings.TrimSpace(buffer.String())
}

func TestParseQuotaResetCreditsIgnoresNullAndFilteredRecords(t *testing.T) {
	count, expirations, ok := parseQuotaResetCredits([]byte(`{"credits":[null,{"status":"redeemed"},{"reset_type":"other","status":"available"},{"status":"available","expiresAt":"soon"}]}`))
	if !ok || count != 1 || len(expirations) != 1 || expirations[0] != "soon" {
		t.Fatalf("count=%d expirations=%v ok=%v", count, expirations, ok)
	}
}

func TestResetCreditExpirationsSortSoonestFirst(t *testing.T) {
	raw := []byte(`{"credits":[
		{"status":"available","expires_at":"2026-07-04T04:05:06Z"},
		{"status":"available","expiresAt":"2026-07-02T04:05:06Z"},
		{"status":"available","expires_at":"2026-07-03T04:05:06Z"}
	]}`)
	count, expirations, ok := parseQuotaResetCredits(raw)
	if !ok || count != 3 {
		t.Fatalf("count=%d expirations=%v ok=%v", count, expirations, ok)
	}
	want := []string{"2026-07-02T04:05:06Z", "2026-07-03T04:05:06Z", "2026-07-04T04:05:06Z"}
	if strings.Join(expirations, ",") != strings.Join(want, ",") {
		t.Fatalf("expirations=%v want=%v", expirations, want)
	}
}
