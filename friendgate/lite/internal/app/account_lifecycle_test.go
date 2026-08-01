package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDeleteAccountDestroysCredentialsCancelsRequestsAndKeepsPoolKey(t *testing.T) {
	server, store := testApp(t)
	accountID, key := createTestAccountAndKey(t, store, "account-delete", "sk-fg_account-delete", "203.0.113.70")
	secondID := createTestAccount(t, store, "remaining-account", "remaining-access", "acct-remaining")
	installOfficialManifest(t, store, accountID, `{"models":[{"slug":"gpt-test"}]}`)
	installOfficialManifest(t, store, secondID, `{"models":[{"slug":"gpt-test"}]}`)

	request := httptest.NewRequest(http.MethodPost, "http://gateway.invalid/v1/responses", nil)
	admitted, finish, err := server.beginKeyRequest(request, key.ID, accountID, "203.0.113.70")
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	go func() {
		<-admitted.Context().Done()
		finish()
		close(finished)
	}()

	cancelled, err := server.deleteAccount(context.Background(), accountID)
	if err != nil || cancelled != 1 {
		t.Fatalf("delete cancelled=%d err=%v", cancelled, err)
	}
	select {
	case <-finished:
	default:
		t.Fatal("account deletion returned before its admitted request exited")
	}
	if !errors.Is(context.Cause(admitted.Context()), errAccountAccessRevoked) {
		t.Fatalf("account deletion cancellation cause=%v", context.Cause(admitted.Context()))
	}
	if _, err := store.GetAccount(context.Background(), accountID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted account remained readable: %v", err)
	}
	if err := store.UpdateAccountTokens(context.Background(), accountID, "restored-access", "restored-refresh", time.Now().Add(time.Hour).Unix(), "acct-restored"); !errors.Is(err, ErrNoAccount) {
		t.Fatalf("late token refresh restored deleted account: %v", err)
	}

	var active int
	var access, refresh, chatGPTID, clientID string
	if err := store.db.QueryRow(`SELECT active,access_token_enc,refresh_token_enc,chatgpt_account_id,client_id FROM accounts WHERE id=?`, accountID).
		Scan(&active, &access, &refresh, &chatGPTID, &clientID); err != nil {
		t.Fatal(err)
	}
	if active != 0 || access != "" || refresh != "" || chatGPTID != "" || clientID != "" {
		t.Fatalf("deleted account retained credentials: active=%d access=%q refresh=%q account=%q client=%q", active, access, refresh, chatGPTID, clientID)
	}
	var affinityCount, modelCount, snapshotCount int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM session_affinities WHERE account_id=?`, accountID).Scan(&affinityCount); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM account_models WHERE account_id=?`, accountID).Scan(&modelCount); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM account_model_snapshots WHERE account_id=?`, accountID).Scan(&snapshotCount); err != nil {
		t.Fatal(err)
	}
	if affinityCount != 0 || modelCount != 0 || snapshotCount != 0 {
		t.Fatalf("deleted account retained routing state: affinities=%d models=%d snapshots=%d", affinityCount, modelCount, snapshotCount)
	}

	seenAuthorization := make(chan string, 1)
	server.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		seenAuthorization <- request.Header.Get("Authorization")
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`data: {"type":"response.completed","response":{"usage":{"total_tokens":1}}}\n\n`)),
			Request:    request,
		}, nil
	})}
	proxyRequest := httptest.NewRequest(http.MethodPost, "http://gateway.invalid/v1/responses", bytes.NewBufferString(`{"model":"gpt-test","input":"continue"}`))
	proxyRequest.RemoteAddr = "203.0.113.70:12345"
	proxyRequest.Header.Set("Authorization", "Bearer sk-fg_account-delete")
	proxyRequest.Header.Set("Content-Type", "application/json")
	proxyRecorder := httptest.NewRecorder()
	server.serveProxy(proxyRecorder, proxyRequest)
	if proxyRecorder.Code != http.StatusOK {
		t.Fatalf("remaining pool account request status=%d body=%s", proxyRecorder.Code, proxyRecorder.Body.String())
	}
	if got := <-seenAuthorization; got != "Bearer remaining-access" {
		t.Fatalf("request did not move to remaining account %d: %q", secondID, got)
	}
}

func TestDisableAccountCancelsInflightAndSameSessionMovesSafely(t *testing.T) {
	server, store := testApp(t)
	accountID, key := createTestAccountAndKey(t, store, "account-disable", "sk-fg_account-disable", "203.0.113.71")
	secondID := createTestAccount(t, store, "remaining-account", "remaining-access", "acct-remaining")
	sessionHash := tokenHash("same-session-after-disable")

	selected, err := store.SelectAccount(context.Background(), key.ID, sessionHash, time.Hour)
	if err != nil || selected.ID != accountID {
		t.Fatalf("initial selection=%+v err=%v", selected, err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://gateway.invalid/v1/responses", nil)
	admitted, finish, err := server.beginKeyRequest(request, key.ID, accountID, "203.0.113.71")
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	go func() {
		<-admitted.Context().Done()
		finish()
		close(finished)
	}()

	cancelled, err := server.updateAccountState(context.Background(), accountID, false)
	if err != nil || cancelled != 1 {
		t.Fatalf("disable cancelled=%d err=%v", cancelled, err)
	}
	select {
	case <-finished:
	default:
		t.Fatal("account disable returned before its admitted request exited")
	}
	if !errors.Is(context.Cause(admitted.Context()), errAccountAccessRevoked) {
		t.Fatalf("account disable cancellation cause=%v", context.Cause(admitted.Context()))
	}
	if _, _, err := server.beginKeyRequest(request, key.ID, accountID, "203.0.113.71"); !errors.Is(err, ErrNoAccount) {
		t.Fatalf("disabled account admitted a new request: %v", err)
	}

	moved, err := store.SelectAccount(context.Background(), key.ID, sessionHash, time.Hour)
	if err != nil || moved.ID != secondID {
		t.Fatalf("same session did not migrate to the remaining live account: selected=%+v err=%v", moved, err)
	}
	var affinityAccountID int64
	if err := store.db.QueryRow(`SELECT account_id FROM session_affinities WHERE key_id=? AND session_hash=?`, key.ID, sessionHash).Scan(&affinityAccountID); err != nil {
		t.Fatal(err)
	}
	if affinityAccountID != secondID {
		t.Fatalf("affinity account=%d want=%d", affinityAccountID, secondID)
	}
}

func TestDisableAccountInterruptsProxyWithTruthfulUnavailableStatus(t *testing.T) {
	server, store := testApp(t)
	accountID, _ := createTestAccountAndKey(t, store, "account-proxy-disable", "sk-fg_account-proxy-disable", "203.0.113.72")
	installOfficialManifest(t, store, accountID, `{"models":[{"slug":"gpt-test"}]}`)
	transportStarted := make(chan struct{})
	server.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		close(transportStarted)
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}

	request := httptest.NewRequest(http.MethodPost, "http://gateway.invalid/v1/responses", bytes.NewBufferString(`{"model":"gpt-test","input":"hello"}`))
	request.RemoteAddr = "203.0.113.72:12345"
	request.Header.Set("Authorization", "Bearer sk-fg_account-proxy-disable")
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		server.serveProxy(recorder, request)
		close(done)
	}()
	select {
	case <-transportStarted:
	case <-time.After(time.Second):
		t.Fatal("proxy never dispatched the admitted request")
	}
	if cancelled, err := server.updateAccountState(context.Background(), accountID, false); err != nil || cancelled != 1 {
		t.Fatalf("disable cancelled=%d err=%v", cancelled, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("proxy did not stop before account disable returned")
	}
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "account_unavailable") || strings.Contains(recorder.Body.String(), "key_inactive") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	usage, err := store.ListUsage(context.Background(), 10)
	if err != nil || len(usage) != 1 || usage[0].Status != http.StatusServiceUnavailable || usage[0].Error != "ChatGPT account access revoked by administrator" {
		t.Fatalf("usage=%+v err=%v", usage, err)
	}
	account, err := store.GetAccount(context.Background(), accountID)
	if err != nil || account.LastError != "" {
		t.Fatalf("administrative account disable marked upstream unhealthy: account=%+v err=%v", account, err)
	}
}

type accountSSEBody struct {
	ctx     context.Context
	payload []byte
	offset  int
}

func (body *accountSSEBody) Read(target []byte) (int, error) {
	if body.offset < len(body.payload) {
		written := copy(target, body.payload[body.offset:])
		body.offset += written
		return written, nil
	}
	<-body.ctx.Done()
	return 0, body.ctx.Err()
}

func (body *accountSSEBody) Close() error { return nil }

func TestDisableAccountAfterSSEHeadersPreservesStreamAndRecordsCause(t *testing.T) {
	server, store := testApp(t)
	accountID, _ := createTestAccountAndKey(t, store, "account-sse-disable", "sk-fg_account-sse-disable", "203.0.113.73")
	installOfficialManifest(t, store, accountID, `{"models":[{"slug":"gpt-test"}]}`)
	payload := []byte("data: {\"type\":\"response.created\"}\n\n")
	server.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:       &accountSSEBody{ctx: request.Context(), payload: payload},
			Request:    request,
		}, nil
	})}

	request := httptest.NewRequest(http.MethodPost, "http://gateway.invalid/v1/responses", bytes.NewBufferString(`{"model":"gpt-test","input":"hello"}`))
	request.RemoteAddr = "203.0.113.73:12345"
	request.Header.Set("Authorization", "Bearer sk-fg_account-sse-disable")
	request.Header.Set("Content-Type", "application/json")
	recorder := &streamingRecorder{ResponseRecorder: httptest.NewRecorder(), wrote: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		server.serveProxy(recorder, request)
		close(done)
	}()
	select {
	case <-recorder.wrote:
	case <-time.After(time.Second):
		t.Fatal("SSE response did not start")
	}
	if cancelled, err := server.updateAccountState(context.Background(), accountID, false); err != nil || cancelled != 1 {
		t.Fatalf("disable cancelled=%d err=%v", cancelled, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SSE proxy did not finish before account disable returned")
	}
	if recorder.Code != http.StatusOK || recorder.Body.String() != string(payload) {
		t.Fatalf("started SSE stream was corrupted: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	usage, err := store.ListUsage(context.Background(), 10)
	if err != nil || len(usage) != 1 || usage[0].Status != http.StatusOK || usage[0].Error != "ChatGPT account access revoked by administrator" {
		t.Fatalf("usage=%+v err=%v", usage, err)
	}
	account, err := store.GetAccount(context.Background(), accountID)
	if err != nil || account.LastError != "" {
		t.Fatalf("administrative SSE cancellation marked upstream unhealthy: account=%+v err=%v", account, err)
	}
}
