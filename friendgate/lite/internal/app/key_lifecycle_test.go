package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type blockingJSONResponseWriter struct {
	header        http.Header
	started       chan struct{}
	release       chan struct{}
	writeDone     chan struct{}
	startedOnce   sync.Once
	writeDoneOnce sync.Once
	mu            sync.Mutex
	status        int
	body          bytes.Buffer
}

func newBlockingJSONResponseWriter() *blockingJSONResponseWriter {
	return &blockingJSONResponseWriter{
		header:    make(http.Header),
		started:   make(chan struct{}),
		release:   make(chan struct{}),
		writeDone: make(chan struct{}),
	}
}

func (w *blockingJSONResponseWriter) Header() http.Header { return w.header }

func (w *blockingJSONResponseWriter) WriteHeader(status int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.status == 0 {
		w.status = status
	}
}

func (w *blockingJSONResponseWriter) Write(value []byte) (int, error) {
	w.startedOnce.Do(func() { close(w.started) })
	<-w.release
	w.mu.Lock()
	if w.status == 0 {
		w.status = http.StatusOK
	}
	written, err := w.body.Write(value)
	w.mu.Unlock()
	w.writeDoneOnce.Do(func() { close(w.writeDone) })
	return written, err
}

func (w *blockingJSONResponseWriter) Status() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status
}

func (w *blockingJSONResponseWriter) BodyString() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.body.String()
}

func TestDisableInterruptsReverseProxyWithoutFalseUpstreamFailure(t *testing.T) {
	server, store := testApp(t)
	accountID, key := createTestAccountAndKey(t, store, "stream-cancel", "sk-fg_stream-cancel", "203.0.113.39")
	installOfficialManifest(t, store, accountID, `{"models":[{"slug":"gpt-test"}]}`)
	transportStarted := make(chan struct{})
	server.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		close(transportStarted)
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}

	request := httptest.NewRequest(http.MethodPost, "http://gateway.invalid/v1/responses", bytes.NewBufferString(`{"model":"gpt-test","input":"hello"}`))
	request.RemoteAddr = "203.0.113.39:12345"
	request.Header.Set("Authorization", "Bearer sk-fg_stream-cancel")
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
	if cancelled, err := server.updateAPIKeyState(context.Background(), key.ID, "disabled", 2); err != nil || cancelled != 1 {
		t.Fatalf("disable cancelled=%d err=%v", cancelled, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reverse proxy did not stop after disable returned")
	}
	if recorder.Code != http.StatusUnauthorized || !strings.Contains(recorder.Body.String(), "key_inactive") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	account, err := store.GetAccount(context.Background(), accountID)
	if err != nil {
		t.Fatal(err)
	}
	if account.LastError != "" {
		t.Fatalf("administrative cancellation was recorded as an upstream account failure: %q", account.LastError)
	}
	usage, err := store.ListUsage(context.Background(), 10)
	if err != nil || len(usage) != 1 || usage[0].Status != http.StatusUnauthorized || usage[0].Error != "key access revoked by administrator" {
		t.Fatalf("usage=%+v err=%v", usage, err)
	}
}

func TestKeyDisableCancelsInflightAndFormsStrictBoundary(t *testing.T) {
	server, store := testApp(t)
	accountID, key := createTestAccountAndKey(t, store, "disable-boundary", "sk-fg_disable-boundary", "203.0.113.40")

	request := httptest.NewRequest("POST", "http://gateway.invalid/v1/responses", nil)
	admitted, finish, err := server.beginKeyRequest(request, key.ID, accountID, "203.0.113.40")
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	go func() {
		<-admitted.Context().Done()
		finish()
		close(finished)
	}()

	cancelled, err := server.updateAPIKeyState(context.Background(), key.ID, "disabled", 2)
	if err != nil {
		t.Fatal(err)
	}
	if cancelled != 1 {
		t.Fatalf("cancelled=%d, want 1", cancelled)
	}
	select {
	case <-admitted.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("in-flight request was not cancelled before disable returned")
	}
	select {
	case <-finished:
	default:
		t.Fatal("disable returned before the in-flight request finished")
	}

	usedBefore := keyUsedRequests(t, store, key.ID)
	if _, nextFinish, nextErr := server.beginKeyRequest(request, key.ID, accountID, "203.0.113.40"); !errors.Is(nextErr, ErrKeyInactive) {
		nextFinish()
		t.Fatalf("new request after disable error=%v", nextErr)
	}
	if usedAfter := keyUsedRequests(t, store, key.ID); usedAfter != usedBefore {
		t.Fatalf("disabled request changed quota: before=%d after=%d", usedBefore, usedAfter)
	}

	if _, err := server.updateAPIKeyState(context.Background(), key.ID, "active", 2); err != nil {
		t.Fatal(err)
	}
	if _, resumedFinish, err := server.beginKeyRequest(request, key.ID, accountID, "203.0.113.40"); err != nil {
		t.Fatalf("request did not resume after re-enable: %v", err)
	} else {
		resumedFinish()
	}
}

func TestKeyIPRemovalCancelsInflightAndRechecksACL(t *testing.T) {
	server, store := testApp(t)
	accountID, key := createTestAccountAndKey(t, store, "ip-boundary", "sk-fg_ip-boundary", "203.0.113.41")
	keys, err := store.ListAPIKeys(context.Background())
	if err != nil || len(keys) != 1 || len(keys[0].AllowedIPs) != 1 {
		t.Fatalf("keys=%+v err=%v", keys, err)
	}

	request := httptest.NewRequest("POST", "http://gateway.invalid/v1/responses", nil)
	admitted, finish, err := server.beginKeyRequest(request, key.ID, accountID, "203.0.113.41")
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	go func() {
		<-admitted.Context().Done()
		finish()
		close(finished)
	}()
	cancelled, err := server.deleteKeyIP(context.Background(), key.ID, keys[0].AllowedIPs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if cancelled != 1 {
		t.Fatalf("cancelled=%d, want 1", cancelled)
	}
	select {
	case <-admitted.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("in-flight request was not cancelled after ACL removal")
	}
	select {
	case <-finished:
	default:
		t.Fatal("ACL removal returned before the in-flight request finished")
	}
	if _, nextFinish, nextErr := server.beginKeyRequest(request, key.ID, accountID, "203.0.113.41"); !errors.Is(nextErr, ErrIPNotAllowed) {
		nextFinish()
		t.Fatalf("request after ACL removal error=%v", nextErr)
	}
}

func TestKeySoftDeleteDestroysSecretsButPreservesUsageAuditJoin(t *testing.T) {
	server, store := testApp(t)
	accountID, key := createTestAccountAndKey(t, store, "delete-boundary", "sk-fg_delete-boundary", "203.0.113.42")
	if err := store.LogUsage(context.Background(), key.ID, accountID, UsageLog{IP: "203.0.113.42", Method: "POST", Path: "/v1/responses", Model: "gpt-test", Status: 200}); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest("POST", "http://gateway.invalid/v1/responses", nil)
	admitted, finish, err := server.beginKeyRequest(request, key.ID, accountID, "203.0.113.42")
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	go func() {
		<-admitted.Context().Done()
		finish()
		close(finished)
	}()
	cancelled, err := server.deleteAPIKey(context.Background(), key.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cancelled != 1 {
		t.Fatalf("cancelled=%d, want 1", cancelled)
	}
	select {
	case <-admitted.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("in-flight request was not cancelled after delete")
	}
	select {
	case <-finished:
	default:
		t.Fatal("delete returned before the in-flight request finished")
	}

	if _, err := store.AuthorizeKey(context.Background(), "sk-fg_delete-boundary", "203.0.113.42"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted key authorization error=%v", err)
	}
	if _, err := store.CopyAPIKey(context.Background(), key.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted key copy error=%v", err)
	}
	if err := store.AddKeyIP(context.Background(), key.ID, "203.0.113.99", "must fail"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("add IP to deleted key error=%v", err)
	}
	if items, err := store.ListAPIKeys(context.Background()); err != nil || len(items) != 0 {
		t.Fatalf("deleted key leaked into list: %+v err=%v", items, err)
	}

	var status, encrypted, masked string
	var aclCount, affinityCount int
	if err := store.db.QueryRow(`SELECT status,key_enc,masked_key,
		(SELECT COUNT(*) FROM key_ips WHERE key_id=api_keys.id),
		(SELECT COUNT(*) FROM session_affinities WHERE key_id=api_keys.id)
		FROM api_keys WHERE id=?`, key.ID).Scan(&status, &encrypted, &masked, &aclCount, &affinityCount); err != nil {
		t.Fatal(err)
	}
	if status != "deleted" || encrypted != "" || masked != "deleted" || aclCount != 0 || affinityCount != 0 {
		t.Fatalf("tombstone status=%q encrypted=%q masked=%q acl=%d affinity=%d", status, encrypted, masked, aclCount, affinityCount)
	}
	usage, err := store.ListUsage(context.Background(), 10)
	if err != nil || len(usage) != 1 || usage[0].Role != "delete-boundary" {
		t.Fatalf("historical usage=%+v err=%v", usage, err)
	}
}

func TestDeletedKeyCannotRecreateSessionAffinity(t *testing.T) {
	_, store := testApp(t)
	_, key := createTestAccountAndKey(t, store, "affinity-tombstone", "sk-fg_affinity-tombstone", "203.0.113.43")
	if _, err := store.SelectAccount(context.Background(), key.ID, tokenHash("before-delete"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteAPIKey(context.Background(), key.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SelectAccount(context.Background(), key.ID, tokenHash("after-delete"), time.Hour); !errors.Is(err, ErrKeyInactive) {
		t.Fatalf("deleted key account selection error=%v", err)
	}
	var affinities int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM session_affinities WHERE key_id=?`, key.ID).Scan(&affinities); err != nil {
		t.Fatal(err)
	}
	if affinities != 0 {
		t.Fatalf("deleted key recreated %d affinity rows", affinities)
	}
}

func TestDeleteAndAccountSelectionCannotLeaveAffinity(t *testing.T) {
	_, store := testApp(t)
	_, key := createTestAccountAndKey(t, store, "affinity-delete-race", "sk-fg_affinity-delete-race", "203.0.113.44")
	const workers = 16
	start := make(chan struct{})
	done := make(chan struct{}, workers)
	for worker := 0; worker < workers; worker++ {
		go func(worker int) {
			<-start
			_, err := store.SelectAccount(context.Background(), key.ID, tokenHash(fmt.Sprintf("race-%d", worker)), time.Hour)
			if err != nil && !errors.Is(err, ErrKeyInactive) {
				t.Errorf("SelectAccount error=%v", err)
			}
			done <- struct{}{}
		}(worker)
	}
	close(start)
	if err := store.DeleteAPIKey(context.Background(), key.ID); err != nil {
		t.Fatal(err)
	}
	for worker := 0; worker < workers; worker++ {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("account selection race did not finish")
		}
	}
	var affinities int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM session_affinities WHERE key_id=?`, key.ID).Scan(&affinities); err != nil {
		t.Fatal(err)
	}
	if affinities != 0 {
		t.Fatalf("delete race left %d affinity rows", affinities)
	}
}

type streamingRecorder struct {
	*httptest.ResponseRecorder
	wrote chan struct{}
	seen  bool
}

func (w *streamingRecorder) Write(value []byte) (int, error) {
	if !w.seen {
		w.seen = true
		close(w.wrote)
	}
	return w.ResponseRecorder.Write(value)
}

func (w *streamingRecorder) Flush() { w.ResponseRecorder.Flush() }

func TestDisableAfterSSEHeadersPreservesStreamAndUsage(t *testing.T) {
	server, store := testApp(t)
	accountID, key := createTestAccountAndKey(t, store, "sse-boundary", "sk-fg_sse-boundary", "203.0.113.45")
	installOfficialManifest(t, store, accountID, `{"models":[{"slug":"gpt-test"}]}`)
	releaseUpstream := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: {\"type\":\"response.created\"}\n\n"))
		w.(http.Flusher).Flush()
		<-releaseUpstream
	}))
	t.Cleanup(func() {
		close(releaseUpstream)
		upstream.Close()
	})
	server.cfg.UpstreamBaseURL = upstream.URL

	request := httptest.NewRequest(http.MethodPost, "http://gateway.invalid/v1/responses", bytes.NewBufferString(`{"model":"gpt-test","input":"hello"}`))
	request.RemoteAddr = "203.0.113.45:12345"
	request.Header.Set("Authorization", "Bearer sk-fg_sse-boundary")
	request.Header.Set("Content-Type", "application/json")
	recorder := &streamingRecorder{ResponseRecorder: httptest.NewRecorder(), wrote: make(chan struct{})}
	proxyDone := make(chan struct{})
	go func() {
		server.serveProxy(recorder, request)
		close(proxyDone)
	}()
	select {
	case <-recorder.wrote:
	case <-time.After(2 * time.Second):
		t.Fatal("SSE response did not start")
	}
	if cancelled, err := server.updateAPIKeyState(context.Background(), key.ID, "disabled", 0); err != nil || cancelled != 1 {
		t.Fatalf("disable cancelled=%d err=%v", cancelled, err)
	}
	select {
	case <-proxyDone:
	case <-time.After(time.Second):
		t.Fatal("SSE proxy did not finish before disable returned")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("stream status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "response.created") || strings.Contains(body, "internal_error") || strings.Contains(body, "key_inactive") {
		t.Fatalf("SSE body was corrupted: %q", body)
	}
	usage, err := store.ListUsage(context.Background(), 10)
	if err != nil || len(usage) != 1 || usage[0].Error != "key access revoked by administrator" {
		t.Fatalf("usage=%+v err=%v", usage, err)
	}
	account, err := store.GetAccount(context.Background(), accountID)
	if err != nil {
		t.Fatal(err)
	}
	if account.LastError != "" {
		t.Fatalf("SSE cancellation marked account unhealthy: %q", account.LastError)
	}
}

func TestAdminCopyResponseWritePrecedesConcurrentKeyDelete(t *testing.T) {
	server, store := testApp(t)
	_, key := createTestAccountAndKey(t, store, "copy-delete-response", "sk-fg_copy-delete-response", "203.0.113.46")
	adminIP, session, csrf := createLifecycleAdminSession(t, store)
	handler := server.adminHandler()

	copyRequest := newLifecycleAdminRequest(http.MethodPost, "http://admin.local/api/keys/"+strconv.FormatInt(key.ID, 10)+"/copy", "", adminIP, session, csrf)
	copyWriter := newBlockingJSONResponseWriter()
	copyDone := make(chan struct{})
	go func() {
		handler.ServeHTTP(copyWriter, copyRequest)
		close(copyDone)
	}()
	waitLifecycleSignal(t, copyWriter.started, "copy response did not start")
	if status := copyWriter.Status(); status != http.StatusOK {
		close(copyWriter.release)
		waitLifecycleSignal(t, copyDone, "failed copy handler did not return")
		t.Fatalf("copy status=%d body=%s", status, copyWriter.BodyString())
	}

	deleteRequest := newLifecycleAdminRequest(http.MethodDelete, "http://admin.local/api/keys/"+strconv.FormatInt(key.ID, 10), "", adminIP, session, csrf)
	deleteRecorder := httptest.NewRecorder()
	type deleteResult struct {
		writeFinished bool
	}
	deleteStarted := make(chan struct{})
	deleteDone := make(chan deleteResult, 1)
	go func() {
		close(deleteStarted)
		handler.ServeHTTP(deleteRecorder, deleteRequest)
		result := deleteResult{}
		select {
		case <-copyWriter.writeDone:
			result.writeFinished = true
		default:
		}
		deleteDone <- result
	}()
	waitLifecycleSignal(t, deleteStarted, "delete request did not start")
	assertLifecycleStillBlocked(t, deleteDone, "key delete returned while the older copy response write was blocked")
	close(copyWriter.release)
	waitLifecycleSignal(t, copyDone, "copy handler did not finish")

	var deleted deleteResult
	select {
	case deleted = <-deleteDone:
	case <-time.After(2 * time.Second):
		t.Fatal("key delete did not finish after copy response was released")
	}
	if !deleted.writeFinished {
		t.Fatal("key delete returned before the older plaintext copy was written")
	}
	if deleteRecorder.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", deleteRecorder.Code, deleteRecorder.Body.String())
	}
	if !strings.Contains(copyWriter.BodyString(), "sk-fg_copy-delete-response") {
		t.Fatalf("copy response lost plaintext: %s", copyWriter.BodyString())
	}
	if _, err := store.CopyAPIKey(context.Background(), key.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("post-delete copy error=%v", err)
	}
}

func TestInvitationRevealResponseWritePrecedesConcurrentKeyDelete(t *testing.T) {
	server, store := testApp(t)
	role := "reveal-delete-response"
	ip := "203.0.113.47"
	_, key := createTestAccountAndKey(t, store, role, "sk-fg_reveal-delete-response", ip)
	token := "invite-token-that-is-long-" + role
	claim := "claim-session-that-is-long-" + role

	revealRequest := httptest.NewRequest(http.MethodGet, "http://invite.local/api/invitations/"+token+"/key", nil)
	revealRequest.RemoteAddr = ip + ":34000"
	revealRequest.AddCookie(&http.Cookie{Name: claimCookieName, Value: claim})
	revealWriter := newBlockingJSONResponseWriter()
	revealDone := make(chan struct{})
	go func() {
		server.inviteHandler().ServeHTTP(revealWriter, revealRequest)
		close(revealDone)
	}()
	waitLifecycleSignal(t, revealWriter.started, "reveal response did not start")
	if status := revealWriter.Status(); status != http.StatusOK {
		close(revealWriter.release)
		waitLifecycleSignal(t, revealDone, "failed reveal handler did not return")
		t.Fatalf("reveal status=%d body=%s", status, revealWriter.BodyString())
	}

	type deleteResult struct {
		err           error
		writeFinished bool
	}
	deleteStarted := make(chan struct{})
	deleteDone := make(chan deleteResult, 1)
	go func() {
		close(deleteStarted)
		_, err := server.deleteAPIKey(context.Background(), key.ID)
		result := deleteResult{err: err}
		select {
		case <-revealWriter.writeDone:
			result.writeFinished = true
		default:
		}
		deleteDone <- result
	}()
	waitLifecycleSignal(t, deleteStarted, "key delete did not start")
	assertLifecycleStillBlocked(t, deleteDone, "key delete returned while the older invitation reveal was blocked")
	close(revealWriter.release)
	waitLifecycleSignal(t, revealDone, "reveal handler did not finish")

	var deleted deleteResult
	select {
	case deleted = <-deleteDone:
	case <-time.After(2 * time.Second):
		t.Fatal("key delete did not finish after reveal response was released")
	}
	if deleted.err != nil || !deleted.writeFinished {
		t.Fatalf("delete err=%v write_finished=%v", deleted.err, deleted.writeFinished)
	}
	if !strings.Contains(revealWriter.BodyString(), "sk-fg_reveal-delete-response") {
		t.Fatalf("reveal response lost plaintext: %s", revealWriter.BodyString())
	}

	after := httptest.NewRequest(http.MethodGet, "http://invite.local/api/invitations/"+token+"/key", nil)
	after.RemoteAddr = ip + ":34000"
	after.AddCookie(&http.Cookie{Name: claimCookieName, Value: claim})
	afterRecorder := httptest.NewRecorder()
	server.inviteHandler().ServeHTTP(afterRecorder, after)
	if afterRecorder.Code != http.StatusGone {
		t.Fatalf("post-delete reveal status=%d body=%s", afterRecorder.Code, afterRecorder.Body.String())
	}
}

func TestInvitationRevealResponseWritePrecedesConcurrentInvitationDelete(t *testing.T) {
	server, store := testApp(t)
	role := "reveal-invitation-delete-response"
	ip := "203.0.113.50"
	_, key := createTestAccountAndKey(t, store, role, "sk-fg_reveal-invitation-delete", ip)
	token := "invite-token-that-is-long-" + role
	claim := "claim-session-that-is-long-" + role
	items, err := store.ListInvitations(context.Background())
	if err != nil || len(items) != 1 {
		t.Fatalf("invitations=%+v err=%v", items, err)
	}

	revealRequest := httptest.NewRequest(http.MethodGet, "http://invite.local/api/invitations/"+token+"/key", nil)
	revealRequest.RemoteAddr = ip + ":34000"
	revealRequest.AddCookie(&http.Cookie{Name: claimCookieName, Value: claim})
	revealWriter := newBlockingJSONResponseWriter()
	revealDone := make(chan struct{})
	go func() {
		server.inviteHandler().ServeHTTP(revealWriter, revealRequest)
		close(revealDone)
	}()
	waitLifecycleSignal(t, revealWriter.started, "reveal response did not start")
	if status := revealWriter.Status(); status != http.StatusOK {
		close(revealWriter.release)
		waitLifecycleSignal(t, revealDone, "failed reveal handler did not return")
		t.Fatalf("reveal status=%d body=%s", status, revealWriter.BodyString())
	}

	type deleteResult struct {
		err           error
		writeFinished bool
	}
	deleteStarted := make(chan struct{})
	deleteDone := make(chan deleteResult, 1)
	go func() {
		close(deleteStarted)
		err := server.deleteInvitation(context.Background(), items[0].ID)
		result := deleteResult{err: err}
		select {
		case <-revealWriter.writeDone:
			result.writeFinished = true
		default:
		}
		deleteDone <- result
	}()
	waitLifecycleSignal(t, deleteStarted, "invitation delete did not start")
	assertLifecycleStillBlocked(t, deleteDone, "invitation delete returned while the older reveal response was blocked")
	close(revealWriter.release)
	waitLifecycleSignal(t, revealDone, "reveal handler did not finish")

	var deleted deleteResult
	select {
	case deleted = <-deleteDone:
	case <-time.After(2 * time.Second):
		t.Fatal("invitation delete did not finish after reveal response was released")
	}
	if deleted.err != nil || !deleted.writeFinished {
		t.Fatalf("delete err=%v write_finished=%v", deleted.err, deleted.writeFinished)
	}
	if _, err := store.PublicInvitation(context.Background(), token); !errors.Is(err, ErrInvalidInvite) {
		t.Fatalf("deleted invitation remained public: %v", err)
	}
	if _, err := store.AuthorizeKey(context.Background(), "sk-fg_reveal-invitation-delete", ip); err != nil {
		t.Fatalf("invitation deletion unexpectedly disabled key %d: %v", key.ID, err)
	}
}

func TestInvitationGenerateResponseWritePrecedesConcurrentInvitationDelete(t *testing.T) {
	server, store := testApp(t)
	createTestAccount(t, store, "generate-delete-account", "access", "acct-generate-delete")
	token := "generate-delete-invitation-token-long-enough"
	claim := "generate-delete-claim-session-long-enough"
	ip := "203.0.113.48"
	invitationID, err := store.CreateInvitation(context.Background(), "generate delete", token, "123456", 0, 0, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyInvitation(context.Background(), token, "123456", ip, claim, "generate-delete-probe-token"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveInviteDevice(context.Background(), token, claim, ip, "generate delete device"); err != nil {
		t.Fatal(err)
	}

	generateRequest := httptest.NewRequest(http.MethodPost, "http://invite.local/api/invitations/"+token+"/generate", strings.NewReader(`{}`))
	generateRequest.RemoteAddr = ip + ":35000"
	generateRequest.Header.Set("Content-Type", "application/json")
	generateRequest.AddCookie(&http.Cookie{Name: claimCookieName, Value: claim})
	generateWriter := newBlockingJSONResponseWriter()
	generateDone := make(chan struct{})
	go func() {
		server.inviteHandler().ServeHTTP(generateWriter, generateRequest)
		close(generateDone)
	}()
	waitLifecycleSignal(t, generateWriter.started, "generate response did not start")
	if status := generateWriter.Status(); status != http.StatusCreated {
		close(generateWriter.release)
		waitLifecycleSignal(t, generateDone, "failed generate handler did not return")
		t.Fatalf("generate status=%d body=%s", status, generateWriter.BodyString())
	}

	type deleteResult struct {
		err           error
		writeFinished bool
	}
	deleteStarted := make(chan struct{})
	deleteDone := make(chan deleteResult, 1)
	go func() {
		close(deleteStarted)
		err := server.deleteInvitation(context.Background(), invitationID)
		result := deleteResult{err: err}
		select {
		case <-generateWriter.writeDone:
			result.writeFinished = true
		default:
		}
		deleteDone <- result
	}()
	waitLifecycleSignal(t, deleteStarted, "invitation delete did not start")
	assertLifecycleStillBlocked(t, deleteDone, "invitation delete returned while the older key generation response was blocked")
	close(generateWriter.release)
	waitLifecycleSignal(t, generateDone, "generate handler did not finish")

	var deleted deleteResult
	select {
	case deleted = <-deleteDone:
	case <-time.After(2 * time.Second):
		t.Fatal("invitation delete did not finish after generate response was released")
	}
	if deleted.err != nil || !deleted.writeFinished {
		t.Fatalf("delete err=%v write_finished=%v", deleted.err, deleted.writeFinished)
	}
	var generated struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal([]byte(generateWriter.BodyString()), &generated); err != nil || generated.Key == "" {
		t.Fatalf("generated payload=%s err=%v", generateWriter.BodyString(), err)
	}
	if _, err := store.PublicInvitation(context.Background(), token); !errors.Is(err, ErrInvalidInvite) {
		t.Fatalf("deleted invitation remained public: %v", err)
	}
	if _, err := store.AuthorizeKey(context.Background(), generated.Key, ip); err != nil {
		t.Fatalf("deleting used invitation unexpectedly deleted its generated key: %v", err)
	}
}

func TestInvitationGenerateResponseWritePrecedesConcurrentKeyDelete(t *testing.T) {
	server, store := testApp(t)
	createTestAccount(t, store, "generate-key-delete-account", "access", "acct-generate-key-delete")
	token := "generate-key-delete-invitation-token-long-enough"
	claim := "generate-key-delete-claim-session-long-enough"
	ip := "203.0.113.51"
	invitationID, err := store.CreateInvitation(context.Background(), "generate key delete", token, "123456", 0, 0, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyInvitation(context.Background(), token, "123456", ip, claim, "generate-key-delete-probe-token"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveInviteDevice(context.Background(), token, claim, ip, "generate key delete device"); err != nil {
		t.Fatal(err)
	}

	generateRequest := httptest.NewRequest(http.MethodPost, "http://invite.local/api/invitations/"+token+"/generate", strings.NewReader(`{}`))
	generateRequest.RemoteAddr = ip + ":35000"
	generateRequest.Header.Set("Content-Type", "application/json")
	generateRequest.AddCookie(&http.Cookie{Name: claimCookieName, Value: claim})
	generateWriter := newBlockingJSONResponseWriter()
	generateDone := make(chan struct{})
	go func() {
		server.inviteHandler().ServeHTTP(generateWriter, generateRequest)
		close(generateDone)
	}()
	waitLifecycleSignal(t, generateWriter.started, "generate response did not start")
	if status := generateWriter.Status(); status != http.StatusCreated {
		close(generateWriter.release)
		waitLifecycleSignal(t, generateDone, "failed generate handler did not return")
		t.Fatalf("generate status=%d body=%s", status, generateWriter.BodyString())
	}
	var keyID int64
	if err := store.db.QueryRow("SELECT api_key_id FROM invitations WHERE id=?", invitationID).Scan(&keyID); err != nil || keyID == 0 {
		close(generateWriter.release)
		waitLifecycleSignal(t, generateDone, "generate handler did not return after lookup failure")
		t.Fatalf("generated key id=%d err=%v", keyID, err)
	}

	type deleteResult struct {
		err           error
		writeFinished bool
	}
	deleteStarted := make(chan struct{})
	deleteDone := make(chan deleteResult, 1)
	go func() {
		close(deleteStarted)
		_, err := server.deleteAPIKey(context.Background(), keyID)
		result := deleteResult{err: err}
		select {
		case <-generateWriter.writeDone:
			result.writeFinished = true
		default:
		}
		deleteDone <- result
	}()
	waitLifecycleSignal(t, deleteStarted, "key delete did not start")
	assertLifecycleStillBlocked(t, deleteDone, "key delete returned while the older generation response was blocked")
	close(generateWriter.release)
	waitLifecycleSignal(t, generateDone, "generate handler did not finish")

	var deleted deleteResult
	select {
	case deleted = <-deleteDone:
	case <-time.After(2 * time.Second):
		t.Fatal("key delete did not finish after generate response was released")
	}
	if deleted.err != nil || !deleted.writeFinished {
		t.Fatalf("delete err=%v write_finished=%v", deleted.err, deleted.writeFinished)
	}
	var generated struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal([]byte(generateWriter.BodyString()), &generated); err != nil || generated.Key == "" {
		t.Fatalf("generated payload=%s err=%v", generateWriter.BodyString(), err)
	}
	if _, err := store.AuthorizeKey(context.Background(), generated.Key, ip); !errors.Is(err, ErrNotFound) {
		t.Fatalf("generated key remained authorized after deletion: %v", err)
	}
	if _, err := store.PublicInvitation(context.Background(), token); !errors.Is(err, ErrInvalidInvite) {
		t.Fatalf("invitation still exposed a deleted generated key: %v", err)
	}
}

func TestAdminKeyLifecycleRoutesWaitForInflightRequestsAndTakeEffect(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		path        func(*APIKey, []APIKey) string
		body        string
		wantErr     error
		wantAuthErr error
	}{
		{
			name: "disable", method: http.MethodPatch,
			path: func(key *APIKey, _ []APIKey) string { return "/api/keys/" + strconv.FormatInt(key.ID, 10) },
			body: `{"status":"disabled","quota_requests":2}`, wantErr: ErrKeyInactive, wantAuthErr: ErrNotFound,
		},
		{
			name: "delete", method: http.MethodDelete,
			path:    func(key *APIKey, _ []APIKey) string { return "/api/keys/" + strconv.FormatInt(key.ID, 10) },
			wantErr: ErrKeyInactive, wantAuthErr: ErrNotFound,
		},
		{
			name: "remove IP", method: http.MethodDelete,
			path: func(key *APIKey, keys []APIKey) string {
				return "/api/keys/" + strconv.FormatInt(key.ID, 10) + "/ips/" + strconv.FormatInt(keys[0].AllowedIPs[0].ID, 10)
			},
			wantErr: ErrIPNotAllowed, wantAuthErr: ErrIPNotAllowed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, store := testApp(t)
			ip := "203.0.113.49"
			plainKey := "sk-fg_admin-route-" + strings.ReplaceAll(test.name, " ", "-")
			accountID, key := createTestAccountAndKey(t, store, "admin-route-"+test.name, plainKey, ip)
			keys, err := store.ListAPIKeys(context.Background())
			if err != nil || len(keys) != 1 || len(keys[0].AllowedIPs) != 1 {
				t.Fatalf("keys=%+v err=%v", keys, err)
			}
			adminIP, session, csrf := createLifecycleAdminSession(t, store)

			baseRequest := httptest.NewRequest(http.MethodPost, "http://gateway.invalid/v1/responses", nil)
			admitted, finish, err := server.beginKeyRequest(baseRequest, key.ID, accountID, ip)
			if err != nil {
				t.Fatal(err)
			}
			cancelSeen := make(chan struct{})
			allowFinish := make(chan struct{})
			go func() {
				<-admitted.Context().Done()
				close(cancelSeen)
				<-allowFinish
				finish()
			}()

			url := "http://admin.local" + test.path(key, keys)
			request := newLifecycleAdminRequest(test.method, url, test.body, adminIP, session, csrf)
			recorder := httptest.NewRecorder()
			responseDone := make(chan struct{})
			go func() {
				server.adminHandler().ServeHTTP(recorder, request)
				close(responseDone)
			}()
			waitLifecycleSignal(t, cancelSeen, "admin route did not cancel the admitted request")
			assertLifecycleStillBlocked(t, responseDone, "admin route returned before the admitted request exited")
			close(allowFinish)
			waitLifecycleSignal(t, responseDone, "admin route did not return after the admitted request exited")

			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			var response struct {
				CancelledRequests int `json:"cancelled_requests"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || response.CancelledRequests != 1 {
				t.Fatalf("response=%s err=%v", recorder.Body.String(), err)
			}
			if _, nextFinish, err := server.beginKeyRequest(baseRequest, key.ID, accountID, ip); !errors.Is(err, test.wantErr) {
				nextFinish()
				t.Fatalf("post-mutation request error=%v want=%v", err, test.wantErr)
			}
			if _, err := store.AuthorizeKey(context.Background(), plainKey, ip); !errors.Is(err, test.wantAuthErr) {
				t.Fatalf("post-mutation authorization error=%v want=%v", err, test.wantAuthErr)
			}
		})
	}
}

func createLifecycleAdminSession(t *testing.T, store *Store) (ip, session, csrf string) {
	t.Helper()
	const secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	encrypted, err := store.vault.Encrypt(secret, "admin-totp")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteAdminSetup(context.Background(), "lifecycle-admin", "test-password-hash", encrypted, -1); err != nil {
		t.Fatal(err)
	}
	ip = "203.0.113.250"
	session, csrf, err = store.NewAdminSession(context.Background(), ip, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return ip, session, csrf
}

func newLifecycleAdminRequest(method, rawURL, body, ip, session, csrf string) *http.Request {
	request := httptest.NewRequest(method, rawURL, strings.NewReader(body))
	request.RemoteAddr = ip + ":4321"
	request.AddCookie(&http.Cookie{Name: adminCookieName, Value: session})
	request.Header.Set("X-CSRF-Token", csrf)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}

func waitLifecycleSignal(t *testing.T, signal <-chan struct{}, failure string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal(failure)
	}
}

func assertLifecycleStillBlocked[T any](t *testing.T, done <-chan T, failure string) {
	t.Helper()
	select {
	case <-done:
		t.Fatal(failure)
	case <-time.After(75 * time.Millisecond):
	}
}

func TestKeyDeleteCannotReturnBeforeConcurrentPlaintextCopyResponse(t *testing.T) {
	server, store := testApp(t)
	_, key := createTestAccountAndKey(t, store, "copy-delete-boundary", "sk-fg_copy-delete-boundary", "203.0.113.46")
	request := httptest.NewRequest(http.MethodPost, "http://admin.local/api/keys/"+strconv.FormatInt(key.ID, 10)+"/copy", strings.NewReader(`{}`))
	request.SetPathValue("id", strconv.FormatInt(key.ID, 10))
	request.RemoteAddr = "203.0.113.200:41000"
	writer := newBlockingJSONResponseWriter()
	copyDone := make(chan struct{})
	go func() {
		server.adminCopyKey(writer, request)
		close(copyDone)
	}()
	select {
	case <-writer.started:
	case <-time.After(time.Second):
		t.Fatal("copy response did not reach its write boundary")
	}
	deleteDone := make(chan error, 1)
	go func() {
		_, err := server.deleteAPIKey(context.Background(), key.ID)
		deleteDone <- err
	}()
	select {
	case err := <-deleteDone:
		t.Fatalf("delete returned before older plaintext response completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(writer.release)
	select {
	case <-copyDone:
	case <-time.After(time.Second):
		t.Fatal("copy response did not finish")
	}
	if err := <-deleteDone; err != nil {
		t.Fatal(err)
	}
	var payload map[string]string
	if err := json.Unmarshal([]byte(writer.BodyString()), &payload); err != nil || payload["key"] != "sk-fg_copy-delete-boundary" {
		t.Fatalf("copy payload=%q parsed=%+v err=%v", writer.BodyString(), payload, err)
	}
}

func TestInvitationDeleteCannotReturnBeforeConcurrentPlaintextReveal(t *testing.T) {
	server, store := testApp(t)
	role := "reveal-delete-boundary"
	ip := "203.0.113.47"
	_, _ = createTestAccountAndKey(t, store, role, "sk-fg_reveal-delete-boundary", ip)
	token := "invite-token-that-is-long-" + role
	claim := "claim-session-that-is-long-" + role
	items, err := store.ListInvitations(context.Background())
	if err != nil || len(items) != 1 {
		t.Fatalf("invitations=%+v err=%v", items, err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://invite.local/api/invitations/"+token+"/key", nil)
	request.SetPathValue("token", token)
	request.RemoteAddr = ip + ":41001"
	request.AddCookie(&http.Cookie{Name: claimCookieName, Value: claim})
	writer := newBlockingJSONResponseWriter()
	revealDone := make(chan struct{})
	go func() {
		server.inviteRevealKey(writer, request)
		close(revealDone)
	}()
	select {
	case <-writer.started:
	case <-time.After(time.Second):
		t.Fatal("reveal response did not reach its write boundary")
	}
	deleteDone := make(chan error, 1)
	go func() { deleteDone <- server.deleteInvitation(context.Background(), items[0].ID) }()
	select {
	case err := <-deleteDone:
		t.Fatalf("invitation delete returned before older plaintext response completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(writer.release)
	select {
	case <-revealDone:
	case <-time.After(time.Second):
		t.Fatal("reveal response did not finish")
	}
	if err := <-deleteDone; err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(writer.BodyString()), &payload); err != nil || payload["key"] != "sk-fg_reveal-delete-boundary" {
		t.Fatalf("reveal payload=%q parsed=%+v err=%v", writer.BodyString(), payload, err)
	}
	if _, err := store.PublicInvitation(context.Background(), token); !errors.Is(err, ErrInvalidInvite) {
		t.Fatalf("deleted invitation remained public: %v", err)
	}
}

func TestManualIPBanCancelsInflightBeforeAdminSuccess(t *testing.T) {
	server, store := testApp(t)
	targetIP := "203.0.113.48"
	accountID, key := createTestAccountAndKey(t, store, "ban-stream-boundary", "sk-fg_ban-stream-boundary", targetIP)
	request := httptest.NewRequest(http.MethodPost, "http://gateway.invalid/v1/responses", nil)
	admitted, finish, err := server.beginKeyRequest(request, key.ID, accountID, targetIP)
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	go func() {
		<-admitted.Context().Done()
		finish()
		close(finished)
	}()
	body := strings.NewReader(`{"ip":"` + targetIP + `","reason":"test manual ban","permanent":true}`)
	adminRequest := httptest.NewRequest(http.MethodPost, "http://admin.local/api/system/bans", body)
	adminRequest.RemoteAddr = "203.0.113.250:42000"
	recorder := httptest.NewRecorder()
	server.adminBanIP(recorder, adminRequest)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("ban status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	select {
	case <-finished:
	default:
		t.Fatal("manual ban returned success before in-flight request exited")
	}
	if !errors.Is(context.Cause(admitted.Context()), errIPAccessBanned) {
		t.Fatalf("cancel cause=%v", context.Cause(admitted.Context()))
	}
	var payload struct {
		Cancelled int `json:"cancelled_requests"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil || payload.Cancelled != 1 {
		t.Fatalf("ban response=%s parsed=%+v err=%v", recorder.Body.String(), payload, err)
	}
	blocked := httptest.NewRequest(http.MethodGet, "http://gateway.invalid/health", nil)
	blocked.RemoteAddr = targetIP + ":42001"
	blockedRecorder := httptest.NewRecorder()
	server.commonHeaders("api", server.proxyHandler()).ServeHTTP(blockedRecorder, blocked)
	if blockedRecorder.Code != http.StatusForbidden {
		t.Fatalf("banned IP remained able to reach API: status=%d body=%s", blockedRecorder.Code, blockedRecorder.Body.String())
	}
}

func TestFinalAdmissionRechecksBanAfterRequestPassedInitialMiddleware(t *testing.T) {
	server, store := testApp(t)
	targetIP := "203.0.113.88"
	accountID, key := createTestAccountAndKey(t, store, "ban-admission-race", "sk-fg_ban-admission-race", targetIP)
	request := httptest.NewRequest(http.MethodPost, "http://gateway.invalid/v1/responses", nil)

	// Model a request which already passed commonHeaders but is waiting for the
	// same lifecycle mutex while an administrator commits and caches the ban.
	server.keyRequestMu.Lock()
	started := make(chan struct{})
	type admissionResult struct {
		finish func()
		err    error
	}
	result := make(chan admissionResult, 1)
	go func() {
		close(started)
		_, finish, err := server.beginKeyRequest(request, key.ID, accountID, targetIP)
		result <- admissionResult{finish: finish, err: err}
	}()
	<-started
	server.banMu.Lock()
	server.activeBans[targetIP] = activeBan{ExpiresAt: time.Now().Add(time.Hour).Unix(), Scope: "all"}
	server.banMu.Unlock()
	server.keyRequestMu.Unlock()
	admission := <-result
	admission.finish()
	if !errors.Is(admission.err, errIPAccessBanned) {
		t.Fatalf("request admitted after ban boundary: %v", admission.err)
	}
	if used := keyUsedRequests(t, store, key.ID); used != 0 {
		t.Fatalf("banned request consumed quota: %d", used)
	}

	_, finish, err := server.beginKeyMetadataRequest(request, key.ID, targetIP)
	finish()
	if !errors.Is(err, errIPAccessBanned) {
		t.Fatalf("GET /models metadata admission bypassed ban: %v", err)
	}
}

func keyUsedRequests(t *testing.T, store *Store, keyID int64) int64 {
	t.Helper()
	var used int64
	if err := store.db.QueryRow("SELECT used_requests FROM api_keys WHERE id=?", keyID).Scan(&used); err != nil {
		t.Fatal(err)
	}
	return used
}
