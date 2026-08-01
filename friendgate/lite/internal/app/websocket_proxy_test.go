package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type wsUpstreamObservation struct {
	path          string
	authorization string
	accountID     string
	sessionID     string
	firstType     websocket.MessageType
	firstPayload  []byte
	secondType    websocket.MessageType
	secondPayload []byte
	err           error
}

func TestResponsesWebSocketRoutesFirstFrameAndRelaysToolBytes(t *testing.T) {
	server, store := testApp(t)
	firstID, key := createTestAccountAndKey(t, store, "ws-raw", "sk-fg_ws-raw", "127.0.0.1")
	secondID := createTestAccount(t, store, "ws-image", "access-image", "acct-image")
	installOfficialManifest(t, store, firstID, `{"models":[{"slug":"gpt-text"}]}`)
	installOfficialManifest(t, store, secondID, `{"models":[{"slug":"gpt-image","tool_capabilities":{"image_generation":true}}]}`)

	responsePayload := []byte(`{"type":"response.completed","response":{"id":"resp_ws_image","output":[{"type":"image_generation_call","result":"aGVsbG8taW1hZ2U="}],"usage":{"input_tokens":4,"output_tokens":7,"total_tokens":11}}}`)
	binaryResponsePayload := []byte(`{"type":"response.output_item.done","item":{"type":"function_call","name":"lookup","arguments":"{\"opaque\":true}"}}`)
	observed := make(chan wsUpstreamObservation, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observation := wsUpstreamObservation{
			path: r.URL.Path, authorization: r.Header.Get("Authorization"),
			accountID: r.Header.Get("ChatGPT-Account-ID"), sessionID: r.Header.Get("Session_ID"),
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			observation.err = err
			observed <- observation
			return
		}
		defer conn.CloseNow()
		observation.firstType, observation.firstPayload, observation.err = conn.Read(r.Context())
		if observation.err != nil {
			observed <- observation
			return
		}
		if err := conn.Write(r.Context(), websocket.MessageText, responsePayload); err != nil {
			observation.err = err
			observed <- observation
			return
		}
		observation.secondType, observation.secondPayload, observation.err = conn.Read(r.Context())
		observed <- observation
		if observation.err != nil {
			return
		}
		if err := conn.Write(r.Context(), websocket.MessageBinary, binaryResponsePayload); err != nil {
			return
		}
		_ = conn.Close(websocket.StatusNormalClosure, "complete")
	}))
	defer upstream.Close()
	server.cfg.UpstreamBaseURL = upstream.URL + "/backend-api/codex"
	server.client = upstream.Client()

	gateway := httptest.NewServer(server.commonHeaders("api", server.proxyHandler()))
	defer gateway.Close()
	header := http.Header{
		"Authorization": []string{"Bearer sk-fg_ws-raw"},
		"Session_ID":    []string{"client-session-must-be-namespaced"},
	}
	client, response, err := websocket.Dial(context.Background(), strings.Replace(gateway.URL, "http://", "ws://", 1)+"/v1/responses", &websocket.DialOptions{HTTPHeader: header})
	if err != nil {
		if response != nil {
			t.Fatalf("gateway dial status=%d err=%v", response.StatusCode, err)
		}
		t.Fatal(err)
	}
	defer client.CloseNow()
	firstPayload := []byte(`{
  "type":"response.create",
  "tools":[{"type":"function","name":"lookup","parameters":{"type":"object"}},{"type":"image_generation","quality":"high"}],
  "input":[{"role":"user","content":[{"type":"input_image","image_url":"data:image/png;base64,AAECAwQ="}]}],
  "model":"gpt-image",
  "future_field":{"opaque":[true,null,1.25]}
}`)
	if err := client.Write(context.Background(), websocket.MessageBinary, firstPayload); err != nil {
		t.Fatal(err)
	}
	messageType, gotResponse, err := client.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if messageType != websocket.MessageText || !bytes.Equal(gotResponse, responsePayload) {
		t.Fatalf("response frame changed: type=%v\nwant=%s\n got=%s", messageType, responsePayload, gotResponse)
	}
	secondPayload := []byte(`{
  "type":"response.create",
  "model":"gpt-image",
  "input":[{"type":"function_call_output","call_id":"call_opaque","output":"{\"preserve\":[1,true,null]}"}],
  "metadata":{"must_remain_in_order":["a","b"]}
}`)
	if err := client.Write(context.Background(), websocket.MessageText, secondPayload); err != nil {
		t.Fatal(err)
	}
	messageType, gotResponse, err = client.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if messageType != websocket.MessageBinary || !bytes.Equal(gotResponse, binaryResponsePayload) {
		t.Fatalf("binary response frame changed: type=%v\nwant=%s\n got=%s", messageType, binaryResponsePayload, gotResponse)
	}

	select {
	case got := <-observed:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.path != "/backend-api/codex/responses" || got.authorization != "Bearer access-image" || got.accountID != "acct-image" {
			t.Fatalf("upstream routing=%+v", got)
		}
		if got.sessionID == "" || got.sessionID == "client-session-must-be-namespaced" {
			t.Fatalf("session header was not isolated: %q", got.sessionID)
		}
		if got.firstType != websocket.MessageBinary || !bytes.Equal(got.firstPayload, firstPayload) {
			t.Fatalf("first frame changed: type=%v\nwant=%s\n got=%s", got.firstType, firstPayload, got.firstPayload)
		}
		if got.secondType != websocket.MessageText || !bytes.Equal(got.secondPayload, secondPayload) {
			t.Fatalf("second frame changed: type=%v\nwant=%s\n got=%s", got.secondType, secondPayload, got.secondPayload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upstream did not receive WebSocket frame")
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		usage, listErr := store.ListUsage(context.Background(), 10)
		if listErr != nil {
			t.Fatal(listErr)
		}
		if len(usage) > 0 {
			if usage[0].Model != "gpt-image" || usage[0].TotalTokens != 11 || usage[0].AccountName != "ws-image" {
				t.Fatalf("usage=%+v", usage[0])
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("WebSocket usage was not persisted")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if used := keyUsedRequests(t, store, key.ID); used != 1 {
		t.Fatalf("WebSocket quota consumption=%d want=1", used)
	}
}

func TestResponsesWebSocketRejectsUnknownFirstModelBeforeQuotaOrUpstream(t *testing.T) {
	server, store := testApp(t)
	accountID, key := createTestAccountAndKey(t, store, "ws-unknown", "sk-fg_ws-unknown", "127.0.0.1")
	installOfficialManifest(t, store, accountID, `{"models":[{"slug":"gpt-known"}]}`)
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		http.Error(w, "unexpected", http.StatusBadGateway)
	}))
	defer upstream.Close()
	server.cfg.UpstreamBaseURL = upstream.URL + "/backend-api/codex"
	server.client = upstream.Client()
	gateway := httptest.NewServer(server.commonHeaders("api", server.proxyHandler()))
	defer gateway.Close()

	client, _, err := websocket.Dial(context.Background(), strings.Replace(gateway.URL, "http://", "ws://", 1)+"/v1/responses", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer sk-fg_ws-unknown"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseNow()
	if err := client.Write(context.Background(), websocket.MessageText, []byte(`{"type":"response.create","model":"gpt-unknown","tools":[{"type":"image_generation"}]}`)); err != nil {
		t.Fatal(err)
	}
	_, payload, err := client.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(payload, []byte(`"code":"model_not_available"`)) {
		t.Fatalf("error payload=%s", payload)
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("unknown model reached upstream %d time(s)", upstreamCalls.Load())
	}
	if used := keyUsedRequests(t, store, key.ID); used != 0 {
		t.Fatalf("unknown model consumed quota: %d", used)
	}
}

func TestResponsesWebSocketRejectsModelSwitchWithoutMovingAccount(t *testing.T) {
	server, store := testApp(t)
	firstID, _ := createTestAccountAndKey(t, store, "ws-switch", "sk-fg_ws-switch", "127.0.0.1")
	secondID := createTestAccount(t, store, "ws-second", "access-second", "acct-second")
	installOfficialManifest(t, store, firstID, `{"models":[{"slug":"gpt-first"}]}`)
	installOfficialManifest(t, store, secondID, `{"models":[{"slug":"gpt-second"}]}`)
	secondFrameReachedUpstream := make(chan bool, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			secondFrameReachedUpstream <- false
			return
		}
		defer conn.CloseNow()
		if _, _, err = conn.Read(r.Context()); err != nil {
			secondFrameReachedUpstream <- false
			return
		}
		if err = conn.Write(r.Context(), websocket.MessageText, []byte(`{"type":"response.created"}`)); err != nil {
			secondFrameReachedUpstream <- false
			return
		}
		readCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		_, _, err = conn.Read(readCtx)
		cancel()
		secondFrameReachedUpstream <- err == nil
	}))
	defer upstream.Close()
	server.cfg.UpstreamBaseURL = upstream.URL + "/backend-api/codex"
	server.client = upstream.Client()
	gateway := httptest.NewServer(server.commonHeaders("api", server.proxyHandler()))
	defer gateway.Close()

	client, _, err := websocket.Dial(context.Background(), strings.Replace(gateway.URL, "http://", "ws://", 1)+"/responses", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer sk-fg_ws-switch"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseNow()
	if err := client.Write(context.Background(), websocket.MessageText, []byte(`{"type":"response.create","model":"gpt-first"}`)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := client.Write(context.Background(), websocket.MessageText, []byte(`{"type":"response.create","model":"gpt-second","tools":[{"type":"image_generation"}]}`)); err != nil {
		t.Fatal(err)
	}
	_, payload, err := client.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var event struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(payload, &event) != nil || event.Error.Code != "model_not_available" {
		t.Fatalf("switch response=%s", payload)
	}
	select {
	case reached := <-secondFrameReachedUpstream:
		if reached {
			t.Fatal("unsupported switched model was forwarded to the original account")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upstream relay did not exit")
	}
}

func TestResponsesWebSocketKeyDeleteCancelsAndDrainsConnection(t *testing.T) {
	server, store := testApp(t)
	accountID, key := createTestAccountAndKey(t, store, "ws-delete", "sk-fg_ws-delete", "127.0.0.1")
	installOfficialManifest(t, store, accountID, `{"models":[{"slug":"gpt-live"}]}`)
	upstreamReady := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		if _, _, err = conn.Read(r.Context()); err != nil {
			return
		}
		close(upstreamReady)
		_, _, _ = conn.Read(r.Context())
	}))
	defer upstream.Close()
	server.cfg.UpstreamBaseURL = upstream.URL + "/backend-api/codex"
	server.client = upstream.Client()
	gateway := httptest.NewServer(server.commonHeaders("api", server.proxyHandler()))
	defer gateway.Close()
	client, _, err := websocket.Dial(context.Background(), strings.Replace(gateway.URL, "http://", "ws://", 1)+"/v1/responses", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer sk-fg_ws-delete"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseNow()
	if err := client.Write(context.Background(), websocket.MessageText, []byte(`{"type":"response.create","model":"gpt-live"}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-upstreamReady:
	case <-time.After(3 * time.Second):
		t.Fatal("WebSocket was not admitted upstream")
	}
	deleteCtx, cancelDelete := context.WithTimeout(context.Background(), 3*time.Second)
	cancelled, err := server.deleteAPIKey(deleteCtx, key.ID)
	cancelDelete()
	if err != nil {
		t.Fatal(err)
	}
	if cancelled != 1 {
		t.Fatalf("deleted key cancelled=%d want=1", cancelled)
	}
	readCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	_, _, readErr := client.Read(readCtx)
	cancel()
	if readErr == nil {
		t.Fatal("client WebSocket remained open after key deletion returned")
	}
	if _, err := store.AuthorizeKey(context.Background(), "sk-fg_ws-delete", "127.0.0.1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted key remained authorized: %v", err)
	}
}

func TestResponsesWebSocketKeyDisableCancelsAndDrainsConnection(t *testing.T) {
	server, store := testApp(t)
	accountID, key := createTestAccountAndKey(t, store, "ws-disable", "sk-fg_ws-disable", "127.0.0.1")
	installOfficialManifest(t, store, accountID, `{"models":[{"slug":"gpt-live"}]}`)
	upstreamReady := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		if _, _, err = conn.Read(r.Context()); err != nil {
			return
		}
		close(upstreamReady)
		_, _, _ = conn.Read(r.Context())
	}))
	defer upstream.Close()
	server.cfg.UpstreamBaseURL = upstream.URL + "/backend-api/codex"
	server.client = upstream.Client()
	gateway := httptest.NewServer(server.commonHeaders("api", server.proxyHandler()))
	defer gateway.Close()
	client, _, err := websocket.Dial(context.Background(), strings.Replace(gateway.URL, "http://", "ws://", 1)+"/v1/responses", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer sk-fg_ws-disable"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseNow()
	if err := client.Write(context.Background(), websocket.MessageText, []byte(`{"type":"response.create","model":"gpt-live"}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-upstreamReady:
	case <-time.After(3 * time.Second):
		t.Fatal("WebSocket was not admitted upstream")
	}
	disableCtx, cancelDisable := context.WithTimeout(context.Background(), 3*time.Second)
	cancelled, err := server.updateAPIKeyState(disableCtx, key.ID, "disabled", key.QuotaRequests)
	cancelDisable()
	if err != nil {
		t.Fatal(err)
	}
	if cancelled != 1 {
		t.Fatalf("disabled key cancelled=%d want=1", cancelled)
	}
	readCtx, cancelRead := context.WithTimeout(context.Background(), time.Second)
	_, _, readErr := client.Read(readCtx)
	cancelRead()
	if readErr == nil {
		t.Fatal("client WebSocket remained open after key disable returned")
	}
	if _, err := store.AuthorizeKey(context.Background(), "sk-fg_ws-disable", "127.0.0.1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disabled key remained authorized: %v", err)
	}
}

func TestResponsesWebSocketAccountDisableIsImmediateAndTruthful(t *testing.T) {
	server, store := testApp(t)
	accountID, _ := createTestAccountAndKey(t, store, "ws-account-disable", "sk-fg_ws-account-disable", "127.0.0.1")
	installOfficialManifest(t, store, accountID, `{"models":[{"slug":"gpt-live"}]}`)
	upstreamReady := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		if _, _, err = conn.Read(r.Context()); err != nil {
			return
		}
		close(upstreamReady)
		_, _, _ = conn.Read(r.Context())
	}))
	defer upstream.Close()
	server.cfg.UpstreamBaseURL = upstream.URL + "/backend-api/codex"
	server.client = upstream.Client()
	gateway := httptest.NewServer(server.commonHeaders("api", server.proxyHandler()))
	defer gateway.Close()
	client, _, err := websocket.Dial(context.Background(), strings.Replace(gateway.URL, "http://", "ws://", 1)+"/v1/responses", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer sk-fg_ws-account-disable"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseNow()
	if err := client.Write(context.Background(), websocket.MessageText, []byte(`{"type":"response.create","model":"gpt-live"}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-upstreamReady:
	case <-time.After(3 * time.Second):
		t.Fatal("WebSocket was not admitted upstream")
	}
	disableCtx, cancelDisable := context.WithTimeout(context.Background(), 3*time.Second)
	cancelled, err := server.updateAccountState(disableCtx, accountID, false)
	cancelDisable()
	if err != nil {
		t.Fatal(err)
	}
	if cancelled != 1 {
		t.Fatalf("disabled account cancelled=%d want=1", cancelled)
	}
	readCtx, cancelRead := context.WithTimeout(context.Background(), time.Second)
	_, _, readErr := client.Read(readCtx)
	cancelRead()
	if readErr == nil {
		t.Fatal("client WebSocket remained open after account disable returned")
	}
	account, err := store.GetAccount(context.Background(), accountID)
	if err != nil {
		t.Fatal(err)
	}
	if account.Active {
		t.Fatal("account remained active after disable returned")
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		usage, listErr := store.ListUsage(context.Background(), 10)
		if listErr != nil {
			t.Fatal(listErr)
		}
		if len(usage) > 0 {
			if usage[0].Status != http.StatusServiceUnavailable || usage[0].Error != "ChatGPT account access revoked by administrator" {
				t.Fatalf("account disable usage status=%d error=%q", usage[0].Status, usage[0].Error)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("account disable WebSocket usage was not persisted")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
