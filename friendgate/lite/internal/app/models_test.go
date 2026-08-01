package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func mustOfficialManifest(t *testing.T, raw string) *parsedOfficialManifest {
	t.Helper()
	manifest, err := parseOfficialModelManifest([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func installOfficialManifest(t *testing.T, store *Store, accountID int64, raw string) {
	t.Helper()
	if err := store.ReplaceAccountModels(context.Background(), accountID, mustOfficialManifest(t, raw)); err != nil {
		t.Fatal(err)
	}
}

func TestModelCatalogMergePreservesOfficialUnknownFields(t *testing.T) {
	_, store := testApp(t)
	firstID := createTestAccount(t, store, "first", "access-first", "acct-first")
	secondID := createTestAccount(t, store, "second", "access-second", "acct-second")
	installOfficialManifest(t, store, firstID, `{
		"object":"list",
		"models":[
			{"slug":"gpt-alpha","object":"model","owned_by":"openai","display_name":"Alpha","supported_reasoning_levels":["low","high"]},
			{"slug":"gpt-shared","generation":"old","unknown":{"source":"first"}}
		],
		"first_only":{"kept_in_snapshot":true}
	}`)
	installOfficialManifest(t, store, secondID, `{
		"object":"codex.models",
		"models":[
			{"slug":"gpt-beta","object":"model","owned_by":"system","tool_capabilities":{"web_search":true,"image_generation":true}},
			{"slug":"gpt-shared","generation":"new","unknown":{"source":"second"}}
		],
		"reasoning":{"default":"high"},
		"future_top_level":{"opaque":[1,2,3]}
	}`)
	if _, err := store.db.Exec(`UPDATE account_model_snapshots SET updated_at=100 WHERE account_id=?`, firstID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE account_model_snapshots SET updated_at=200 WHERE account_id=?`, secondID); err != nil {
		t.Fatal(err)
	}

	catalog, err := store.ListModelCatalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if catalog.ModelCount != 3 || len(catalog.Accounts) != 2 || catalog.UpdatedAt != 200 {
		t.Fatalf("catalog=%+v", catalog)
	}
	if got := strings.Join(catalog.Accounts[0].Models, ","); got != "gpt-alpha,gpt-shared" {
		t.Fatalf("first account models=%q", got)
	}
	if got := strings.Join(catalog.Accounts[1].Models, ","); got != "gpt-beta,gpt-shared" {
		t.Fatalf("second account models=%q", got)
	}

	merged, err := store.MergedOfficialModelManifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(merged, &envelope); err != nil {
		t.Fatal(err)
	}
	if string(envelope["object"]) != `"codex.models"` || len(envelope["reasoning"]) == 0 || len(envelope["future_top_level"]) == 0 {
		t.Fatalf("newest official envelope fields were not retained: %s", merged)
	}
	if _, exists := envelope["first_only"]; exists {
		t.Fatalf("merged manifest did not use one real top-level template: %s", merged)
	}
	var models []map[string]json.RawMessage
	if err := json.Unmarshal(envelope["models"], &models); err != nil {
		t.Fatal(err)
	}
	if len(models) != 3 {
		t.Fatalf("merged models=%s", envelope["models"])
	}
	bySlug := make(map[string]map[string]json.RawMessage)
	for _, model := range models {
		bySlug[rawJSONString(model["slug"])] = model
	}
	if len(bySlug["gpt-alpha"]["supported_reasoning_levels"]) == 0 || len(bySlug["gpt-beta"]["tool_capabilities"]) == 0 {
		t.Fatalf("per-model unknown fields were lost: %s", envelope["models"])
	}
	if string(bySlug["gpt-shared"]["generation"]) != `"new"` {
		t.Fatalf("duplicate model did not use newest live snapshot: %s", envelope["models"])
	}
}

func TestSelectAccountForModelPreservesAffinityAndFailsClosedWithoutCatalog(t *testing.T) {
	_, store := testApp(t)
	firstID, key := createTestAccountAndKey(t, store, "model-routing", "sk-fg_model-routing", "203.0.113.80")
	secondID := createTestAccount(t, store, "second", "access-second", "acct-second")
	installOfficialManifest(t, store, firstID, `{"models":[{"slug":"gpt-first"}]}`)
	installOfficialManifest(t, store, secondID, `{"models":[{"slug":"gpt-second"}]}`)

	selected, err := store.SelectAccountForModel(context.Background(), key.ID, tokenHash("conversation"), "gpt-second", time.Hour)
	if err != nil || selected.ID != secondID {
		t.Fatalf("selected=%+v err=%v", selected, err)
	}
	if _, err := store.SelectAccountForModel(context.Background(), key.ID, tokenHash("conversation"), "gpt-first", time.Hour); !errors.Is(err, ErrModelNotAvailable) {
		t.Fatalf("an existing conversation moved to another account: %v", err)
	}
	if _, err := store.SelectAccountForModel(context.Background(), key.ID, tokenHash("missing"), "gpt-missing", time.Hour); !errors.Is(err, ErrModelNotAvailable) {
		t.Fatalf("unknown model error=%v", err)
	}

	store.MarkAccountCooldown(context.Background(), secondID, time.Now().Add(time.Hour).Unix(), "rate limited")
	selected, err = store.SelectAccountForModel(context.Background(), key.ID, tokenHash("conversation"), "gpt-second", time.Hour)
	if err != nil || selected.ID != secondID {
		t.Fatalf("cooldown broke an existing conversation: selected=%+v err=%v", selected, err)
	}
	if _, err := store.SelectAccountForModel(context.Background(), key.ID, tokenHash("new conversation"), "gpt-second", time.Hour); !errors.Is(err, ErrNoAccount) {
		t.Fatalf("all supporting accounts in cooldown error=%v", err)
	}

	if _, err := store.db.Exec(`DELETE FROM account_models`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`DELETE FROM account_model_snapshots`); err != nil {
		t.Fatal(err)
	}
	selected, err = store.SelectAccountForModel(context.Background(), key.ID, tokenHash("unsynced deployment"), "future-model", time.Hour)
	if !errors.Is(err, ErrModelCatalogUnavailable) || selected != nil {
		t.Fatalf("deployment without a successful snapshot did not fail closed: selected=%+v err=%v", selected, err)
	}
}

func TestRefreshAccountModelsFailureRetainsLastGoodSnapshot(t *testing.T) {
	server, store := testApp(t)
	accountID := createTestAccount(t, store, "refresh-failure", "access-refresh", "acct-refresh")
	installOfficialManifest(t, store, accountID, `{"models":[{"slug":"gpt-retained","future_field":true}]}`)
	server.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("upstream unavailable")), Request: request}, nil
	})}

	catalog, err := server.RefreshAccountModels(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Accounts) != 1 || catalog.Accounts[0].Error == "" || strings.Join(catalog.Accounts[0].Models, ",") != "gpt-retained" {
		t.Fatalf("failed refresh did not retain the last good snapshot: %+v", catalog)
	}
	merged, err := store.MergedOfficialModelManifest(context.Background())
	if err != nil || !bytes.Contains(merged, []byte(`"future_field":true`)) {
		t.Fatalf("merged=%s err=%v", merged, err)
	}
}

func TestRefreshAccountModelsFetchesOfficialManifestForEachLiveAccount(t *testing.T) {
	server, store := testApp(t)
	firstID := createTestAccount(t, store, "sync-first", "sync-access-first", "acct-sync-first")
	secondID := createTestAccount(t, store, "sync-second", "sync-access-second", "acct-sync-second")
	var seenMu sync.Mutex
	seen := make(map[string]bool)
	server.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Path != "/backend-api/codex/models" || request.URL.Query().Get("client_version") != defaultCodexVersion {
			return nil, errors.New("unexpected Codex models request URL")
		}
		if request.Header.Get("ChatGPT-Account-ID") == "" || request.Header.Get("Originator") != "codex_cli_rs" || request.Header.Get("Version") != defaultCodexVersion {
			return nil, errors.New("missing official Codex models headers")
		}
		authorization := request.Header.Get("Authorization")
		seenMu.Lock()
		seen[authorization] = true
		seenMu.Unlock()
		var body string
		switch authorization {
		case "Bearer sync-access-first":
			body = `{"models":[{"slug":"gpt-sync-first","reasoning":{"levels":["high"]}}],"account_feature":"first"}`
		case "Bearer sync-access-second":
			body = `{"models":[{"slug":"gpt-sync-second","tools":{"image_generation":true}}],"account_feature":"second"}`
		default:
			return nil, errors.New("unexpected account authorization")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
	})}

	catalog, err := server.RefreshAccountModels(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if catalog.ModelCount != 2 || len(catalog.Accounts) != 2 {
		t.Fatalf("catalog=%+v", catalog)
	}
	seenMu.Lock()
	firstSeen, secondSeen := seen["Bearer sync-access-first"], seen["Bearer sync-access-second"]
	seenMu.Unlock()
	if !firstSeen || !secondSeen {
		t.Fatalf("not every live account was synchronized: %+v", seen)
	}
	for accountID, modelID := range map[int64]string{firstID: "gpt-sync-first", secondID: "gpt-sync-second"} {
		var count int
		if err := store.db.QueryRow(`SELECT COUNT(*) FROM account_models WHERE account_id=? AND model_id=?`, accountID, modelID).Scan(&count); err != nil || count != 1 {
			t.Fatalf("account=%d model=%s count=%d err=%v", accountID, modelID, count, err)
		}
	}
}

func TestAutomaticModelSyncRunsImmediatelyOnThirtyMinuteSchedule(t *testing.T) {
	if modelSyncInterval != 30*time.Minute {
		t.Fatalf("model sync interval=%s want=30m", modelSyncInterval)
	}
	server, store := testApp(t)
	accountID := createTestAccount(t, store, "automatic-sync", "automatic-access", "acct-automatic")
	started := make(chan struct{}, 1)
	server.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"models":[{"slug":"gpt-automatic"}]}`)),
			Request:    request,
		}, nil
	})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		server.modelSyncLoop(ctx)
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("startup model synchronization did not run immediately")
	}
	deadline := time.Now().Add(time.Second)
	for {
		var models int
		err := store.db.QueryRow(`SELECT COUNT(*) FROM account_models WHERE account_id=? AND model_id='gpt-automatic'`, accountID).Scan(&models)
		if err == nil && models == 1 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("automatic model snapshot was not persisted: models=%d err=%v", models, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("model synchronization loop did not stop with its context")
	}
}

func TestRefreshAccountModelsLateResultCannotRestoreDeletedAccount(t *testing.T) {
	server, store := testApp(t)
	accountID := createTestAccount(t, store, "delete-during-refresh", "access-delete", "acct-delete")
	installOfficialManifest(t, store, accountID, `{"models":[{"slug":"gpt-old"}]}`)
	started := make(chan struct{})
	release := make(chan struct{})
	server.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		close(started)
		<-release
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"models":[{"slug":"gpt-late"}]}`)), Request: request}, nil
	})}
	refreshDone := make(chan error, 1)
	go func() {
		_, err := server.RefreshAccountModels(context.Background())
		refreshDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("model refresh did not start")
	}
	deleteStarted := make(chan struct{})
	deleteDone := make(chan error, 1)
	go func() {
		close(deleteStarted)
		_, err := server.deleteAccount(context.Background(), accountID)
		deleteDone <- err
	}()
	<-deleteStarted
	select {
	case err := <-deleteDone:
		t.Fatalf("account deletion returned while model credential request was still active: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-refreshDone; err != nil {
		t.Fatal(err)
	}
	if err := <-deleteDone; err != nil {
		t.Fatal(err)
	}
	var models, snapshots int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM account_models WHERE account_id=?`, accountID).Scan(&models); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM account_model_snapshots WHERE account_id=?`, accountID).Scan(&snapshots); err != nil {
		t.Fatal(err)
	}
	if models != 0 || snapshots != 0 {
		t.Fatalf("late refresh restored deleted routing state: models=%d snapshots=%d", models, snapshots)
	}
}

func TestGatewayModelsUsesStoredOfficialManifestAndFailsClosedWithoutOne(t *testing.T) {
	server, store := testApp(t)
	accountID, key := createTestAccountAndKey(t, store, "models-endpoint", "sk-fg_models-endpoint", "203.0.113.81")
	usedBefore := keyUsedRequests(t, store, key.ID)

	request := httptest.NewRequest(http.MethodGet, "http://gateway.invalid/v1/models?client_version=0.144.1", nil)
	request.RemoteAddr = "203.0.113.81:4321"
	request.Header.Set("Authorization", "Bearer sk-fg_models-endpoint")
	recorder := httptest.NewRecorder()
	server.serveProxy(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "model_catalog_unavailable") {
		t.Fatalf("unsynced models status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	installOfficialManifest(t, store, accountID, `{"object":"codex.models","models":[{"slug":"gpt-live","reasoning":{"levels":["medium","high"]}}],"tool_schema_version":7}`)
	request = httptest.NewRequest(http.MethodGet, "http://gateway.invalid/backend-api/codex/models?client_version=0.144.1", nil)
	request.RemoteAddr = "203.0.113.81:4321"
	request.Header.Set("X-API-Key", "sk-fg_models-endpoint")
	recorder = httptest.NewRecorder()
	server.serveProxy(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("models status=%d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"tool_schema_version":7`) || !strings.Contains(recorder.Body.String(), `"levels":["medium","high"]`) {
		t.Fatalf("official model fields were not returned: %s", recorder.Body.String())
	}
	if usedAfter := keyUsedRequests(t, store, key.ID); usedAfter != usedBefore {
		t.Fatalf("GET /models consumed request quota: before=%d after=%d", usedBefore, usedAfter)
	}
	request = httptest.NewRequest(http.MethodGet, "http://gateway.invalid/v1/models", nil)
	request.RemoteAddr = "203.0.113.99:4321"
	request.Header.Set("Authorization", "Bearer sk-fg_models-endpoint")
	recorder = httptest.NewRecorder()
	server.serveProxy(recorder, request)
	if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), "ip_not_allowed") {
		t.Fatalf("models endpoint bypassed the key IP ACL: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestGatewayModelCatalogErrorsOccurBeforeQuotaOrUpstreamDispatch(t *testing.T) {
	server, store := testApp(t)
	accountID, key := createTestAccountAndKey(t, store, "model-errors", "sk-fg_model-errors", "203.0.113.83")
	called := false
	server.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("unexpected upstream dispatch")
	})}
	request := httptest.NewRequest(http.MethodPost, "http://gateway.invalid/v1/responses", strings.NewReader(`{"model":"gpt-unsynced","input":"test"}`))
	request.RemoteAddr = "203.0.113.83:4321"
	request.Header.Set("Authorization", "Bearer sk-fg_model-errors")
	recorder := httptest.NewRecorder()
	server.serveProxy(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "model_catalog_unavailable") {
		t.Fatalf("unsynced request status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	installOfficialManifest(t, store, accountID, `{"models":[{"slug":"gpt-known"}]}`)
	largeBody := `{"input":"` + strings.Repeat("x", requestBodyMemory+4096) + `","model":"gpt-unknown"}`
	request = httptest.NewRequest(http.MethodPost, "http://gateway.invalid/v1/responses", strings.NewReader(largeBody))
	request.RemoteAddr = "203.0.113.83:4321"
	request.Header.Set("Authorization", "Bearer sk-fg_model-errors")
	recorder = httptest.NewRecorder()
	server.serveProxy(recorder, request)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "model_not_available") {
		t.Fatalf("unknown late model status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if called {
		t.Fatal("invalid model reached the upstream transport")
	}
	if used := keyUsedRequests(t, store, key.ID); used != 0 {
		t.Fatalf("invalid model consumed quota: %d", used)
	}
}

func TestGatewayRoutesByModelWithoutChangingJSONOrSSE(t *testing.T) {
	server, store := testApp(t)
	firstID, _ := createTestAccountAndKey(t, store, "raw-pass-through", "sk-fg_raw-pass-through", "203.0.113.82")
	secondID := createTestAccount(t, store, "image-account", "access-image", "acct-image")
	installOfficialManifest(t, store, firstID, `{"models":[{"slug":"gpt-text"}]}`)
	installOfficialManifest(t, store, secondID, `{"models":[{"slug":"gpt-image"}]}`)

	requestBody := []byte(`{
  "tools": [
    {"type":"function","name":"lookup","description":"opaque","parameters":{"type":"object","properties":{"q":{"type":"string"}}}},
    {"type":"image_generation","quality":"high","background":"transparent"}
  ],
  "input": [{"role":"user","content":[{"type":"input_text","text":"draw"},{"type":"input_image","image_url":"data:image/png;base64,AAECAwQ="}]}],
	"future_request_field": {"must_remain": [true, null, 1.25]},
	"opaque_padding": "` + strings.Repeat("x", requestBodyMemory+4096) + `",
	"model": "gpt-image"
}`)
	responseBody := "event: response.output_text.delta\n" +
		"data: {\"type\":\"response.output_text.delta\",\"delta\":\"ok\",\"future\":{\"x\":1}}\n\n" +
		"event: response.completed\n" +
		"data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":2,\"output_tokens\":1,\"total_tokens\":3}}}\n\n"
	seen := make(chan struct {
		authorization string
		body          []byte
	}, 1)
	server.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		seen <- struct {
			authorization string
			body          []byte
		}{authorization: request.Header.Get("Authorization"), body: body}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:       io.NopCloser(strings.NewReader(responseBody)),
			Request:    request,
		}, nil
	})}
	request := httptest.NewRequest(http.MethodPost, "http://gateway.invalid/v1/responses", bytes.NewReader(requestBody))
	request.RemoteAddr = "203.0.113.82:4321"
	request.Header.Set("Authorization", "Bearer sk-fg_raw-pass-through")
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.serveProxy(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.String() != responseBody {
		t.Fatalf("SSE changed: status=%d\nwant=%q\n got=%q", recorder.Code, responseBody, recorder.Body.String())
	}
	forwarded := <-seen
	if forwarded.authorization != "Bearer access-image" {
		t.Fatalf("model request was not routed to account %d: %q", secondID, forwarded.authorization)
	}
	if !bytes.Equal(forwarded.body, requestBody) {
		t.Fatalf("request JSON changed:\nwant=%s\n got=%s", requestBody, forwarded.body)
	}
}
