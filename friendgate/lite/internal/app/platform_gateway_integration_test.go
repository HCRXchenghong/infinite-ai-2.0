package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// This opt-in test drives the actual HTTP gateway against a local OpenAI
// compatible upstream and a real PostgreSQL transaction path. It verifies the
// important product boundary: users receive a platform alias, while the
// upstream receives only its private model ID and the original tools payload.
func TestPlatformGatewayPostgresIntegration(t *testing.T) {
	dsn := os.Getenv("INFINITE_AI_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("INFINITE_AI_TEST_POSTGRES_URL is not set")
	}
	ctx := context.Background()
	var upstreamBody []byte
	var upstreamMu sync.Mutex
	blockedUpstreamStarted := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" || r.Header.Get("Authorization") != "Bearer gateway-integration-secret" {
			http.Error(w, "unexpected upstream request", http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		upstreamMu.Lock()
		upstreamBody = body
		upstreamMu.Unlock()
		if bytes.Contains(body, []byte(`"input":"block-until-revoked"`)) {
			close(blockedUpstreamStarted)
			<-r.Context().Done()
			return
		}
		if bytes.Contains(body, []byte(`"stream":true`)) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":3,\"output_tokens\":5,\"total_tokens\":8}}}\n\n"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-ID", "upstream-request-id")
		_, _ = w.Write([]byte(`{"id":"resp_test","usage":{"input_tokens":7,"output_tokens":11,"total_tokens":18}}`))
	}))
	defer upstream.Close()

	keyMaterial := bytes.Repeat([]byte{0x73}, 32)
	vault, err := NewVault(keyMaterial)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		DatabasePath: filepath.Join(t.TempDir(), "legacy.db"), PlatformDatabaseURL: dsn, PlatformGatewayEnabled: true,
		PlatformDBMaxOpen: 4, PlatformDBMaxIdle: 2, PlatformDBMaxLife: time.Minute,
		AdminUsername: "admin", AdminPassword: "gateway-integration-admin-password", MasterKey: keyMaterial,
		BanThreshold: 20, BanWindow: time.Minute, BanDuration: time.Hour, MaxBodyBytes: 4 << 20,
		StickyTTL: time.Hour, AccountCooldown: time.Minute, UserSessionTTL: time.Hour,
		DesktopFlowTTL: time.Minute, DesktopAccessTTL: time.Minute, DesktopRefreshTTL: time.Hour,
	}
	legacy, err := OpenStore(cfg, vault)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = legacy.Close() })
	platform := legacy.Platform()
	unique := strings.ReplaceAll(newPlatformID(), "-", "")
	model, err := platform.CreatePlatformModel(ctx, PlatformModelInput{ModelKey: "gateway-" + unique, DisplayName: "Gateway integration", Category: "multimodal", Capabilities: json.RawMessage(`{"tools":true,"image_generation":true}`), Billing: json.RawMessage(`{}`), Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := platform.UpsertProductModelPublication(ctx, ProductModelPublicationInput{ModelID: model.ID, ProductScope: ProductScopeExternalAPI, Protocol: "responses", Enabled: true, PlanRules: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	pool, err := platform.CreateRoutePool(ctx, DefaultPlatformTenantID(), "gateway-pool-"+unique, "quota_aware")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := platform.CreateProviderConnection(ctx, ProviderConnectionInput{ProviderKind: "openai_compatible", ProviderName: "gateway-provider-" + unique, BaseURL: upstream.URL + "/v1", Credential: "gateway-integration-secret", Settings: json.RawMessage(`{}`), Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	account, err := platform.CreateUpstreamAccount(ctx, UpstreamAccountInput{ConnectionID: provider.ID, Label: "gateway account", ExternalReference: "gateway-account-" + unique, ModelCatalog: json.RawMessage(`[{"id":"private-gateway-model"}]`), QuotaState: json.RawMessage(`{}`), Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if err := platform.AddRoutePoolMember(ctx, RoutePoolMemberInput{RoutePoolID: pool.ID, UpstreamAccountID: account.ID, Priority: 1, Weight: 1, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := platform.CreateRouteTarget(ctx, ModelRouteTargetInput{ModelID: model.ID, ProductScope: ProductScopeExternalAPI, Protocol: "responses", RoutePoolID: pool.ID, UpstreamModelID: "private-gateway-model", Priority: 1, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	userID := newPlatformID()
	if _, err := platform.db.ExecContext(ctx, `INSERT INTO users(id,tenant_id,email,display_name) VALUES($1,$2,$3,$4)`, userID, DefaultPlatformTenantID(), unique+"@gateway.integration.invalid", "Gateway integration"); err != nil {
		t.Fatal(err)
	}
	walletID, err := platform.EnsureWallet(ctx, userID, ProductScopeExternalAPI)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, window := range []string{"monthly", "rolling_5h"} {
		if _, err := platform.GrantQuota(ctx, walletID, QuotaBucketInput{WindowKind: window, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour), Tokens: 100_000, Reference: "gateway-" + window + "-" + unique, Reason: "integration"}); err != nil {
			t.Fatal(err)
		}
	}
	key, plainKey, err := platform.CreatePlatformAPIKey(ctx, PlatformAPIKeyInput{UserID: userID, RoutePoolID: pool.ID, Label: "gateway integration key", Scopes: []PlatformKeyScopeInput{{ProductScope: ProductScopeExternalAPI, ModelID: model.ID}}})
	if err != nil {
		t.Fatal(err)
	}

	server := NewServer(cfg, legacy, vault)
	requestBody := []byte(`{"model":"` + model.ModelKey + `","input":"draw a blue cube","tools":[{"type":"image_generation","size":"1024x1024"}],"max_output_tokens":64}`)
	req := httptest.NewRequest(http.MethodPost, "http://gateway.invalid/v1/responses", bytes.NewReader(requestBody))
	req.Header.Set("Authorization", "Bearer "+plainKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.proxyHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("gateway status=%d body=%s", rec.Code, rec.Body.String())
	}
	upstreamMu.Lock()
	fastUpstreamBody := append([]byte(nil), upstreamBody...)
	upstreamMu.Unlock()
	if strings.Contains(string(fastUpstreamBody), model.ModelKey) || !strings.Contains(string(fastUpstreamBody), `"model":"private-gateway-model"`) || !strings.Contains(string(fastUpstreamBody), `"tools":[{"type":"image_generation","size":"1024x1024"}]`) {
		t.Fatalf("upstream body was not isolated/preserved: %s", fastUpstreamBody)
	}
	modelsRequest := httptest.NewRequest(http.MethodGet, "http://gateway.invalid/v1/models", nil)
	modelsRequest.Header.Set("Authorization", "Bearer "+plainKey)
	modelsRec := httptest.NewRecorder()
	server.proxyHandler().ServeHTTP(modelsRec, modelsRequest)
	if modelsRec.Code != http.StatusOK || !strings.Contains(modelsRec.Body.String(), model.ModelKey) || strings.Contains(modelsRec.Body.String(), "private-gateway-model") {
		t.Fatalf("model catalogue leaked or missing alias: status=%d body=%s", modelsRec.Code, modelsRec.Body.String())
	}
	streamReq := httptest.NewRequest(http.MethodPost, "http://gateway.invalid/v1/responses", strings.NewReader(`{"model":"`+model.ModelKey+`","input":"stream this","stream":true,"max_output_tokens":64}`))
	streamReq.Header.Set("Authorization", "Bearer "+plainKey)
	streamReq.Header.Set("Content-Type", "application/json")
	streamRec := httptest.NewRecorder()
	server.proxyHandler().ServeHTTP(streamRec, streamReq)
	if streamRec.Code != http.StatusOK || !strings.Contains(streamRec.Body.String(), "event: response.completed") || !strings.Contains(streamRec.Body.String(), `"total_tokens":8`) {
		t.Fatalf("SSE response was not passed through: status=%d body=%s", streamRec.Code, streamRec.Body.String())
	}
	var usage struct {
		Billed    int64 `json:"billed_tokens"`
		Input     int64 `json:"input_tokens"`
		Output    int64 `json:"output_tokens"`
		Estimated bool  `json:"estimated"`
	}
	if err := platform.db.QueryRowContext(ctx, `SELECT billed_tokens,input_tokens,output_tokens,estimated FROM usage_records WHERE api_key_id=$1 AND billed_tokens=18 LIMIT 1`, key.ID).Scan(&usage.Billed, &usage.Input, &usage.Output, &usage.Estimated); err != nil || usage.Billed != 18 || usage.Input != 7 || usage.Output != 11 || usage.Estimated {
		t.Fatalf("non-stream usage record=%+v err=%v", usage, err)
	}
	var streamUsageRows int
	if err := platform.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM usage_records WHERE api_key_id=$1 AND billed_tokens=8 AND estimated=false`, key.ID).Scan(&streamUsageRows); err != nil || streamUsageRows != 1 {
		t.Fatalf("stream usage rows=%d err=%v", streamUsageRows, err)
	}
	if err := platform.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ledger_entries WHERE wallet_account_id=$1 AND entry_type='settle' AND tokens=8`, walletID).Scan(&streamUsageRows); err != nil || streamUsageRows != 2 {
		t.Fatalf("stream ledger settlement rows=%d err=%v", streamUsageRows, err)
	}
	// Disabling a key is not merely a next-request check: it cancels an
	// already-open streaming/long request before the administration endpoint
	// returns. This is the required immediate-effect lifecycle boundary.
	streamKey, streamPlainKey, err := platform.CreatePlatformAPIKey(ctx, PlatformAPIKeyInput{UserID: userID, RoutePoolID: pool.ID, Label: "gateway stream key", Scopes: []PlatformKeyScopeInput{{ProductScope: ProductScopeExternalAPI, ModelID: model.ID}}})
	if err != nil {
		t.Fatal(err)
	}
	gateway := httptest.NewServer(server.proxyHandler())
	defer gateway.Close()
	result := make(chan int, 1)
	go func() {
		request, _ := http.NewRequest(http.MethodPost, gateway.URL+"/v1/responses", strings.NewReader(`{"model":"`+model.ModelKey+`","input":"block-until-revoked","max_output_tokens":64}`))
		request.Header.Set("Authorization", "Bearer "+streamPlainKey)
		request.Header.Set("Content-Type", "application/json")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			result <- 0
			return
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		result <- response.StatusCode
	}()
	select {
	case <-blockedUpstreamStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("gateway request did not reach upstream")
	}
	cancelled, err := server.setPlatformAPIKeyStatus(ctx, streamKey.ID, "disabled")
	if err != nil || cancelled != 1 {
		t.Fatalf("stream key disable cancelled=%d err=%v", cancelled, err)
	}
	select {
	case status := <-result:
		if status != http.StatusUnauthorized {
			t.Fatalf("revoked in-flight request status=%d, want 401", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("revoked in-flight request did not finish")
	}
	if _, err := server.setPlatformAPIKeyStatus(ctx, key.ID, "disabled"); err != nil {
		t.Fatal(err)
	}
	disabledReq := httptest.NewRequest(http.MethodGet, "http://gateway.invalid/v1/models", nil)
	disabledReq.Header.Set("Authorization", "Bearer "+plainKey)
	disabledRec := httptest.NewRecorder()
	server.proxyHandler().ServeHTTP(disabledRec, disabledReq)
	if disabledRec.Code != http.StatusUnauthorized {
		t.Fatalf("disabled key remained valid: status=%d body=%s", disabledRec.Code, disabledRec.Body.String())
	}
}

func TestPlatformGatewayPostgresNativeProtocolIntegration(t *testing.T) {
	dsn := os.Getenv("INFINITE_AI_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("INFINITE_AI_TEST_POSTGRES_URL is not set")
	}
	ctx := context.Background()
	var anthropicBody, geminiBody []byte
	var upstreamMu sync.Mutex
	anthropic := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" || r.Header.Get("X-API-Key") != "anthropic-native-secret" || r.Header.Get("Anthropic-Version") == "" || r.Header.Get("Authorization") != "" {
			http.Error(w, "unexpected anthropic request", http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		upstreamMu.Lock()
		anthropicBody = body
		upstreamMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_test","type":"message","usage":{"input_tokens":4,"output_tokens":6}}`))
	}))
	defer anthropic.Close()
	gemini := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1beta/models/gemini-private:generateContent" || r.URL.Query().Get("key") != "gemini-native-secret" || r.Header.Get("Authorization") != "" {
			http.Error(w, "unexpected gemini request", http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		upstreamMu.Lock()
		geminiBody = body
		upstreamMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"ok"}]}}],"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":7,"totalTokenCount":12}}`))
	}))
	defer gemini.Close()

	keyMaterial := bytes.Repeat([]byte{0x61}, 32)
	vault, err := NewVault(keyMaterial)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		DatabasePath: filepath.Join(t.TempDir(), "legacy.db"), PlatformDatabaseURL: dsn, PlatformGatewayEnabled: true,
		PlatformDBMaxOpen: 4, PlatformDBMaxIdle: 2, PlatformDBMaxLife: time.Minute,
		AdminUsername: "admin", AdminPassword: "gateway-native-admin-password", MasterKey: keyMaterial,
		BanThreshold: 20, BanWindow: time.Minute, BanDuration: time.Hour, MaxBodyBytes: 4 << 20,
		StickyTTL: time.Hour, AccountCooldown: time.Minute, UserSessionTTL: time.Hour,
		DesktopFlowTTL: time.Minute, DesktopAccessTTL: time.Minute, DesktopRefreshTTL: time.Hour,
	}
	store, err := OpenStore(cfg, vault)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	platform := store.Platform()
	unique := strings.ReplaceAll(newPlatformID(), "-", "")
	anthropicModel, err := platform.CreatePlatformModel(ctx, PlatformModelInput{ModelKey: "claude-" + unique, DisplayName: "Claude native", Category: "chat", Capabilities: json.RawMessage(`{}`), Billing: json.RawMessage(`{}`), Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	geminiModel, err := platform.CreatePlatformModel(ctx, PlatformModelInput{ModelKey: "gemini-" + unique, DisplayName: "Gemini native", Category: "multimodal", Capabilities: json.RawMessage(`{}`), Billing: json.RawMessage(`{}`), Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	for _, publication := range []ProductModelPublicationInput{
		{ModelID: anthropicModel.ID, ProductScope: ProductScopeExternalAPI, Protocol: "messages", Enabled: true, PlanRules: json.RawMessage(`{}`)},
		{ModelID: geminiModel.ID, ProductScope: ProductScopeExternalAPI, Protocol: "generate_content", Enabled: true, PlanRules: json.RawMessage(`{}`)},
	} {
		if _, err := platform.UpsertProductModelPublication(ctx, publication); err != nil {
			t.Fatal(err)
		}
	}
	pool, err := platform.CreateRoutePool(ctx, DefaultPlatformTenantID(), "native-pool-"+unique, "quota_aware")
	if err != nil {
		t.Fatal(err)
	}
	anthropicProvider, err := platform.CreateProviderConnection(ctx, ProviderConnectionInput{ProviderKind: "anthropic_compatible", ProviderName: "anthropic-" + unique, BaseURL: anthropic.URL + "/v1", Credential: "anthropic-native-secret", Settings: json.RawMessage(`{}`), Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	geminiProvider, err := platform.CreateProviderConnection(ctx, ProviderConnectionInput{ProviderKind: "gemini_compatible", ProviderName: "gemini-" + unique, BaseURL: gemini.URL + "/v1beta", Credential: "gemini-native-secret", Settings: json.RawMessage(`{}`), Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	anthropicAccount, err := platform.CreateUpstreamAccount(ctx, UpstreamAccountInput{ConnectionID: anthropicProvider.ID, Label: "anthropic native", ExternalReference: "anthropic-" + unique, ModelCatalog: json.RawMessage(`[{"id":"claude-private"}]`), QuotaState: json.RawMessage(`{}`), Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	geminiAccount, err := platform.CreateUpstreamAccount(ctx, UpstreamAccountInput{ConnectionID: geminiProvider.ID, Label: "gemini native", ExternalReference: "gemini-" + unique, ModelCatalog: json.RawMessage(`[{"name":"models/gemini-private"}]`), QuotaState: json.RawMessage(`{}`), Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range []RoutePoolMemberInput{
		{RoutePoolID: pool.ID, UpstreamAccountID: anthropicAccount.ID, Priority: 1, Weight: 1, Enabled: true},
		{RoutePoolID: pool.ID, UpstreamAccountID: geminiAccount.ID, Priority: 1, Weight: 1, Enabled: true},
	} {
		if err := platform.AddRoutePoolMember(ctx, member); err != nil {
			t.Fatal(err)
		}
	}
	for _, target := range []ModelRouteTargetInput{
		{ModelID: anthropicModel.ID, ProductScope: ProductScopeExternalAPI, Protocol: "messages", RoutePoolID: pool.ID, UpstreamModelID: "claude-private", Priority: 1, Enabled: true},
		{ModelID: geminiModel.ID, ProductScope: ProductScopeExternalAPI, Protocol: "generate_content", RoutePoolID: pool.ID, UpstreamModelID: "gemini-private", Priority: 1, Enabled: true},
	} {
		if _, err := platform.CreateRouteTarget(ctx, target); err != nil {
			t.Fatal(err)
		}
	}
	userID := newPlatformID()
	if _, err := platform.db.ExecContext(ctx, `INSERT INTO users(id,tenant_id,email,display_name) VALUES($1,$2,$3,$4)`, userID, DefaultPlatformTenantID(), unique+"@native.integration.invalid", "Native integration"); err != nil {
		t.Fatal(err)
	}
	walletID, err := platform.EnsureWallet(ctx, userID, ProductScopeExternalAPI)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, window := range []string{"monthly", "rolling_5h"} {
		if _, err := platform.GrantQuota(ctx, walletID, QuotaBucketInput{WindowKind: window, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour), Tokens: 100_000, Reference: "native-" + window + "-" + unique, Reason: "integration"}); err != nil {
			t.Fatal(err)
		}
	}
	key, plainKey, err := platform.CreatePlatformAPIKey(ctx, PlatformAPIKeyInput{UserID: userID, RoutePoolID: pool.ID, Label: "native key", Scopes: []PlatformKeyScopeInput{
		{ProductScope: ProductScopeExternalAPI, ModelID: anthropicModel.ID},
		{ProductScope: ProductScopeExternalAPI, ModelID: geminiModel.ID},
	}})
	if err != nil {
		t.Fatal(err)
	}

	server := NewServer(cfg, store, vault)
	anthropicReq := httptest.NewRequest(http.MethodPost, "http://gateway.invalid/v1/messages", strings.NewReader(`{"model":"`+anthropicModel.ModelKey+`","max_tokens":32,"messages":[{"role":"user","content":"hi"}]}`))
	anthropicReq.Header.Set("Authorization", "Bearer "+plainKey)
	anthropicReq.Header.Set("Content-Type", "application/json")
	anthropicRec := httptest.NewRecorder()
	server.proxyHandler().ServeHTTP(anthropicRec, anthropicReq)
	if anthropicRec.Code != http.StatusOK {
		t.Fatalf("Anthropic gateway status=%d body=%s", anthropicRec.Code, anthropicRec.Body.String())
	}
	upstreamMu.Lock()
	seenAnthropicBody := string(anthropicBody)
	upstreamMu.Unlock()
	if strings.Contains(seenAnthropicBody, anthropicModel.ModelKey) || !strings.Contains(seenAnthropicBody, `"model":"claude-private"`) {
		t.Fatalf("Anthropic body was not rewritten privately: %s", seenAnthropicBody)
	}

	geminiReq := httptest.NewRequest(http.MethodPost, "http://gateway.invalid/v1beta/models/"+geminiModel.ModelKey+":generateContent?key="+url.QueryEscape(plainKey), strings.NewReader(`{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"generationConfig":{"maxOutputTokens":32}}`))
	geminiReq.Header.Set("Content-Type", "application/json")
	geminiRec := httptest.NewRecorder()
	server.proxyHandler().ServeHTTP(geminiRec, geminiReq)
	if geminiRec.Code != http.StatusOK {
		t.Fatalf("Gemini gateway status=%d body=%s", geminiRec.Code, geminiRec.Body.String())
	}
	upstreamMu.Lock()
	seenGeminiBody := string(geminiBody)
	upstreamMu.Unlock()
	if strings.Contains(seenGeminiBody, geminiModel.ModelKey) || !strings.Contains(seenGeminiBody, `"contents"`) {
		t.Fatalf("Gemini body was not passed through safely: %s", seenGeminiBody)
	}
	modelsReq := httptest.NewRequest(http.MethodGet, "http://gateway.invalid/v1beta/models?key="+url.QueryEscape(plainKey), nil)
	modelsRec := httptest.NewRecorder()
	server.proxyHandler().ServeHTTP(modelsRec, modelsReq)
	if modelsRec.Code != http.StatusOK || !strings.Contains(modelsRec.Body.String(), "models/"+geminiModel.ModelKey) || strings.Contains(modelsRec.Body.String(), "gemini-private") {
		t.Fatalf("Gemini model catalogue leaked or missed alias: status=%d body=%s", modelsRec.Code, modelsRec.Body.String())
	}
	var anthropicBilled, geminiBilled int64
	if err := platform.db.QueryRowContext(ctx, `SELECT billed_tokens FROM usage_records WHERE api_key_id=$1 AND model_id=$2 AND protocol='messages' ORDER BY created_at DESC LIMIT 1`, key.ID, anthropicModel.ID).Scan(&anthropicBilled); err != nil || anthropicBilled != 10 {
		t.Fatalf("Anthropic usage billed=%d err=%v", anthropicBilled, err)
	}
	if err := platform.db.QueryRowContext(ctx, `SELECT billed_tokens FROM usage_records WHERE api_key_id=$1 AND model_id=$2 AND protocol='generate_content' ORDER BY created_at DESC LIMIT 1`, key.ID, geminiModel.ID).Scan(&geminiBilled); err != nil || geminiBilled != 12 {
		t.Fatalf("Gemini usage billed=%d err=%v", geminiBilled, err)
	}
}
