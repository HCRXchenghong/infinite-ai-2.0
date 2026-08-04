package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// This test is intentionally opt-in so the normal unit suite remains usable
// without a local PostgreSQL daemon. The deployment verification command sets
// INFINITE_AI_TEST_POSTGRES_URL to exercise the actual migrations and quota
// transaction path.
func TestPlatformStorePostgresIntegration(t *testing.T) {
	dsn := os.Getenv("INFINITE_AI_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("INFINITE_AI_TEST_POSTGRES_URL is not set")
	}
	ctx := context.Background()
	store, err := OpenPlatformStore(ctx, Config{PlatformDatabaseURL: dsn, PlatformDBMaxOpen: 4, PlatformDBMaxIdle: 2, PlatformDBMaxLife: time.Minute, MasterKey: bytes.Repeat([]byte{0x4a}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	overview, err := store.Overview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !overview.Healthy || overview.Plans != 4 {
		t.Fatalf("unexpected overview: %+v", overview)
	}
	unique := strings.ReplaceAll(newPlatformID(), "-", "")

	model, err := store.CreatePlatformModel(ctx, PlatformModelInput{
		ModelKey:     "integration-image-" + unique,
		DisplayName:  "Integration image",
		Description:  "database integration test model",
		Category:     "image",
		Capabilities: json.RawMessage(`{"image_generation":true}`),
		Billing:      json.RawMessage(`{"token_equivalent":1000}`),
		Status:       "active",
	})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := store.CreateRoutePool(ctx, DefaultPlatformTenantID(), "integration-route-"+unique, "quota_aware")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateRouteTarget(ctx, ModelRouteTargetInput{ModelID: model.ID, ProductScope: ProductScopeChat, Protocol: "responses", RoutePoolID: pool.ID, UpstreamModelID: "image-upstream-v1", Priority: 1, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if routes, err := store.ListRouteTargets(ctx, model.ID); err != nil || len(routes) != 1 || routes[0].UpstreamModelID != "image-upstream-v1" {
		t.Fatalf("routes=%+v err=%v", routes, err)
	}
	provider, err := store.CreateProviderConnection(ctx, ProviderConnectionInput{ProviderKind: "openai_compatible", ProviderName: "integration-provider-" + unique, BaseURL: "https://provider.example.invalid/v1", Credential: "integration-upstream-secret", Settings: json.RawMessage(`{"timeout_seconds":60}`), Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	accounts, err := store.ListProviderConnections(ctx)
	if err != nil {
		t.Fatal(err)
	}
	foundProvider := false
	for _, item := range accounts {
		if item.ID == provider.ID && item.HasCredential {
			foundProvider = true
			break
		}
	}
	if !foundProvider {
		t.Fatalf("provider credential state was not retained: %+v", accounts)
	}
	var encryptedCredential string
	if err := store.db.QueryRowContext(ctx, `SELECT credential_enc FROM provider_connections WHERE id=$1`, provider.ID).Scan(&encryptedCredential); err != nil || encryptedCredential == "integration-upstream-secret" || encryptedCredential == "" {
		t.Fatalf("provider secret was not encrypted: value=%q err=%v", encryptedCredential, err)
	}
	upstream, err := store.CreateUpstreamAccount(ctx, UpstreamAccountInput{ConnectionID: provider.ID, Label: "integration-account", ExternalReference: "account-" + unique, ModelCatalog: json.RawMessage(`[{"id":"image-upstream-v1"}]`), QuotaState: json.RawMessage(`{"remaining":100}`), Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AddRoutePoolMember(ctx, RoutePoolMemberInput{RoutePoolID: pool.ID, UpstreamAccountID: upstream.ID, Priority: 1, Weight: 100, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	selected, err := store.SelectRouteTarget(ctx, RouteSelectionRequest{ModelID: model.ID, ProductScope: ProductScopeChat, Protocol: "responses", AffinityHash: "integration-affinity-" + unique, StickyTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if selected.UpstreamAccountID != upstream.ID || selected.UpstreamModelID != "image-upstream-v1" || selected.Credential != "integration-upstream-secret" {
		t.Fatalf("unexpected route selection: %+v", selected)
	}
	if err := store.SetUpstreamAccountStatus(ctx, upstream.ID, "disabled"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SelectRouteTarget(ctx, RouteSelectionRequest{ModelID: model.ID, ProductScope: ProductScopeChat, Protocol: "responses", AffinityHash: "integration-after-disable-" + unique, StickyTTL: time.Hour}); !errors.Is(err, ErrNoRouteCandidate) {
		t.Fatalf("disabled account remained routable: %v", err)
	}

	userID := newPlatformID()
	if _, err := store.db.ExecContext(ctx, `INSERT INTO users(id, tenant_id, email, display_name) VALUES ($1,$2,$3,$4)`, userID, DefaultPlatformTenantID(), unique+"@integration.invalid", "integration"); err != nil {
		t.Fatal(err)
	}
	chatWallet, err := store.EnsureWallet(ctx, userID, ProductScopeChat)
	if err != nil {
		t.Fatal(err)
	}
	agentWallet, err := store.EnsureWallet(ctx, userID, ProductScopeAgent)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, walletID := range []string{chatWallet, agentWallet} {
		if _, err := store.GrantQuota(ctx, walletID, QuotaBucketInput{WindowKind: "monthly", StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour), Tokens: 1_000, Reference: "integration-month-" + unique, Reason: "test"}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.GrantQuota(ctx, walletID, QuotaBucketInput{WindowKind: "rolling_5h", StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour), Tokens: 500, Reference: "integration-rolling-" + unique, Reason: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	requestID := "request-" + unique
	if _, err := store.ReserveTokens(ctx, chatWallet, requestID, 100); err != nil {
		t.Fatal(err)
	}
	if err := store.SettleReservedTokens(ctx, chatWallet, requestID, 40); err != nil {
		t.Fatal(err)
	}
	var chatSettled, agentSettled int64
	if err := store.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(settled_tokens),0) FROM quota_buckets WHERE wallet_account_id=$1`, chatWallet).Scan(&chatSettled); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(settled_tokens),0) FROM quota_buckets WHERE wallet_account_id=$1`, agentWallet).Scan(&agentSettled); err != nil {
		t.Fatal(err)
	}
	if chatSettled != 80 || agentSettled != 0 {
		t.Fatalf("chat and agent must remain separate: chat=%d agent=%d", chatSettled, agentSettled)
	}

	modelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" || r.Header.Get("Authorization") != "Bearer integration-model-secret" {
			http.Error(w, "unexpected model discovery request", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"infinite-text","object":"model"},{"id":"infinite-image","object":"model"}]}`))
	}))
	defer modelServer.Close()
	compatible, err := store.CreateProviderConnection(ctx, ProviderConnectionInput{ProviderKind: "openai_compatible", ProviderName: "integration-compatible-" + unique, BaseURL: modelServer.URL + "/v1", Credential: "integration-model-secret", Settings: json.RawMessage(`{}`), Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	health, err := store.TestProviderConnection(ctx, compatible.ID)
	if err != nil || !health.Healthy || health.StatusCode != http.StatusOK {
		t.Fatalf("compatible provider health=%+v err=%v", health, err)
	}
	compatibleAccount, err := store.CreateUpstreamAccount(ctx, UpstreamAccountInput{ConnectionID: compatible.ID, Label: "compatible model account", ExternalReference: "compatible-" + unique, ModelCatalog: json.RawMessage(`[]`), QuotaState: json.RawMessage(`{}`), Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	discovered, err := store.SyncUpstreamAccountModels(ctx, compatibleAccount.ID)
	if err != nil || len(discovered) != 2 || discovered[0].RealModelID != "infinite-image" {
		t.Fatalf("compatible model sync=%+v err=%v", discovered, err)
	}
	if err := store.DeleteUpstreamAccount(ctx, compatibleAccount.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListUpstreamModelSnapshots(ctx, compatibleAccount.ID); err != nil {
		t.Fatal(err)
	}

	invitation, err := store.CreatePlatformInvitation(ctx, PlatformInvitationInput{RoleLabel: "Integration member", Policy: json.RawMessage(`{"chat_tokens":1000}`), ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	registered, err := store.RegisterUser(ctx, PlatformUserRegistration{Email: unique + "@user.integration.invalid", DisplayName: "Platform User", Password: "integration-user-password", InvitationToken: invitation.Token, InvitationCode: invitation.Code})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RegisterUser(ctx, PlatformUserRegistration{Email: unique + "-second@user.integration.invalid", DisplayName: "Platform User", Password: "integration-user-password", InvitationToken: invitation.Token, InvitationCode: invitation.Code}); !errors.Is(err, ErrPlatformInviteInvalid) {
		t.Fatalf("used invitation accepted: %v", err)
	}
	userToken, csrf, err := store.NewPlatformUserSession(ctx, registered.ID, "203.0.113.20", "integration-browser", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if sessionUser, err := store.PlatformUserSession(ctx, userToken, "203.0.113.25", "integration-browser"); err != nil || sessionUser.ID != registered.ID || !store.VerifyPlatformCSRF(ctx, userToken, csrf) {
		t.Fatalf("platform user session is not valid: user=%+v err=%v", sessionUser, err)
	}
	key, plainKey, err := store.CreatePlatformAPIKey(ctx, PlatformAPIKeyInput{UserID: registered.ID, RoutePoolID: pool.ID, Label: "integration external key", Scopes: []PlatformKeyScopeInput{{ProductScope: ProductScopeExternalAPI, ModelID: model.ID}}, IPPolicy: json.RawMessage(`{"mode":"allow_list","addresses":["203.0.113.0/24"]}`)})
	if err != nil {
		t.Fatal(err)
	}
	if authorized, err := store.AuthorizePlatformAPIKey(ctx, plainKey, "203.0.113.30"); err != nil || authorized.ID != key.ID || len(authorized.Scopes) != 1 {
		t.Fatalf("platform key authorization=%+v err=%v", authorized, err)
	}
	if _, err := store.AuthorizePlatformAPIKey(ctx, plainKey, "198.51.100.1"); !errors.Is(err, ErrPlatformKeyIPDenied) {
		t.Fatalf("platform key ignored IP policy: %v", err)
	}
	if copied, err := store.CopyPlatformAPIKey(ctx, key.ID); err != nil || copied != plainKey {
		t.Fatalf("platform key controlled copy mismatch: %q %v", copied, err)
	}
	if err := store.SetPlatformAPIKeyStatus(ctx, key.ID, "disabled"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthorizePlatformAPIKey(ctx, plainKey, "203.0.113.30"); !errors.Is(err, ErrPlatformKeyInactive) {
		t.Fatalf("disabled platform key remained authorized: %v", err)
	}
	if err := store.DeletePlatformAPIKey(ctx, key.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CopyPlatformAPIKey(ctx, key.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted platform key remained copyable: %v", err)
	}
}
