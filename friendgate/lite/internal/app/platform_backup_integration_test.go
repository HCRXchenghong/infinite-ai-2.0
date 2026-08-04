package app

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPlatformPortableBackupPostgresIntegration(t *testing.T) {
	dsn := os.Getenv("INFINITE_AI_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("INFINITE_AI_TEST_POSTGRES_URL is not set")
	}
	ctx := context.Background()
	sourceKey := bytes.Repeat([]byte{0x91}, 32)
	sourceVault, err := NewVault(sourceKey)
	if err != nil {
		t.Fatal(err)
	}
	sourceCfg := Config{
		DatabasePath: filepath.Join(t.TempDir(), "source-legacy.db"), PlatformDatabaseURL: dsn, PlatformGatewayEnabled: true,
		PlatformDBMaxOpen: 4, PlatformDBMaxIdle: 2, PlatformDBMaxLife: time.Minute,
		AdminUsername: "admin", AdminPassword: "platform-backup-admin-password", MasterKey: sourceKey,
		BanThreshold: 20, BanWindow: time.Minute, BanDuration: time.Hour, MaxBodyBytes: 4 << 20,
		StickyTTL: time.Hour, AccountCooldown: time.Minute, UserSessionTTL: time.Hour,
		DesktopFlowTTL: time.Minute, DesktopAccessTTL: time.Minute, DesktopRefreshTTL: time.Hour,
	}
	source, err := OpenStore(sourceCfg, sourceVault)
	if err != nil {
		t.Fatal(err)
	}
	platform := source.Platform()
	if err := platform.SetRegistrationMode(ctx, RegistrationPublic, ""); err != nil {
		t.Fatal(err)
	}
	unique := strings.ReplaceAll(newPlatformID(), "-", "")
	user, err := platform.RegisterUser(ctx, PlatformUserRegistration{Email: unique + "@backup.integration.invalid", DisplayName: "Backup user", Password: "platform-backup-password"})
	if err != nil {
		t.Fatal(err)
	}
	model, err := platform.CreatePlatformModel(ctx, PlatformModelInput{ModelKey: "backup-model-" + unique, DisplayName: "Backup model", Category: "chat", Capabilities: json.RawMessage(`{}`), Billing: json.RawMessage(`{}`), Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := platform.UpsertProductModelPublication(ctx, ProductModelPublicationInput{ModelID: model.ID, ProductScope: ProductScopeExternalAPI, Protocol: "responses", Enabled: true, PlanRules: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	pool, err := platform.CreateRoutePool(ctx, DefaultPlatformTenantID(), "backup-pool-"+unique, "quota_aware")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := platform.CreateProviderConnection(ctx, ProviderConnectionInput{ProviderKind: "openai_compatible", ProviderName: "backup-provider-" + unique, BaseURL: "https://backup-upstream.invalid/v1", Credential: "platform-backup-provider-secret", Settings: json.RawMessage(`{}`), Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	account, err := platform.CreateUpstreamAccount(ctx, UpstreamAccountInput{ConnectionID: provider.ID, Label: "backup account", ExternalReference: "backup-account-" + unique, Credential: "platform-backup-upstream-secret", ModelCatalog: json.RawMessage(`[{"id":"private-backup-model"}]`), QuotaState: json.RawMessage(`{}`), Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if err := platform.AddRoutePoolMember(ctx, RoutePoolMemberInput{RoutePoolID: pool.ID, UpstreamAccountID: account.ID, Priority: 1, Weight: 1, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := platform.CreateRouteTarget(ctx, ModelRouteTargetInput{ModelID: model.ID, ProductScope: ProductScopeExternalAPI, Protocol: "responses", RoutePoolID: pool.ID, UpstreamModelID: "private-backup-model", Priority: 1, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	key, plainKey, err := platform.CreatePlatformAPIKey(ctx, PlatformAPIKeyInput{UserID: user.ID, RoutePoolID: pool.ID, Label: "backup key", Scopes: []PlatformKeyScopeInput{{ProductScope: ProductScopeExternalAPI, ModelID: model.ID}}})
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := platform.CreatePlatformChatConversation(ctx, user.ID, PlatformChatConversationInput{Title: "Backup chat", SelectedModelKey: model.ModelKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := platform.AppendPlatformChatMessage(ctx, PlatformChatMessageInput{ConversationID: conversation.ID, UserID: user.ID, Role: "user", Text: "persist me", ModelKey: model.ModelKey, Status: "sent"}); err != nil {
		t.Fatal(err)
	}
	if _, err := platform.AppendPlatformChatMessage(ctx, PlatformChatMessageInput{ConversationID: conversation.ID, UserID: user.ID, Role: "assistant", Text: "restored markdown **ok**", ModelKey: model.ModelKey, Status: "sent"}); err != nil {
		t.Fatal(err)
	}
	backupPath, size, err := platform.createPlatformPortableBackupFile(ctx, portableTestPassphrase, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if size <= 0 {
		t.Fatalf("platform backup size=%d", size)
	}
	t.Cleanup(func() { _ = os.Remove(backupPath) })
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}

	targetKey := bytes.Repeat([]byte{0x92}, 32)
	targetVault, err := NewVault(targetKey)
	if err != nil {
		t.Fatal(err)
	}
	targetCfg := sourceCfg
	targetCfg.DatabasePath = filepath.Join(t.TempDir(), "target-legacy.db")
	targetCfg.MasterKey = targetKey
	target, err := OpenStore(targetCfg, targetVault)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	server := NewServer(targetCfg, target, targetVault)
	summary, err := server.restorePortableBackupFile(ctx, backupPath, portableTestPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Tables == 0 || summary.Rows == 0 {
		t.Fatalf("empty platform restore summary: %+v", summary)
	}
	restoredPlatform := target.Platform()
	copiedKey, err := restoredPlatform.CopyPlatformAPIKey(ctx, key.ID)
	if err != nil {
		t.Fatal(err)
	}
	if copiedKey != plainKey {
		t.Fatalf("restored platform API key mismatch: %q", copiedKey)
	}
	route, err := restoredPlatform.SelectRouteTarget(ctx, RouteSelectionRequest{ModelID: model.ID, ProductScope: ProductScopeExternalAPI, Protocol: "responses", RoutePoolID: pool.ID, AffinityHash: "backup-restore-" + unique, StickyTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if route.Credential != "platform-backup-upstream-secret" || route.UpstreamModelID != "private-backup-model" {
		t.Fatalf("restored route credential/model mismatch: %+v", route)
	}
	restoredConversation, restoredMessages, err := restoredPlatform.PlatformChatConversation(ctx, user.ID, conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if restoredConversation.Title != "Backup chat" || len(restoredMessages) != 2 || restoredMessages[1].Text != "restored markdown **ok**" {
		t.Fatalf("restored chat history mismatch: conversation=%+v messages=%+v", restoredConversation, restoredMessages)
	}
}
