package app

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPlatformQuotaRenewalAndAdminRechargeIntegration(t *testing.T) {
	dsn := os.Getenv("INFINITE_AI_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("INFINITE_AI_TEST_POSTGRES_URL is not set")
	}
	ctx := context.Background()
	store, err := OpenPlatformStore(ctx, Config{PlatformDatabaseURL: dsn, PlatformDBMaxOpen: 4, PlatformDBMaxIdle: 2, PlatformDBMaxLife: time.Minute, MasterKey: bytes.Repeat([]byte{0x73}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	previousMode, err := store.RegistrationMode(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetRegistrationMode(ctx, RegistrationPublic, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.SetRegistrationMode(context.Background(), previousMode, "") })
	unique := strings.ReplaceAll(newPlatformID(), "-", "")
	user, err := store.RegisterUser(ctx, PlatformUserRegistration{Email: unique + "@quota.integration.invalid", DisplayName: "quota integration", Password: "correct-horse-battery-staple"})
	if err != nil {
		t.Fatal(err)
	}
	walletID, err := store.EnsureProductQuota(ctx, user.ID, ProductScopeChat)
	if err != nil {
		t.Fatal(err)
	}
	var expiredRolling string
	if err := store.db.QueryRowContext(ctx, `SELECT id::text FROM quota_buckets WHERE wallet_account_id=$1 AND window_kind='rolling_5h' ORDER BY ends_at DESC LIMIT 1`, walletID).Scan(&expiredRolling); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE quota_buckets SET ends_at=now()-interval '1 second' WHERE id=$1`, expiredRolling); err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnsureProductQuota(ctx, user.ID, ProductScopeChat); err != nil {
		t.Fatal(err)
	}
	var activeRolling int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM quota_buckets WHERE wallet_account_id=$1 AND window_kind='rolling_5h' AND starts_at<=now() AND ends_at>now()`, walletID).Scan(&activeRolling); err != nil {
		t.Fatal(err)
	}
	if activeRolling != 1 {
		t.Fatalf("expected exactly one active rolling bucket, got %d", activeRolling)
	}
	before, err := store.ListPlatformWalletSummaries(ctx, user.ID)
	if err != nil || len(before) != 2 {
		t.Fatalf("wallet summaries before recharge=%+v err=%v", before, err)
	}
	var beforeChat PlatformWalletSummary
	for _, item := range before {
		if item.ProductScope == ProductScopeChat {
			beforeChat = item
		}
	}
	if err := store.GrantPlatformWalletTokens(ctx, user.ID, ProductScopeChat, 12_345, "integration recharge"); err != nil {
		t.Fatal(err)
	}
	after, err := store.ListPlatformWalletSummaries(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	var afterChat PlatformWalletSummary
	for _, item := range after {
		if item.ProductScope == ProductScopeChat {
			afterChat = item
		}
	}
	if afterChat.MonthlyRemaining-beforeChat.MonthlyRemaining != 12_345 || afterChat.RollingRemaining-beforeChat.RollingRemaining != 12_345 {
		t.Fatalf("recharge was not isolated and applied to both active chat limits: before=%+v after=%+v", beforeChat, afterChat)
	}
	var agentRechargeEntries int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ledger_entries l JOIN wallet_accounts w ON w.id=l.wallet_account_id WHERE w.user_id=$1 AND w.product_scope='agent' AND l.entry_type='recharge'`, user.ID).Scan(&agentRechargeEntries); err != nil {
		t.Fatal(err)
	}
	if agentRechargeEntries != 0 {
		t.Fatalf("Chat recharge must not reach Agent wallet: %d agent recharge entries", agentRechargeEntries)
	}
}
