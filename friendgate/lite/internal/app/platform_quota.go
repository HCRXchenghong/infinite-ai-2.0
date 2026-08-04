package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// EnsureProductQuota returns one product-only wallet and makes the current
// subscription period usable.  A wallet is never shared between Chat, Agent
// and external API.  In particular, an exhausted five-hour window is not
// replaced until the previous window has genuinely ended.
func (s *PlatformStore) EnsureProductQuota(ctx context.Context, userID string, scope ProductScope) (string, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" || !scope.Valid() {
		return "", fmt.Errorf("%w: product quota", ErrInvalidPlan)
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()

	var subscriptionID, planCode string
	var subscriptionEnds time.Time
	var monthlyTokens, rollingTokens int64
	err = tx.QueryRowContext(ctx, `SELECT s.id::text,p.code,s.ends_at,
CASE WHEN $2='chat' THEN v.chat_monthly_tokens WHEN $2='agent' THEN v.agent_monthly_tokens ELSE 0 END,
CASE WHEN $2='chat' THEN v.chat_rolling_5h_tokens WHEN $2='agent' THEN v.agent_rolling_5h_tokens ELSE 0 END
FROM subscriptions s JOIN plan_versions v ON v.id=s.plan_version_id JOIN plans p ON p.id=v.plan_id
WHERE s.user_id=$1 AND s.status IN ('trialing','active') AND s.starts_at<=now() AND s.ends_at>now()
ORDER BY s.ends_at DESC LIMIT 1 FOR UPDATE`, userID, scope).Scan(&subscriptionID, &planCode, &subscriptionEnds, &monthlyTokens, &rollingTokens)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if errors.Is(err, sql.ErrNoRows) {
		// A user with no currently active entitlement falls back to the current
		// Free plan. Paid renewals are intentionally not simulated here: they
		// must later be created by a verified payment or an administrator grant.
		var versionID string
		var chatMonthly, agentMonthly, chatRolling, agentRolling int64
		if err := tx.QueryRowContext(ctx, `SELECT v.id::text,v.chat_monthly_tokens,v.agent_monthly_tokens,v.chat_rolling_5h_tokens,v.agent_rolling_5h_tokens
FROM plans p JOIN plan_versions v ON v.plan_id=p.id AND v.ends_at IS NULL
WHERE p.code='free' AND p.status='active' FOR SHARE`).Scan(&versionID, &chatMonthly, &agentMonthly, &chatRolling, &agentRolling); err != nil {
			return "", err
		}
		if scope == ProductScopeChat {
			monthlyTokens, rollingTokens = chatMonthly, chatRolling
		} else if scope == ProductScopeAgent {
			monthlyTokens, rollingTokens = agentMonthly, agentRolling
		}
		subscriptionID = newPlatformID()
		subscriptionEnds = now.AddDate(0, 1, 0)
		snapshot := mustJSON(map[string]any{"plan_code": "free", "plan_version_id": versionID, "assigned_at": now.Format(time.RFC3339), "reason": "automatic_free_renewal"})
		if _, err := tx.ExecContext(ctx, `INSERT INTO subscriptions(id,user_id,plan_version_id,status,source,starts_at,ends_at,snapshot) VALUES($1,$2,$3,'active','free_assignment',$4,$5,$6::jsonb)`, subscriptionID, userID, versionID, now, subscriptionEnds, snapshot); err != nil {
			return "", err
		}
	}

	walletID := newPlatformID()
	if err := tx.QueryRowContext(ctx, `INSERT INTO wallet_accounts(id,user_id,product_scope) VALUES($1,$2,$3)
ON CONFLICT (user_id,product_scope) DO UPDATE SET updated_at=wallet_accounts.updated_at
RETURNING id::text`, walletID, userID, scope).Scan(&walletID); err != nil {
		return "", err
	}
	// External API is intentionally not funded by a Chat/Agent membership.
	// It receives zero-value current buckets so a later administrator recharge
	// has a real reservation target without coupling it to either membership
	// wallet.
	if scope == ProductScopeExternalAPI {
		monthlyTokens, rollingTokens = 0, 0
	}
	for _, allocation := range []struct {
		window string
		tokens int64
		ends   time.Time
	}{
		{window: "monthly", tokens: monthlyTokens, ends: subscriptionEnds},
		{window: "rolling_5h", tokens: rollingTokens, ends: now.Add(5 * time.Hour)},
	} {
		var present bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM quota_buckets WHERE wallet_account_id=$1 AND window_kind=$2 AND starts_at<=now() AND ends_at>now())`, walletID, allocation.window).Scan(&present); err != nil {
			return "", err
		}
		if present {
			continue
		}
		if allocation.tokens < 0 || !allocation.ends.After(now) {
			return "", fmt.Errorf("%w: active subscription quota", ErrInvalidPlan)
		}
		bucketID := newPlatformID()
		if _, err := tx.ExecContext(ctx, `INSERT INTO quota_buckets(id,wallet_account_id,window_kind,starts_at,ends_at,granted_tokens,source_subscription_id) VALUES($1,$2,$3,$4,$5,$6,$7)`, bucketID, walletID, allocation.window, now, allocation.ends, allocation.tokens, subscriptionID); err != nil {
			return "", err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO ledger_entries(id,wallet_account_id,quota_bucket_id,entry_type,tokens,reference_type,reference_id,reason) VALUES($1,$2,$3,'grant',$4,'subscription',$5,$6)`, newPlatformID(), walletID, bucketID, allocation.tokens, subscriptionID, "subscription quota allocation"); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return walletID, nil
}

// GrantPlatformWalletTokens is the administrator-controlled recharge path.
// It increases the currently active monthly and rolling buckets together so
// the reservation algorithm continues to enforce both limits. It never
// creates a third, ignored "grant" bucket.
func (s *PlatformStore) GrantPlatformWalletTokens(ctx context.Context, userID string, scope ProductScope, tokens int64, reason string) error {
	userID, reason = strings.TrimSpace(userID), strings.TrimSpace(reason)
	if userID == "" || !scope.Valid() || tokens <= 0 || tokens > 1_000_000_000 || reason == "" || len(reason) > 500 {
		return fmt.Errorf("%w: wallet recharge", ErrInvalidPlan)
	}
	walletID, err := s.EnsureProductQuota(ctx, userID, scope)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT id::text FROM quota_buckets WHERE wallet_account_id=$1 AND window_kind IN ('monthly','rolling_5h') AND starts_at<=now() AND ends_at>now() FOR UPDATE`, walletID)
	if err != nil {
		return err
	}
	buckets := make([]string, 0, 2)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		buckets = append(buckets, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(buckets) != 2 {
		return ErrQuotaExceeded
	}
	referenceID := "admin-credit-" + newPlatformID()
	for _, bucketID := range buckets {
		if _, err := tx.ExecContext(ctx, `UPDATE quota_buckets SET granted_tokens=granted_tokens+$2,updated_at=now() WHERE id=$1`, bucketID, tokens); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO ledger_entries(id,wallet_account_id,quota_bucket_id,entry_type,tokens,reference_type,reference_id,reason) VALUES($1,$2,$3,'recharge',$4,'admin_credit',$5,$6)`, newPlatformID(), walletID, bucketID, tokens, referenceID, reason); err != nil {
			return err
		}
	}
	return tx.Commit()
}
