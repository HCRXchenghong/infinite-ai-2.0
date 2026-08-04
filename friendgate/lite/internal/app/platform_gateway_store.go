package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrPlatformModelDenied       = errors.New("platform model is not available to this key")
	ErrPlatformPublicationAbsent = errors.New("platform model is not published for this protocol")
)

// PlatformUsageSettlement is the minimum, privacy-preserving request record
// written by the public gateway.  It intentionally has no request or response
// body field: raw payload logging is a separate, short-lived diagnostic mode,
// never a side effect of normal use.
type PlatformUsageSettlement struct {
	RequestID         string
	UserID            string
	APIKeyID          string
	ModelID           string
	UpstreamAccountID string
	ProductScope      ProductScope
	Protocol          string
	SessionScopeHash  string
	StatusCode        int
	InputTokens       int64
	CachedInputTokens int64
	OutputTokens      int64
	ReasoningTokens   int64
	BilledTokens      int64
	Estimated         bool
	ToolSummary       json.RawMessage
	ErrorCode         string
	DurationMS        int64
}

// PlatformProductModel is a public model alias together with the current
// routability result. It deliberately contains neither a route target nor any
// source provider metadata.
type PlatformProductModel struct {
	PlatformModel
	Available bool `json:"available"`
}

// ListPlatformProductModelsForUser is used by Chat/Agent surfaces. It applies
// the active subscription's optional publication rule and then checks that at
// least one active same-protocol route exists. A draft mapping is therefore
// visible only to administrators, never as a clickable user model.
func (s *PlatformStore) ListPlatformProductModelsForUser(ctx context.Context, userID string, scope ProductScope, protocol string) ([]PlatformProductModel, error) {
	return s.ListPlatformProductModelsForUserProtocols(ctx, userID, scope, []string{protocol})
}

func (s *PlatformStore) ListPlatformProductModelsForUserProtocols(ctx context.Context, userID string, scope ProductScope, protocols []string) ([]PlatformProductModel, error) {
	userID = strings.TrimSpace(userID)
	protocols, err := normalizePlatformProtocols(protocols)
	if userID == "" || !scope.Valid() || err != nil {
		return nil, ErrInvalidPlatformModel
	}
	var planCode string
	err = s.db.QueryRowContext(ctx, `SELECT p.code FROM subscriptions s JOIN plan_versions v ON v.id=s.plan_version_id JOIN plans p ON p.id=v.plan_id JOIN users u ON u.id=s.user_id AND u.status='active'
WHERE s.user_id=$1 AND s.status IN ('trialing','active') AND s.starts_at<=now() AND s.ends_at>now()
ORDER BY s.ends_at DESC LIMIT 1`, userID).Scan(&planCode)
	if errors.Is(err, sql.ErrNoRows) {
		return []PlatformProductModel{}, nil
	}
	if err != nil {
		return nil, err
	}
	placeholders, args := platformProtocolPlaceholders(2, protocols)
	args = append([]any{scope}, args...)
	query := `SELECT m.id::text,m.model_key,m.display_name,m.description,m.category,m.capabilities,m.billing,m.status,m.created_at,m.updated_at,p.protocol,p.plan_rules,
EXISTS(SELECT 1 FROM model_route_targets t JOIN route_pools rp ON rp.id=t.route_pool_id AND rp.status='active' JOIN route_pool_members rm ON rm.route_pool_id=rp.id AND rm.enabled JOIN upstream_accounts a ON a.id=rm.upstream_account_id AND a.status='active' AND (a.cooldown_until IS NULL OR a.cooldown_until<=now()) JOIN provider_connections c ON c.id=a.connection_id AND c.status='active' WHERE t.model_id=m.id AND t.product_scope=p.product_scope AND t.protocol=p.protocol AND t.enabled) AS available
FROM product_model_publications p JOIN platform_models m ON m.id=p.model_id AND m.status='active'
WHERE p.product_scope=$1 AND p.protocol IN (` + placeholders + `) AND p.enabled ORDER BY m.model_key,p.protocol`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PlatformProductModel, 0)
	byID := make(map[string]int)
	for rows.Next() {
		var item PlatformProductModel
		var rules json.RawMessage
		var publicationProtocol string
		if err := rows.Scan(&item.ID, &item.ModelKey, &item.DisplayName, &item.Description, &item.Category, &item.Capabilities, &item.Billing, &item.Status, &item.CreatedAt, &item.UpdatedAt, &publicationProtocol, &rules, &item.Available); err != nil {
			return nil, err
		}
		if !platformPublicationAllowedForPlan(rules, planCode) {
			continue
		}
		if index, exists := byID[item.ID]; exists {
			items[index].Available = items[index].Available || item.Available
			continue
		}
		byID[item.ID] = len(items)
		items = append(items, item)
	}
	return items, rows.Err()
}

func platformPublicationAllowedForPlan(rules json.RawMessage, planCode string) bool {
	var policy struct {
		AllowedPlans []string `json:"allowed_plans"`
	}
	if json.Unmarshal(rules, &policy) != nil || len(policy.AllowedPlans) == 0 {
		return true
	}
	for _, code := range policy.AllowedPlans {
		if strings.EqualFold(strings.TrimSpace(code), planCode) {
			return true
		}
	}
	return false
}

func (s *PlatformStore) ResolvePlatformProductModelForUser(ctx context.Context, userID string, scope ProductScope, protocol, modelKey string) (*PlatformModel, error) {
	modelKey = strings.TrimSpace(strings.ToLower(modelKey))
	if modelKey == "" || len(modelKey) > 128 {
		return nil, ErrPlatformModelDenied
	}
	items, err := s.ListPlatformProductModelsForUser(ctx, userID, scope, protocol)
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		if item.ModelKey == modelKey && item.Available {
			model := item.PlatformModel
			return &model, nil
		}
	}
	return nil, ErrPlatformModelDenied
}

// ResolvePlatformGatewayModel verifies the three separate controls required
// to expose a model: the key scope, the public product publication, and the
// active platform model. It never accepts an upstream model ID from a client.
func (s *PlatformStore) ResolvePlatformGatewayModel(ctx context.Context, key *PlatformAPIKey, modelKey string, scope ProductScope, protocol string) (*PlatformModel, error) {
	if key == nil || strings.TrimSpace(key.ID) == "" || !scope.Valid() || !validProtocol(strings.TrimSpace(strings.ToLower(protocol))) {
		return nil, ErrPlatformModelDenied
	}
	modelKey = strings.TrimSpace(strings.ToLower(modelKey))
	if modelKey == "" || len(modelKey) > 128 {
		return nil, ErrPlatformModelDenied
	}
	protocol = strings.TrimSpace(strings.ToLower(protocol))
	model := &PlatformModel{}
	err := s.db.QueryRowContext(ctx, `SELECT m.id::text,m.model_key,m.display_name,m.description,m.category,m.capabilities,m.billing,m.status,m.created_at,m.updated_at
FROM api_key_scopes k
JOIN platform_models m ON m.id=k.model_id AND m.status='active'
JOIN product_model_publications p ON p.model_id=m.id AND p.product_scope=k.product_scope AND p.protocol=$4 AND p.enabled
WHERE k.api_key_id=$1 AND k.product_scope=$2 AND m.model_key=$3`, key.ID, scope, modelKey, protocol).Scan(
		&model.ID, &model.ModelKey, &model.DisplayName, &model.Description, &model.Category, &model.Capabilities, &model.Billing, &model.Status, &model.CreatedAt, &model.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		// Do not distinguish a disabled publication from a model omitted from a
		// key: that information would be useful for key probing.
		return nil, ErrPlatformModelDenied
	}
	if err != nil {
		return nil, err
	}
	return model, nil
}

// ListPlatformGatewayModels returns only model aliases explicitly authorized
// for this key. Source-account catalogs remain private administrator data.
func (s *PlatformStore) ListPlatformGatewayModels(ctx context.Context, key *PlatformAPIKey, scope ProductScope) ([]PlatformModel, error) {
	return s.ListPlatformGatewayModelsForProtocols(ctx, key, scope, []string{"responses", "chat_completions", "messages", "generate_content"})
}

func (s *PlatformStore) ListPlatformGatewayModelsForProtocols(ctx context.Context, key *PlatformAPIKey, scope ProductScope, protocols []string) ([]PlatformModel, error) {
	if key == nil || strings.TrimSpace(key.ID) == "" || !scope.Valid() {
		return nil, ErrPlatformModelDenied
	}
	protocols, err := normalizePlatformProtocols(protocols)
	if err != nil {
		return nil, ErrPlatformModelDenied
	}
	placeholders, args := platformProtocolPlaceholders(3, protocols)
	args = append([]any{key.ID, scope}, args...)
	query := `SELECT DISTINCT m.id::text,m.model_key,m.display_name,m.description,m.category,m.capabilities,m.billing,m.status,m.created_at,m.updated_at
FROM api_key_scopes k
JOIN platform_models m ON m.id=k.model_id AND m.status='active'
JOIN product_model_publications p ON p.model_id=m.id AND p.product_scope=k.product_scope AND p.enabled AND p.protocol IN (` + placeholders + `)
WHERE k.api_key_id=$1 AND k.product_scope=$2
ORDER BY m.model_key`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PlatformModel, 0)
	for rows.Next() {
		var item PlatformModel
		if err := rows.Scan(&item.ID, &item.ModelKey, &item.DisplayName, &item.Description, &item.Category, &item.Capabilities, &item.Billing, &item.Status, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// RecordPlatformUsageAndSettle atomically changes both quota windows and
// writes their corresponding request record.  It is deliberately one
// transaction, so the dashboard can never claim a request consumed tokens
// while the ledger says it did not (or the reverse).
func (s *PlatformStore) RecordPlatformUsageAndSettle(ctx context.Context, walletID, referenceID string, input PlatformUsageSettlement) error {
	walletID = strings.TrimSpace(walletID)
	referenceID = strings.TrimSpace(referenceID)
	input.RequestID = strings.TrimSpace(input.RequestID)
	input.Protocol = strings.TrimSpace(strings.ToLower(input.Protocol))
	if walletID == "" || referenceID == "" || input.RequestID == "" || input.UserID == "" || input.ModelID == "" || input.UpstreamAccountID == "" || !input.ProductScope.Valid() || !validProtocol(input.Protocol) || input.StatusCode < 100 || input.StatusCode > 599 || input.BilledTokens < 0 {
		return fmt.Errorf("%w: gateway usage settlement", ErrInvalidPlan)
	}
	if len(input.ToolSummary) == 0 {
		input.ToolSummary = json.RawMessage(`{}`)
	}
	if !isJSONObject(input.ToolSummary) {
		return fmt.Errorf("%w: gateway tool summary", ErrInvalidPlan)
	}
	input.ErrorCode = truncate(strings.TrimSpace(input.ErrorCode), 120)
	if input.DurationMS < 0 {
		input.DurationMS = 0
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var alreadyRecorded bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM usage_records WHERE tenant_id=$1 AND request_id=$2)`, DefaultPlatformTenantID(), input.RequestID).Scan(&alreadyRecorded); err != nil {
		return err
	}
	if alreadyRecorded {
		return tx.Commit()
	}

	rows, err := tx.QueryContext(ctx, `SELECT b.id::text,b.granted_tokens,b.reserved_tokens,b.settled_tokens,l.tokens
FROM ledger_entries l
JOIN quota_buckets b ON b.id=l.quota_bucket_id
WHERE l.wallet_account_id=$1 AND l.entry_type='reserve' AND l.reference_type='request' AND l.reference_id=$2
FOR UPDATE`, walletID, referenceID)
	if err != nil {
		return err
	}
	type heldBucket struct {
		id                               string
		granted, reserved, settled, held int64
	}
	buckets := make([]heldBucket, 0, 2)
	for rows.Next() {
		var bucket heldBucket
		if err := rows.Scan(&bucket.id, &bucket.granted, &bucket.reserved, &bucket.settled, &bucket.held); err != nil {
			_ = rows.Close()
			return err
		}
		buckets = append(buckets, bucket)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(buckets) != 2 {
		return ErrNotFound
	}
	// The same reserve is held in both windows, therefore the smallest hold is
	// the valid billable amount. The gateway chooses its hold from the client's
	// max-output declaration; a nonconforming upstream is capped and clearly
	// marked rather than allowing quota counters to become inconsistent.
	maxHeld := buckets[0].held
	for _, bucket := range buckets[1:] {
		if bucket.held < maxHeld {
			maxHeld = bucket.held
		}
	}
	settle := input.BilledTokens
	if settle > maxHeld {
		settle = maxHeld
		input.BilledTokens = settle
		input.Estimated = true
		if input.ErrorCode == "" {
			input.ErrorCode = "usage_capped_at_reservation"
		}
	}
	for _, bucket := range buckets {
		if bucket.reserved < bucket.held || bucket.granted-bucket.reserved-bucket.settled+bucket.held < settle {
			return ErrQuotaExceeded
		}
		if _, err := tx.ExecContext(ctx, `UPDATE quota_buckets SET reserved_tokens=reserved_tokens-$2,settled_tokens=settled_tokens+$3,updated_at=now() WHERE id=$1`, bucket.id, bucket.held, settle); err != nil {
			return err
		}
		if settle > 0 {
			if _, err := tx.ExecContext(ctx, `INSERT INTO ledger_entries(id,wallet_account_id,quota_bucket_id,entry_type,tokens,reference_type,reference_id,reason) VALUES($1,$2,$3,'settle',$4,'request',$5,'actual gateway token use')`, newPlatformID(), walletID, bucket.id, settle, referenceID); err != nil {
				return err
			}
		}
		if released := bucket.held - settle; released > 0 {
			if _, err := tx.ExecContext(ctx, `INSERT INTO ledger_entries(id,wallet_account_id,quota_bucket_id,entry_type,tokens,reference_type,reference_id,reason) VALUES($1,$2,$3,'release',$4,'request',$5,'unused gateway token hold released')`, newPlatformID(), walletID, bucket.id, released, referenceID); err != nil {
				return err
			}
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO usage_records(id,tenant_id,user_id,api_key_id,model_id,upstream_account_id,product_scope,protocol,request_id,session_scope_hash,status_code,input_tokens,cached_input_tokens,output_tokens,reasoning_tokens,billed_tokens,estimated,tool_summary,error_code,duration_ms)
VALUES($1,$2,$3,NULLIF($4,'')::uuid,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18::jsonb,$19,$20)`,
		newPlatformID(), DefaultPlatformTenantID(), input.UserID, input.APIKeyID, input.ModelID, input.UpstreamAccountID, input.ProductScope, input.Protocol, input.RequestID, input.SessionScopeHash, input.StatusCode, input.InputTokens, input.CachedInputTokens, input.OutputTokens, input.ReasoningTokens, input.BilledTokens, input.Estimated, string(input.ToolSummary), input.ErrorCode, input.DurationMS)
	if err != nil {
		return err
	}
	return tx.Commit()
}
