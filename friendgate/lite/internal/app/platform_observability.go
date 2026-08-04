package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// PlatformDashboard is deliberately calculated from the PostgreSQL product
// tables.  It contains no synthetic counters and no request/response bodies.
// The admin page can poll this lightweight snapshot without inspecting the
// legacy SQLite transition store.
type PlatformDashboard struct {
	CheckedAt      time.Time                `json:"checked_at"`
	Users          int64                    `json:"users"`
	ActiveUsers    int64                    `json:"active_users"`
	ActiveAPIKeys  int64                    `json:"active_api_keys"`
	ActiveDevices  int64                    `json:"active_devices"`
	TodayRequests  int64                    `json:"today_requests"`
	TodayTokens    int64                    `json:"today_tokens"`
	TodayErrors    int64                    `json:"today_errors"`
	TodayEstimated int64                    `json:"today_estimated"`
	ModelRanking   []PlatformModelUsageRank `json:"model_ranking"`
	ScopeUsage     []PlatformScopeUsage     `json:"scope_usage"`
}

type PlatformModelUsageRank struct {
	ModelKey string `json:"model_key"`
	Requests int64  `json:"requests"`
	Tokens   int64  `json:"tokens"`
	Errors   int64  `json:"errors"`
}

type PlatformScopeUsage struct {
	ProductScope ProductScope `json:"product_scope"`
	Requests     int64        `json:"requests"`
	Tokens       int64        `json:"tokens"`
	Errors       int64        `json:"errors"`
}

// PlatformUsageRecord is a privacy-preserving administrative call record. It
// deliberately excludes Authorization values, cookies, OAuth material and raw
// prompt/response text.
type PlatformUsageRecord struct {
	ID                string          `json:"id"`
	RequestID         string          `json:"request_id"`
	UserID            string          `json:"user_id,omitempty"`
	UserEmail         string          `json:"user_email,omitempty"`
	APIKeyID          string          `json:"api_key_id,omitempty"`
	APIKeyLabel       string          `json:"api_key_label,omitempty"`
	ProjectID         string          `json:"project_id,omitempty"`
	DeviceID          string          `json:"device_id,omitempty"`
	PlatformModelID   string          `json:"platform_model_id,omitempty"`
	PlatformModelKey  string          `json:"platform_model_key,omitempty"`
	UpstreamAccountID string          `json:"upstream_account_id,omitempty"`
	UpstreamLabel     string          `json:"upstream_label,omitempty"`
	ProductScope      ProductScope    `json:"product_scope"`
	Protocol          string          `json:"protocol"`
	StatusCode        int             `json:"status_code"`
	InputTokens       int64           `json:"input_tokens"`
	OutputTokens      int64           `json:"output_tokens"`
	ReasoningTokens   int64           `json:"reasoning_tokens"`
	BilledTokens      int64           `json:"billed_tokens"`
	Estimated         bool            `json:"estimated"`
	ToolSummary       json.RawMessage `json:"tool_summary"`
	ErrorCode         string          `json:"error_code,omitempty"`
	DurationMS        int64           `json:"duration_ms"`
	CreatedAt         time.Time       `json:"created_at"`
}

type PlatformWalletSummary struct {
	UserID           string       `json:"user_id"`
	UserEmail        string       `json:"user_email"`
	DisplayName      string       `json:"display_name"`
	UserStatus       string       `json:"user_status"`
	PlanCode         string       `json:"plan_code,omitempty"`
	ProductScope     ProductScope `json:"product_scope"`
	MonthlyGranted   int64        `json:"monthly_granted"`
	MonthlyUsed      int64        `json:"monthly_used"`
	MonthlyReserved  int64        `json:"monthly_reserved"`
	MonthlyRemaining int64        `json:"monthly_remaining"`
	MonthlyEndsAt    *time.Time   `json:"monthly_ends_at,omitempty"`
	RollingGranted   int64        `json:"rolling_granted"`
	RollingUsed      int64        `json:"rolling_used"`
	RollingReserved  int64        `json:"rolling_reserved"`
	RollingRemaining int64        `json:"rolling_remaining"`
	RollingEndsAt    *time.Time   `json:"rolling_ends_at,omitempty"`
}

type PlatformAuditRecord struct {
	ID         string          `json:"id"`
	ActorKind  string          `json:"actor_kind"`
	Action     string          `json:"action"`
	TargetKind string          `json:"target_kind"`
	TargetID   string          `json:"target_id"`
	IP         string          `json:"ip"`
	Metadata   json.RawMessage `json:"metadata"`
	CreatedAt  time.Time       `json:"created_at"`
}

func (s *PlatformStore) PlatformDashboard(ctx context.Context) (*PlatformDashboard, error) {
	result := &PlatformDashboard{CheckedAt: time.Now().UTC(), ModelRanking: make([]PlatformModelUsageRank, 0), ScopeUsage: make([]PlatformScopeUsage, 0)}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*),COUNT(*) FILTER (WHERE status='active') FROM users WHERE tenant_id=$1`, DefaultPlatformTenantID()).Scan(&result.Users, &result.ActiveUsers); err != nil {
		return nil, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_keys_v2 WHERE status='active'`).Scan(&result.ActiveAPIKeys); err != nil {
		return nil, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_devices WHERE status='active'`).Scan(&result.ActiveDevices); err != nil {
		return nil, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(billed_tokens),0),COUNT(*) FILTER (WHERE status_code >= 400),COUNT(*) FILTER (WHERE estimated)
FROM usage_records WHERE tenant_id=$1 AND created_at >= date_trunc('day', now())`, DefaultPlatformTenantID()).Scan(&result.TodayRequests, &result.TodayTokens, &result.TodayErrors, &result.TodayEstimated); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT COALESCE(m.model_key,'已删除模型'),COUNT(*),COALESCE(SUM(u.billed_tokens),0),COUNT(*) FILTER (WHERE u.status_code >= 400)
FROM usage_records u LEFT JOIN platform_models m ON m.id=u.model_id
WHERE u.tenant_id=$1 AND u.created_at >= date_trunc('day', now())
GROUP BY m.model_key ORDER BY COUNT(*) DESC,COALESCE(SUM(u.billed_tokens),0) DESC LIMIT 10`, DefaultPlatformTenantID())
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var item PlatformModelUsageRank
		if err := rows.Scan(&item.ModelKey, &item.Requests, &item.Tokens, &item.Errors); err != nil {
			_ = rows.Close()
			return nil, err
		}
		result.ModelRanking = append(result.ModelRanking, item)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	rows, err = s.db.QueryContext(ctx, `SELECT product_scope,COUNT(*),COALESCE(SUM(billed_tokens),0),COUNT(*) FILTER (WHERE status_code >= 400)
FROM usage_records WHERE tenant_id=$1 AND created_at >= date_trunc('day', now())
GROUP BY product_scope ORDER BY product_scope`, DefaultPlatformTenantID())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var item PlatformScopeUsage
		if err := rows.Scan(&item.ProductScope, &item.Requests, &item.Tokens, &item.Errors); err != nil {
			return nil, err
		}
		result.ScopeUsage = append(result.ScopeUsage, item)
	}
	return result, rows.Err()
}

func (s *PlatformStore) ListPlatformUsage(ctx context.Context, limit int) ([]PlatformUsageRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := s.db.QueryContext(ctx, `SELECT u.id::text,u.request_id,COALESCE(u.user_id::text,''),COALESCE(usr.email,''),COALESCE(u.api_key_id::text,''),COALESCE(k.label,''),COALESCE(u.project_id::text,''),COALESCE(u.device_id::text,''),COALESCE(u.model_id::text,''),COALESCE(m.model_key,''),COALESCE(u.upstream_account_id::text,''),COALESCE(a.label,''),u.product_scope,u.protocol,u.status_code,u.input_tokens,u.output_tokens,u.reasoning_tokens,u.billed_tokens,u.estimated,u.tool_summary,u.error_code,u.duration_ms,u.created_at
FROM usage_records u
LEFT JOIN users usr ON usr.id=u.user_id
LEFT JOIN api_keys_v2 k ON k.id=u.api_key_id
LEFT JOIN platform_models m ON m.id=u.model_id
LEFT JOIN upstream_accounts a ON a.id=u.upstream_account_id
WHERE u.tenant_id=$1 ORDER BY u.created_at DESC LIMIT $2`, DefaultPlatformTenantID(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PlatformUsageRecord, 0)
	for rows.Next() {
		var item PlatformUsageRecord
		if err := rows.Scan(&item.ID, &item.RequestID, &item.UserID, &item.UserEmail, &item.APIKeyID, &item.APIKeyLabel, &item.ProjectID, &item.DeviceID, &item.PlatformModelID, &item.PlatformModelKey, &item.UpstreamAccountID, &item.UpstreamLabel, &item.ProductScope, &item.Protocol, &item.StatusCode, &item.InputTokens, &item.OutputTokens, &item.ReasoningTokens, &item.BilledTokens, &item.Estimated, &item.ToolSummary, &item.ErrorCode, &item.DurationMS, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PlatformStore) ListPlatformWalletSummaries(ctx context.Context, userID string) ([]PlatformWalletSummary, error) {
	userID = strings.TrimSpace(userID)
	query := `SELECT w.user_id::text,u.email,u.display_name,u.status,COALESCE((SELECT p.code FROM subscriptions s JOIN plan_versions v ON v.id=s.plan_version_id JOIN plans p ON p.id=v.plan_id WHERE s.user_id=w.user_id AND s.status IN ('trialing','active') AND s.starts_at<=now() AND s.ends_at>now() ORDER BY s.ends_at DESC LIMIT 1),''),w.product_scope,
COALESCE(MAX(b.granted_tokens) FILTER (WHERE b.window_kind='monthly' AND b.starts_at<=now() AND b.ends_at>now()),0),COALESCE(MAX(b.settled_tokens) FILTER (WHERE b.window_kind='monthly' AND b.starts_at<=now() AND b.ends_at>now()),0),COALESCE(MAX(b.reserved_tokens) FILTER (WHERE b.window_kind='monthly' AND b.starts_at<=now() AND b.ends_at>now()),0),MAX(b.ends_at) FILTER (WHERE b.window_kind='monthly' AND b.starts_at<=now() AND b.ends_at>now()),
COALESCE(MAX(b.granted_tokens) FILTER (WHERE b.window_kind='rolling_5h' AND b.starts_at<=now() AND b.ends_at>now()),0),COALESCE(MAX(b.settled_tokens) FILTER (WHERE b.window_kind='rolling_5h' AND b.starts_at<=now() AND b.ends_at>now()),0),COALESCE(MAX(b.reserved_tokens) FILTER (WHERE b.window_kind='rolling_5h' AND b.starts_at<=now() AND b.ends_at>now()),0),MAX(b.ends_at) FILTER (WHERE b.window_kind='rolling_5h' AND b.starts_at<=now() AND b.ends_at>now())
FROM wallet_accounts w JOIN users u ON u.id=w.user_id LEFT JOIN quota_buckets b ON b.wallet_account_id=w.id
WHERE u.tenant_id=$1`
	args := []any{DefaultPlatformTenantID()}
	if userID != "" {
		query += " AND w.user_id=$2"
		args = append(args, userID)
	}
	query += " GROUP BY w.user_id,u.email,u.display_name,u.status,w.product_scope ORDER BY u.created_at DESC,w.product_scope"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PlatformWalletSummary, 0)
	for rows.Next() {
		var item PlatformWalletSummary
		var monthlyEnds, rollingEnds sql.NullTime
		if err := rows.Scan(&item.UserID, &item.UserEmail, &item.DisplayName, &item.UserStatus, &item.PlanCode, &item.ProductScope, &item.MonthlyGranted, &item.MonthlyUsed, &item.MonthlyReserved, &monthlyEnds, &item.RollingGranted, &item.RollingUsed, &item.RollingReserved, &rollingEnds); err != nil {
			return nil, err
		}
		item.MonthlyRemaining = maxInt64(0, item.MonthlyGranted-item.MonthlyUsed-item.MonthlyReserved)
		item.RollingRemaining = maxInt64(0, item.RollingGranted-item.RollingUsed-item.RollingReserved)
		if monthlyEnds.Valid {
			value := monthlyEnds.Time
			item.MonthlyEndsAt = &value
		}
		if rollingEnds.Valid {
			value := rollingEnds.Time
			item.RollingEndsAt = &value
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PlatformStore) ListPlatformAudits(ctx context.Context, limit int) ([]PlatformAuditRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id::text,actor_kind,action,target_kind,target_id,ip,metadata,created_at FROM audit_events WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, DefaultPlatformTenantID(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PlatformAuditRecord, 0)
	for rows.Next() {
		var item PlatformAuditRecord
		if err := rows.Scan(&item.ID, &item.ActorKind, &item.Action, &item.TargetKind, &item.TargetID, &item.IP, &item.Metadata, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// RecordPlatformAudit writes only structured, bounded metadata. It is a
// separate product-domain audit trail: the transition SQLite log remains
// available for legacy migration diagnostics but is not its substitute.
func (s *PlatformStore) RecordPlatformAudit(ctx context.Context, actorKind, action, targetKind, targetID, ip string, metadata any) error {
	actorKind, action, targetKind, targetID = strings.TrimSpace(actorKind), strings.TrimSpace(action), strings.TrimSpace(targetKind), strings.TrimSpace(targetID)
	if actorKind == "" || action == "" || targetKind == "" || len(actorKind) > 64 || len(action) > 160 || len(targetKind) > 80 || len(targetID) > 256 || len(ip) > 128 {
		return fmt.Errorf("%w: platform audit event", ErrInvalidPlatformModel)
	}
	raw, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	if len(raw) > 32<<10 {
		return fmt.Errorf("%w: platform audit metadata", ErrInvalidPlatformModel)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO audit_events(id,tenant_id,actor_kind,action,target_kind,target_id,ip,metadata) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`, newPlatformID(), DefaultPlatformTenantID(), actorKind, action, targetKind, targetID, ip, string(raw)); err != nil {
		return err
	}
	return nil
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}
