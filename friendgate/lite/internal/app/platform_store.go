package app

import (
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

//go:embed migrations/postgres/*.sql
var platformMigrations embed.FS

var (
	ErrPlatformDatabaseUnavailable = errors.New("PostgreSQL platform database is not configured")
	ErrInvalidPlatformModel        = errors.New("invalid platform model")
	ErrInvalidPlan                 = errors.New("invalid plan")
	ErrNoRouteTarget               = errors.New("no enabled route target for platform model")
	ErrNoRouteCandidate            = errors.New("no healthy upstream account in route pool")
)

// ProductScope is deliberately present on every quota, route and usage record.
// It is the boundary that prevents a web Chat request from consuming Agent
// credits, and vice versa.
type ProductScope string

const (
	ProductScopeChat        ProductScope = "chat"
	ProductScopeAgent       ProductScope = "agent"
	ProductScopeExternalAPI ProductScope = "external_api"
	defaultPlatformTenantID              = "00000000-0000-4000-8000-000000000001"
)

func (s ProductScope) Valid() bool {
	return s == ProductScopeChat || s == ProductScopeAgent || s == ProductScopeExternalAPI
}

type PlatformModel struct {
	ID           string          `json:"id"`
	ModelKey     string          `json:"model_key"`
	DisplayName  string          `json:"display_name"`
	Description  string          `json:"description"`
	Category     string          `json:"category"`
	Capabilities json.RawMessage `json:"capabilities"`
	Billing      json.RawMessage `json:"billing"`
	Status       string          `json:"status"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

type PlatformModelInput struct {
	ModelKey     string          `json:"model_key"`
	DisplayName  string          `json:"display_name"`
	Description  string          `json:"description"`
	Category     string          `json:"category"`
	Capabilities json.RawMessage `json:"capabilities"`
	Billing      json.RawMessage `json:"billing"`
	Status       string          `json:"status"`
}

type ProductModelPublication struct {
	ID              string          `json:"id"`
	ModelID         string          `json:"model_id"`
	ProductScope    ProductScope    `json:"product_scope"`
	Protocol        string          `json:"protocol"`
	Enabled         bool            `json:"enabled"`
	DefaultForScope bool            `json:"default_for_scope"`
	PlanRules       json.RawMessage `json:"plan_rules"`
}

type ProductModelPublicationInput struct {
	ModelID         string          `json:"model_id"`
	ProductScope    ProductScope    `json:"product_scope"`
	Protocol        string          `json:"protocol"`
	Enabled         bool            `json:"enabled"`
	DefaultForScope bool            `json:"default_for_scope"`
	PlanRules       json.RawMessage `json:"plan_rules"`
}

type Plan struct {
	ID          string       `json:"id"`
	Code        string       `json:"code"`
	DisplayName string       `json:"display_name"`
	Description string       `json:"description"`
	SortOrder   int          `json:"sort_order"`
	Status      string       `json:"status"`
	Current     *PlanVersion `json:"current,omitempty"`
}

type PlanVersion struct {
	ID                   string          `json:"id"`
	PlanID               string          `json:"plan_id"`
	Version              int             `json:"version"`
	Currency             string          `json:"currency"`
	MonthlyPriceMinor    int64           `json:"monthly_price_minor"`
	ChatMonthlyTokens    int64           `json:"chat_monthly_tokens"`
	AgentMonthlyTokens   int64           `json:"agent_monthly_tokens"`
	ChatRolling5HTokens  int64           `json:"chat_rolling_5h_tokens"`
	AgentRolling5HTokens int64           `json:"agent_rolling_5h_tokens"`
	Entitlements         json.RawMessage `json:"entitlements"`
	ModelRules           json.RawMessage `json:"model_rules"`
	StartsAt             time.Time       `json:"starts_at"`
	EndsAt               *time.Time      `json:"ends_at,omitempty"`
}

type PlanInput struct {
	Code        string `json:"code"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	SortOrder   int    `json:"sort_order"`
	Status      string `json:"status"`
}

type PlanVersionInput struct {
	Currency             string          `json:"currency"`
	MonthlyPriceMinor    int64           `json:"monthly_price_minor"`
	ChatMonthlyTokens    int64           `json:"chat_monthly_tokens"`
	AgentMonthlyTokens   int64           `json:"agent_monthly_tokens"`
	ChatRolling5HTokens  int64           `json:"chat_rolling_5h_tokens"`
	AgentRolling5HTokens int64           `json:"agent_rolling_5h_tokens"`
	Entitlements         json.RawMessage `json:"entitlements"`
	ModelRules           json.RawMessage `json:"model_rules"`
}

type RoutePool struct {
	ID              string `json:"id"`
	TenantID        string `json:"tenant_id"`
	Name            string `json:"name"`
	Status          string `json:"status"`
	SelectionPolicy string `json:"selection_policy"`
}

type ProviderConnection struct {
	ID            string          `json:"id"`
	TenantID      string          `json:"tenant_id"`
	ProviderKind  string          `json:"provider_kind"`
	ProviderName  string          `json:"provider_name"`
	BaseURL       string          `json:"base_url"`
	Settings      json.RawMessage `json:"settings"`
	Status        string          `json:"status"`
	LastHealthAt  *time.Time      `json:"last_health_at,omitempty"`
	LastError     string          `json:"last_error,omitempty"`
	HasCredential bool            `json:"has_credential"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

type ProviderConnectionInput struct {
	ProviderKind string          `json:"provider_kind"`
	ProviderName string          `json:"provider_name"`
	BaseURL      string          `json:"base_url"`
	Credential   string          `json:"credential,omitempty"`
	Settings     json.RawMessage `json:"settings"`
	Status       string          `json:"status"`
}

type UpstreamAccount struct {
	ID                    string          `json:"id"`
	ConnectionID          string          `json:"connection_id"`
	ProxyPoolID           string          `json:"proxy_pool_id,omitempty"`
	Label                 string          `json:"label"`
	ExternalReferenceHash string          `json:"external_reference_hash,omitempty"`
	ModelCatalog          json.RawMessage `json:"model_catalog"`
	QuotaState            json.RawMessage `json:"quota_state"`
	Status                string          `json:"status"`
	HealthScore           float64         `json:"health_score"`
	CooldownUntil         *time.Time      `json:"cooldown_until,omitempty"`
	ResetAt               *time.Time      `json:"reset_at,omitempty"`
	LastUsedAt            *time.Time      `json:"last_used_at,omitempty"`
	LastError             string          `json:"last_error,omitempty"`
	HasCredential         bool            `json:"has_credential"`
	CreatedAt             time.Time       `json:"created_at"`
	UpdatedAt             time.Time       `json:"updated_at"`
}

type UpstreamAccountInput struct {
	ConnectionID      string          `json:"connection_id"`
	ProxyPoolID       string          `json:"proxy_pool_id,omitempty"`
	Label             string          `json:"label"`
	ExternalReference string          `json:"external_reference,omitempty"`
	Credential        string          `json:"credential,omitempty"`
	ModelCatalog      json.RawMessage `json:"model_catalog"`
	QuotaState        json.RawMessage `json:"quota_state"`
	Status            string          `json:"status"`
}

type RoutePoolMemberInput struct {
	RoutePoolID       string `json:"route_pool_id"`
	UpstreamAccountID string `json:"upstream_account_id"`
	Priority          int    `json:"priority"`
	Weight            int    `json:"weight"`
	Enabled           bool   `json:"enabled"`
}

type ModelRouteTarget struct {
	ID              string       `json:"id"`
	ModelID         string       `json:"model_id"`
	ProductScope    ProductScope `json:"product_scope"`
	Protocol        string       `json:"protocol"`
	RoutePoolID     string       `json:"route_pool_id"`
	UpstreamModelID string       `json:"upstream_model_id"`
	Priority        int          `json:"priority"`
	Enabled         bool         `json:"enabled"`
}

type ModelRouteTargetInput struct {
	ModelID         string       `json:"model_id"`
	ProductScope    ProductScope `json:"product_scope"`
	Protocol        string       `json:"protocol"`
	RoutePoolID     string       `json:"route_pool_id"`
	UpstreamModelID string       `json:"upstream_model_id"`
	Priority        int          `json:"priority"`
	Enabled         bool         `json:"enabled"`
}

type RouteSelectionRequest struct {
	ModelID      string       `json:"model_id"`
	ProductScope ProductScope `json:"product_scope"`
	Protocol     string       `json:"protocol"`
	// RoutePoolID is an optional API-key routing boundary. When present, a key
	// cannot accidentally fall back to a target belonging to another pool.
	RoutePoolID  string        `json:"route_pool_id,omitempty"`
	AffinityHash string        `json:"-"`
	StickyTTL    time.Duration `json:"-"`
}

// RouteSelection contains only data needed by the gateway. Its credential is
// deliberately excluded from JSON and is never returned by administrator APIs.
type RouteSelection struct {
	TargetID           string `json:"target_id"`
	ModelID            string `json:"model_id"`
	RoutePoolID        string `json:"route_pool_id"`
	UpstreamAccountID  string `json:"upstream_account_id"`
	ConnectionID       string `json:"connection_id"`
	ProviderKind       string `json:"provider_kind"`
	ProviderName       string `json:"provider_name"`
	BaseURL            string `json:"base_url"`
	UpstreamModelID    string `json:"upstream_model_id"`
	Credential         string `json:"-"`
	accountCredential  string
	providerCredential string
}

type PlatformOverview struct {
	Configured bool      `json:"configured"`
	Healthy    bool      `json:"healthy"`
	Plans      int64     `json:"plans"`
	Models     int64     `json:"models"`
	RoutePools int64     `json:"route_pools"`
	Targets    int64     `json:"route_targets"`
	CheckedAt  time.Time `json:"checked_at"`
}

type TokenReservation struct {
	ReferenceID string    `json:"reference_id"`
	WalletID    string    `json:"wallet_id"`
	Tokens      int64     `json:"tokens"`
	ReservedAt  time.Time `json:"reserved_at"`
}

type QuotaBucketInput struct {
	WindowKind string
	StartsAt   time.Time
	EndsAt     time.Time
	Tokens     int64
	Reference  string
	Reason     string
}

// PlatformStore is the PostgreSQL source of truth for new Infinite AI product
// data. The existing local gateway store remains separate only while a
// migration is being audited; both are owned by the same Go process.
type PlatformStore struct {
	db    *sql.DB
	vault *Vault
}

func OpenPlatformStore(ctx context.Context, cfg Config, vaults ...*Vault) (*PlatformStore, error) {
	if strings.TrimSpace(cfg.PlatformDatabaseURL) == "" {
		return nil, ErrPlatformDatabaseUnavailable
	}
	db, err := sql.Open("pgx", cfg.PlatformDatabaseURL)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(cfg.PlatformDBMaxOpen)
	db.SetMaxIdleConns(cfg.PlatformDBMaxIdle)
	db.SetConnMaxLifetime(cfg.PlatformDBMaxLife)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	var vault *Vault
	if len(vaults) > 0 {
		vault = vaults[0]
	}
	if vault == nil && len(cfg.MasterKey) == 32 {
		vault, err = NewVault(cfg.MasterKey)
		if err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	store := &PlatformStore{db: db, vault: vault}
	if err := store.Migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.EnsureDefaultTenant(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.SeedDefaultPlans(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *PlatformStore) EnsureDefaultTenant(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO tenants(id, slug, display_name, status) VALUES ($1,'default','Infinite AI','active') ON CONFLICT (slug) DO NOTHING`, defaultPlatformTenantID); err != nil {
		return err
	}
	for key, value := range map[string]string{
		"registration_mode": "\"invite_only\"",
		"payment_enabled":   "false",
		"external_api_mode": "\"authenticated_public\"",
	} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO platform_settings(tenant_id,key,value) VALUES($1,$2,$3::jsonb) ON CONFLICT(tenant_id,key) DO NOTHING`, defaultPlatformTenantID, key, value); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func DefaultPlatformTenantID() string { return defaultPlatformTenantID }

func (s *PlatformStore) Close() error { return s.db.Close() }

func (s *PlatformStore) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *PlatformStore) Overview(ctx context.Context) (PlatformOverview, error) {
	overview := PlatformOverview{Configured: true, CheckedAt: time.Now().UTC()}
	if err := s.db.PingContext(ctx); err != nil {
		return overview, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM plans), (SELECT COUNT(*) FROM platform_models), (SELECT COUNT(*) FROM route_pools), (SELECT COUNT(*) FROM model_route_targets)`).Scan(&overview.Plans, &overview.Models, &overview.RoutePools, &overview.Targets); err != nil {
		return overview, err
	}
	overview.Healthy = true
	return overview, nil
}

// Migrate serializes all schema changes. Migration files are append-only and
// only marked applied after their SQL succeeds in the same transaction.
func (s *PlatformStore) Migrate(ctx context.Context) error {
	entries, err := fs.ReadDir(platformMigrations, "migrations/postgres")
	if err != nil {
		return fmt.Errorf("read PostgreSQL migrations: %w", err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return errors.New("no PostgreSQL migrations embedded")
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("prepare migration table: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(912260203)`); err != nil {
		return fmt.Errorf("lock migrations: %w", err)
	}
	for _, name := range names {
		var applied bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, name).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %s: %w", name, err)
		}
		if applied {
			continue
		}
		body, readErr := platformMigrations.ReadFile("migrations/postgres/" + name)
		if readErr != nil {
			return fmt.Errorf("read migration %s: %w", name, readErr)
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version) VALUES ($1)`, name); err != nil {
			return fmt.Errorf("record migration %s: %w", name, err)
		}
	}
	return tx.Commit()
}

func DefaultPlanSeeds() []struct {
	PlanInput
	PlanVersionInput
} {
	defaultRules := json.RawMessage(`{"models":"published_by_plan","projects":1,"chat_tools":true,"agent_tools":false}`)
	return []struct {
		PlanInput
		PlanVersionInput
	}{
		{PlanInput: PlanInput{Code: "free", DisplayName: "Free", Description: "体验套餐", SortOrder: 10, Status: "active"}, PlanVersionInput: PlanVersionInput{Currency: "USD", MonthlyPriceMinor: 0, ChatMonthlyTokens: 100_000, AgentMonthlyTokens: 50_000, ChatRolling5HTokens: 10_000, AgentRolling5HTokens: 5_000, Entitlements: defaultRules, ModelRules: json.RawMessage(`{"tier":"free"}`)}},
		{PlanInput: PlanInput{Code: "go", DisplayName: "Go", Description: "轻量个人套餐", SortOrder: 20, Status: "active"}, PlanVersionInput: PlanVersionInput{Currency: "USD", MonthlyPriceMinor: 800, ChatMonthlyTokens: 2_000_000, AgentMonthlyTokens: 1_000_000, ChatRolling5HTokens: 100_000, AgentRolling5HTokens: 50_000, Entitlements: json.RawMessage(`{"models":"published_by_plan","projects":5,"chat_tools":true,"agent_tools":true}`), ModelRules: json.RawMessage(`{"tier":"go"}`)}},
		{PlanInput: PlanInput{Code: "plus", DisplayName: "Plus", Description: "个人主力套餐", SortOrder: 30, Status: "active"}, PlanVersionInput: PlanVersionInput{Currency: "USD", MonthlyPriceMinor: 2000, ChatMonthlyTokens: 5_000_000, AgentMonthlyTokens: 5_000_000, ChatRolling5HTokens: 250_000, AgentRolling5HTokens: 250_000, Entitlements: json.RawMessage(`{"models":"published_by_plan","projects":20,"chat_tools":true,"agent_tools":true}`), ModelRules: json.RawMessage(`{"tier":"plus"}`)}},
		{PlanInput: PlanInput{Code: "pro", DisplayName: "Pro", Description: "高强度专业套餐", SortOrder: 40, Status: "active"}, PlanVersionInput: PlanVersionInput{Currency: "USD", MonthlyPriceMinor: 10000, ChatMonthlyTokens: 25_000_000, AgentMonthlyTokens: 25_000_000, ChatRolling5HTokens: 1_250_000, AgentRolling5HTokens: 1_250_000, Entitlements: json.RawMessage(`{"models":"published_by_plan","projects":100,"chat_tools":true,"agent_tools":true}`), ModelRules: json.RawMessage(`{"tier":"pro"}`)}},
	}
}

func (s *PlatformStore) SeedDefaultPlans(ctx context.Context) error {
	for _, seed := range DefaultPlanSeeds() {
		if _, err := s.CreatePlanIfMissing(ctx, seed.PlanInput, seed.PlanVersionInput); err != nil {
			return fmt.Errorf("seed plan %s: %w", seed.Code, err)
		}
	}
	return nil
}

func (s *PlatformStore) CreatePlanIfMissing(ctx context.Context, input PlanInput, version PlanVersionInput) (*Plan, error) {
	if err := validatePlanInput(&input); err != nil {
		return nil, err
	}
	if err := validatePlanVersionInput(&version); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var planID string
	err = tx.QueryRowContext(ctx, `SELECT id::text FROM plans WHERE code=$1 FOR UPDATE`, input.Code).Scan(&planID)
	if errors.Is(err, sql.ErrNoRows) {
		planID = newPlatformID()
		if _, err := tx.ExecContext(ctx, `INSERT INTO plans(id, code, display_name, description, sort_order, status) VALUES ($1,$2,$3,$4,$5,$6)`, planID, input.Code, input.DisplayName, input.Description, input.SortOrder, input.Status); err != nil {
			return nil, err
		}
		if _, err := insertPlanVersion(ctx, tx, planID, 1, version); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.PlanByCode(ctx, input.Code)
}

func (s *PlatformStore) PlanByCode(ctx context.Context, code string) (*Plan, error) {
	rows, err := s.listPlansQuery(ctx, `WHERE p.code=$1`, strings.TrimSpace(strings.ToLower(code)))
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	return &rows[0], nil
}

func (s *PlatformStore) ListPlans(ctx context.Context) ([]Plan, error) {
	return s.listPlansQuery(ctx, ``, nil)
}

func (s *PlatformStore) listPlansQuery(ctx context.Context, where string, arg any) ([]Plan, error) {
	query := `SELECT p.id::text, p.code, p.display_name, p.description, p.sort_order, p.status,
       v.id::text, v.version, v.currency, v.monthly_price_minor, v.chat_monthly_tokens,
       v.agent_monthly_tokens, v.chat_rolling_5h_tokens, v.agent_rolling_5h_tokens,
       v.entitlements, v.model_rules, v.starts_at, v.ends_at
FROM plans p
LEFT JOIN plan_versions v ON v.plan_id=p.id AND v.ends_at IS NULL ` + where + ` ORDER BY p.sort_order, p.code`
	var rows *sql.Rows
	var err error
	if arg == nil {
		rows, err = s.db.QueryContext(ctx, query)
	} else {
		rows, err = s.db.QueryContext(ctx, query, arg)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	plans := make([]Plan, 0)
	for rows.Next() {
		var plan Plan
		var currentID sql.NullString
		var current PlanVersion
		var endsAt sql.NullTime
		if err := rows.Scan(&plan.ID, &plan.Code, &plan.DisplayName, &plan.Description, &plan.SortOrder, &plan.Status,
			&currentID, &current.Version, &current.Currency, &current.MonthlyPriceMinor, &current.ChatMonthlyTokens,
			&current.AgentMonthlyTokens, &current.ChatRolling5HTokens, &current.AgentRolling5HTokens,
			&current.Entitlements, &current.ModelRules, &current.StartsAt, &endsAt); err != nil {
			return nil, err
		}
		if currentID.Valid {
			current.ID, current.PlanID = currentID.String, plan.ID
			if endsAt.Valid {
				value := endsAt.Time
				current.EndsAt = &value
			}
			plan.Current = &current
		}
		plans = append(plans, plan)
	}
	return plans, rows.Err()
}

// ReplaceCurrentPlanVersion makes package edits forward-only. Existing
// subscriptions retain their explicit snapshot; only new purchases see the
// newly inserted version.
func (s *PlatformStore) ReplaceCurrentPlanVersion(ctx context.Context, planCode string, input PlanVersionInput) (*PlanVersion, error) {
	if err := validatePlanVersionInput(&input); err != nil {
		return nil, err
	}
	planCode = strings.TrimSpace(strings.ToLower(planCode))
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var planID string
	if err := tx.QueryRowContext(ctx, `SELECT id::text FROM plans WHERE code=$1 FOR UPDATE`, planCode).Scan(&planID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var nextVersion int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0)+1 FROM plan_versions WHERE plan_id=$1`, planID).Scan(&nextVersion); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `UPDATE plan_versions SET ends_at=$2 WHERE plan_id=$1 AND ends_at IS NULL`, planID, now); err != nil {
		return nil, err
	}
	version, err := insertPlanVersion(ctx, tx, planID, nextVersion, input)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return version, nil
}

func insertPlanVersion(ctx context.Context, tx *sql.Tx, planID string, versionNumber int, input PlanVersionInput) (*PlanVersion, error) {
	version := &PlanVersion{ID: newPlatformID(), PlanID: planID, Version: versionNumber, Currency: input.Currency, MonthlyPriceMinor: input.MonthlyPriceMinor, ChatMonthlyTokens: input.ChatMonthlyTokens, AgentMonthlyTokens: input.AgentMonthlyTokens, ChatRolling5HTokens: input.ChatRolling5HTokens, AgentRolling5HTokens: input.AgentRolling5HTokens, Entitlements: input.Entitlements, ModelRules: input.ModelRules, StartsAt: time.Now().UTC()}
	_, err := tx.ExecContext(ctx, `INSERT INTO plan_versions(id, plan_id, version, currency, monthly_price_minor, chat_monthly_tokens, agent_monthly_tokens, chat_rolling_5h_tokens, agent_rolling_5h_tokens, entitlements, model_rules, starts_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12)`, version.ID, planID, versionNumber, version.Currency, version.MonthlyPriceMinor, version.ChatMonthlyTokens, version.AgentMonthlyTokens, version.ChatRolling5HTokens, version.AgentRolling5HTokens, string(version.Entitlements), string(version.ModelRules), version.StartsAt)
	if err != nil {
		return nil, err
	}
	return version, nil
}

func (s *PlatformStore) CreatePlatformModel(ctx context.Context, input PlatformModelInput) (*PlatformModel, error) {
	if err := validatePlatformModelInput(&input); err != nil {
		return nil, err
	}
	model := &PlatformModel{ID: newPlatformID(), ModelKey: input.ModelKey, DisplayName: input.DisplayName, Description: input.Description, Category: input.Category, Capabilities: input.Capabilities, Billing: input.Billing, Status: input.Status}
	err := s.db.QueryRowContext(ctx, `INSERT INTO platform_models(id, model_key, display_name, description, category, capabilities, billing, status) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8) RETURNING created_at, updated_at`, model.ID, model.ModelKey, model.DisplayName, model.Description, model.Category, string(model.Capabilities), string(model.Billing), model.Status).Scan(&model.CreatedAt, &model.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return model, nil
}

func (s *PlatformStore) ListPlatformModels(ctx context.Context) ([]PlatformModel, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id::text, model_key, display_name, description, category, capabilities, billing, status, created_at, updated_at FROM platform_models ORDER BY model_key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]PlatformModel, 0)
	for rows.Next() {
		var model PlatformModel
		if err := rows.Scan(&model.ID, &model.ModelKey, &model.DisplayName, &model.Description, &model.Category, &model.Capabilities, &model.Billing, &model.Status, &model.CreatedAt, &model.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, model)
	}
	return result, rows.Err()
}

// UpsertProductModelPublication is the explicit boundary between a private
// platform-model catalogue entry and a model an end user can discover. Route
// targets alone never publish a model.
func (s *PlatformStore) UpsertProductModelPublication(ctx context.Context, input ProductModelPublicationInput) (*ProductModelPublication, error) {
	input.ModelID = strings.TrimSpace(input.ModelID)
	input.Protocol = strings.TrimSpace(strings.ToLower(input.Protocol))
	if input.ModelID == "" || !input.ProductScope.Valid() || !validProtocol(input.Protocol) {
		return nil, ErrInvalidPlatformModel
	}
	if len(input.PlanRules) == 0 {
		input.PlanRules = json.RawMessage(`{}`)
	}
	if !isJSONObject(input.PlanRules) {
		return nil, ErrInvalidPlatformModel
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var active bool
	if err := tx.QueryRowContext(ctx, `SELECT status='active' FROM platform_models WHERE id=$1 FOR UPDATE`, input.ModelID).Scan(&active); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	if !active {
		return nil, ErrInvalidPlatformModel
	}
	if input.DefaultForScope && input.Enabled {
		if _, err := tx.ExecContext(ctx, `UPDATE product_model_publications SET default_for_scope=false,updated_at=now() WHERE product_scope=$1 AND default_for_scope AND enabled`, input.ProductScope); err != nil {
			return nil, err
		}
	}
	item := &ProductModelPublication{ID: newPlatformID(), ModelID: input.ModelID, ProductScope: input.ProductScope, Protocol: input.Protocol, Enabled: input.Enabled, DefaultForScope: input.DefaultForScope, PlanRules: input.PlanRules}
	err = tx.QueryRowContext(ctx, `INSERT INTO product_model_publications(id,model_id,product_scope,protocol,enabled,default_for_scope,plan_rules)
VALUES($1,$2,$3,$4,$5,$6,$7::jsonb)
ON CONFLICT(model_id,product_scope,protocol) DO UPDATE SET enabled=excluded.enabled,default_for_scope=excluded.default_for_scope,plan_rules=excluded.plan_rules,updated_at=now()
RETURNING id::text`, item.ID, item.ModelID, item.ProductScope, item.Protocol, item.Enabled, item.DefaultForScope, string(item.PlanRules)).Scan(&item.ID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return item, nil
}

func (s *PlatformStore) ListProductModelPublications(ctx context.Context, modelID string) ([]ProductModelPublication, error) {
	query := `SELECT id::text,model_id::text,product_scope,protocol,enabled,default_for_scope,plan_rules FROM product_model_publications`
	args := []any{}
	if modelID = strings.TrimSpace(modelID); modelID != "" {
		query += ` WHERE model_id=$1`
		args = append(args, modelID)
	}
	query += ` ORDER BY product_scope,protocol,model_id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ProductModelPublication, 0)
	for rows.Next() {
		var item ProductModelPublication
		if err := rows.Scan(&item.ID, &item.ModelID, &item.ProductScope, &item.Protocol, &item.Enabled, &item.DefaultForScope, &item.PlanRules); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PlatformStore) UpdatePlatformModel(ctx context.Context, id string, input PlatformModelInput) (*PlatformModel, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, ErrInvalidPlatformModel
	}
	if err := validatePlatformModelInput(&input); err != nil {
		return nil, err
	}
	model := &PlatformModel{ID: id, ModelKey: input.ModelKey, DisplayName: input.DisplayName, Description: input.Description, Category: input.Category, Capabilities: input.Capabilities, Billing: input.Billing, Status: input.Status}
	err := s.db.QueryRowContext(ctx, `UPDATE platform_models SET model_key=$2, display_name=$3, description=$4, category=$5, capabilities=$6::jsonb, billing=$7::jsonb, status=$8, updated_at=now() WHERE id=$1 RETURNING created_at, updated_at`, model.ID, model.ModelKey, model.DisplayName, model.Description, model.Category, string(model.Capabilities), string(model.Billing), model.Status).Scan(&model.CreatedAt, &model.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return model, nil
}

func (s *PlatformStore) CreateRoutePool(ctx context.Context, tenantID, name, policy string) (*RoutePool, error) {
	tenantID = strings.TrimSpace(tenantID)
	name = strings.TrimSpace(name)
	policy = strings.TrimSpace(strings.ToLower(policy))
	if tenantID == "" || name == "" || (policy != "quota_aware" && policy != "fixed") {
		return nil, fmt.Errorf("%w: route pool", ErrInvalidPlatformModel)
	}
	pool := &RoutePool{ID: newPlatformID(), TenantID: tenantID, Name: name, Status: "active", SelectionPolicy: policy}
	err := s.db.QueryRowContext(ctx, `INSERT INTO route_pools(id, tenant_id, name, status, selection_policy) VALUES ($1,$2,$3,$4,$5) RETURNING id::text`, pool.ID, pool.TenantID, pool.Name, pool.Status, pool.SelectionPolicy).Scan(&pool.ID)
	if err != nil {
		return nil, err
	}
	return pool, nil
}

func (s *PlatformStore) ListRoutePools(ctx context.Context) ([]RoutePool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id::text, tenant_id::text, name, status, selection_policy FROM route_pools ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]RoutePool, 0)
	for rows.Next() {
		var pool RoutePool
		if err := rows.Scan(&pool.ID, &pool.TenantID, &pool.Name, &pool.Status, &pool.SelectionPolicy); err != nil {
			return nil, err
		}
		result = append(result, pool)
	}
	return result, rows.Err()
}

// CreateProviderConnection accepts only administrator-supplied upstream
// configuration. Secrets are encrypted before reaching PostgreSQL and are
// never returned from this API. OAuth providers remain disabled until their
// official client configuration and callback validation are completed.
func (s *PlatformStore) CreateProviderConnection(ctx context.Context, input ProviderConnectionInput) (*ProviderConnection, error) {
	if err := validateProviderConnectionInput(&input); err != nil {
		return nil, err
	}
	credential, err := s.encryptPlatformSecret(input.Credential, "platform-provider-credential")
	if err != nil {
		return nil, err
	}
	connection := &ProviderConnection{ID: newPlatformID(), TenantID: DefaultPlatformTenantID(), ProviderKind: input.ProviderKind, ProviderName: input.ProviderName, BaseURL: input.BaseURL, Settings: input.Settings, Status: input.Status, HasCredential: credential != ""}
	err = s.db.QueryRowContext(ctx, `INSERT INTO provider_connections(id, tenant_id, provider_kind, provider_name, base_url, credential_enc, settings, status) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8) RETURNING created_at,updated_at`, connection.ID, connection.TenantID, connection.ProviderKind, connection.ProviderName, connection.BaseURL, credential, string(connection.Settings), connection.Status).Scan(&connection.CreatedAt, &connection.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return connection, nil
}

func (s *PlatformStore) ListProviderConnections(ctx context.Context) ([]ProviderConnection, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id::text, tenant_id::text, provider_kind, provider_name, base_url, settings, status, last_health_at, last_error, credential_enc <> '', created_at, updated_at FROM provider_connections ORDER BY provider_name, created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ProviderConnection, 0)
	for rows.Next() {
		var item ProviderConnection
		var health sql.NullTime
		if err := rows.Scan(&item.ID, &item.TenantID, &item.ProviderKind, &item.ProviderName, &item.BaseURL, &item.Settings, &item.Status, &health, &item.LastError, &item.HasCredential, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		if health.Valid {
			value := health.Time
			item.LastHealthAt = &value
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PlatformStore) CreateUpstreamAccount(ctx context.Context, input UpstreamAccountInput) (*UpstreamAccount, error) {
	if err := validateUpstreamAccountInput(&input); err != nil {
		return nil, err
	}
	credential, err := s.encryptPlatformSecret(input.Credential, "platform-upstream-account-credential")
	if err != nil {
		return nil, err
	}
	externalRefHash := ""
	if input.ExternalReference != "" {
		externalRefHash = tokenHash(input.ExternalReference)
	}
	account := &UpstreamAccount{ID: newPlatformID(), ConnectionID: input.ConnectionID, ProxyPoolID: input.ProxyPoolID, Label: input.Label, ExternalReferenceHash: externalRefHash, ModelCatalog: input.ModelCatalog, QuotaState: input.QuotaState, Status: input.Status, HealthScore: 100, HasCredential: credential != ""}
	var proxyPoolID any
	if account.ProxyPoolID != "" {
		proxyPoolID = account.ProxyPoolID
	}
	err = s.db.QueryRowContext(ctx, `INSERT INTO upstream_accounts(id, connection_id, proxy_pool_id, external_account_ref_hash, label, credential_enc, model_catalog, quota_state, status, health_score) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9,$10) RETURNING created_at,updated_at`, account.ID, account.ConnectionID, proxyPoolID, account.ExternalReferenceHash, account.Label, credential, string(account.ModelCatalog), string(account.QuotaState), account.Status, account.HealthScore).Scan(&account.CreatedAt, &account.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return account, nil
}

func (s *PlatformStore) ListUpstreamAccounts(ctx context.Context, connectionID string) ([]UpstreamAccount, error) {
	query := `SELECT id::text, connection_id::text, COALESCE(proxy_pool_id::text,''), label, external_account_ref_hash, model_catalog, quota_state, status, health_score, cooldown_until, reset_at, last_used_at, last_error, credential_enc <> '', created_at, updated_at FROM upstream_accounts`
	args := []any{}
	if connectionID = strings.TrimSpace(connectionID); connectionID != "" {
		query += ` WHERE connection_id=$1`
		args = append(args, connectionID)
	}
	query += ` ORDER BY label, created_at`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]UpstreamAccount, 0)
	for rows.Next() {
		var item UpstreamAccount
		var cooldown, reset, lastUsed sql.NullTime
		if err := rows.Scan(&item.ID, &item.ConnectionID, &item.ProxyPoolID, &item.Label, &item.ExternalReferenceHash, &item.ModelCatalog, &item.QuotaState, &item.Status, &item.HealthScore, &cooldown, &reset, &lastUsed, &item.LastError, &item.HasCredential, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		if cooldown.Valid {
			value := cooldown.Time
			item.CooldownUntil = &value
		}
		if reset.Valid {
			value := reset.Time
			item.ResetAt = &value
		}
		if lastUsed.Valid {
			value := lastUsed.Time
			item.LastUsedAt = &value
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PlatformStore) AddRoutePoolMember(ctx context.Context, input RoutePoolMemberInput) error {
	input.RoutePoolID = strings.TrimSpace(input.RoutePoolID)
	input.UpstreamAccountID = strings.TrimSpace(input.UpstreamAccountID)
	if input.RoutePoolID == "" || input.UpstreamAccountID == "" || input.Priority < 0 || input.Weight <= 0 {
		return fmt.Errorf("%w: route pool member", ErrInvalidPlatformModel)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO route_pool_members(id, route_pool_id, upstream_account_id, priority, weight, enabled) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT(route_pool_id, upstream_account_id) DO UPDATE SET priority=excluded.priority,weight=excluded.weight,enabled=excluded.enabled,updated_at=now()`, newPlatformID(), input.RoutePoolID, input.UpstreamAccountID, input.Priority, input.Weight, input.Enabled)
	return err
}

// SelectRouteTarget first honors a tenant-scoped sticky association, then
// selects the healthiest eligible target. The affinity value must already be a
// non-reversible HMAC created by the gateway from tenant, user/key, product,
// project, conversation and protocol identifiers.
func (s *PlatformStore) SelectRouteTarget(ctx context.Context, request RouteSelectionRequest) (*RouteSelection, error) {
	request.ModelID = strings.TrimSpace(request.ModelID)
	request.Protocol = strings.TrimSpace(strings.ToLower(request.Protocol))
	request.RoutePoolID = strings.TrimSpace(request.RoutePoolID)
	request.AffinityHash = strings.TrimSpace(request.AffinityHash)
	if request.ModelID == "" || !request.ProductScope.Valid() || !validProtocol(request.Protocol) || len(request.AffinityHash) < 24 || request.StickyTTL <= 0 || request.StickyTTL > 7*24*time.Hour {
		return nil, fmt.Errorf("%w: route selection", ErrInvalidPlatformModel)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	selection, err := findStickyRouteTarget(ctx, tx, request)
	if errors.Is(err, sql.ErrNoRows) {
		selection, err = findBestRouteTarget(ctx, tx, request)
	}
	if errors.Is(err, sql.ErrNoRows) {
		var targets int
		if countErr := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM model_route_targets t JOIN route_pools p ON p.id=t.route_pool_id AND p.status='active' WHERE t.model_id=$1 AND t.product_scope=$2 AND t.protocol=$3 AND t.enabled AND ($4='' OR t.route_pool_id::text=$4)`, request.ModelID, request.ProductScope, request.Protocol, request.RoutePoolID).Scan(&targets); countErr != nil {
			return nil, countErr
		}
		if targets == 0 {
			return nil, ErrNoRouteTarget
		}
		return nil, ErrNoRouteCandidate
	}
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO route_affinities(id, tenant_id, scope_hash, route_pool_id, upstream_account_id, expires_at, last_used_at) VALUES ($1,$2,$3,$4,$5,now()+$6::interval,now()) ON CONFLICT(tenant_id,scope_hash) DO UPDATE SET route_pool_id=excluded.route_pool_id,upstream_account_id=excluded.upstream_account_id,expires_at=excluded.expires_at,last_used_at=now()`, newPlatformID(), DefaultPlatformTenantID(), request.AffinityHash, selection.RoutePoolID, selection.UpstreamAccountID, intervalLiteral(request.StickyTTL)); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE upstream_accounts SET last_used_at=now(),updated_at=now() WHERE id=$1 AND status='active'`, selection.UpstreamAccountID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	credential, err := s.decryptPlatformSecret(selection.accountCredential, "platform-upstream-account-credential")
	if selection.accountCredential == "" {
		credential, err = s.decryptPlatformSecret(selection.providerCredential, "platform-provider-credential")
	}
	if err != nil {
		return nil, err
	}
	selection.Credential = credential
	return selection, nil
}

func findStickyRouteTarget(ctx context.Context, tx *sql.Tx, request RouteSelectionRequest) (*RouteSelection, error) {
	query := `SELECT t.id::text,t.model_id::text,t.route_pool_id::text,a.id::text,a.connection_id::text,c.provider_kind,c.provider_name,c.base_url,t.upstream_model_id,a.credential_enc,c.credential_enc
FROM route_affinities f
JOIN model_route_targets t ON t.route_pool_id=f.route_pool_id AND t.model_id=$3 AND t.product_scope=$4 AND t.protocol=$5 AND t.enabled
JOIN route_pools p ON p.id=t.route_pool_id AND p.status='active'
JOIN route_pool_members m ON m.route_pool_id=t.route_pool_id AND m.upstream_account_id=f.upstream_account_id AND m.enabled
JOIN upstream_accounts a ON a.id=f.upstream_account_id AND a.status='active' AND (a.cooldown_until IS NULL OR a.cooldown_until<=now())
JOIN provider_connections c ON c.id=a.connection_id AND c.status='active'
WHERE f.tenant_id=$1 AND f.scope_hash=$2 AND f.expires_at>now() AND ($6='' OR t.route_pool_id::text=$6)
ORDER BY t.priority,m.priority,a.health_score DESC LIMIT 1`
	return scanRouteSelection(tx.QueryRowContext(ctx, query, DefaultPlatformTenantID(), request.AffinityHash, request.ModelID, request.ProductScope, request.Protocol, request.RoutePoolID))
}

func findBestRouteTarget(ctx context.Context, tx *sql.Tx, request RouteSelectionRequest) (*RouteSelection, error) {
	query := `SELECT t.id::text,t.model_id::text,t.route_pool_id::text,a.id::text,a.connection_id::text,c.provider_kind,c.provider_name,c.base_url,t.upstream_model_id,a.credential_enc,c.credential_enc
FROM model_route_targets t
JOIN route_pools p ON p.id=t.route_pool_id AND p.status='active'
JOIN route_pool_members m ON m.route_pool_id=t.route_pool_id AND m.enabled
JOIN upstream_accounts a ON a.id=m.upstream_account_id AND a.status='active' AND (a.cooldown_until IS NULL OR a.cooldown_until<=now())
JOIN provider_connections c ON c.id=a.connection_id AND c.status='active'
WHERE t.model_id=$1 AND t.product_scope=$2 AND t.protocol=$3 AND t.enabled AND ($4='' OR t.route_pool_id::text=$4)
ORDER BY CASE WHEN a.reset_at IS NULL THEN 1 ELSE 0 END,a.reset_at ASC,t.priority,m.priority,a.health_score DESC,m.weight DESC,a.last_used_at ASC NULLS FIRST LIMIT 1`
	return scanRouteSelection(tx.QueryRowContext(ctx, query, request.ModelID, request.ProductScope, request.Protocol, request.RoutePoolID))
}

func scanRouteSelection(row *sql.Row) (*RouteSelection, error) {
	selection := &RouteSelection{}
	err := row.Scan(&selection.TargetID, &selection.ModelID, &selection.RoutePoolID, &selection.UpstreamAccountID, &selection.ConnectionID, &selection.ProviderKind, &selection.ProviderName, &selection.BaseURL, &selection.UpstreamModelID, &selection.accountCredential, &selection.providerCredential)
	if err != nil {
		return nil, err
	}
	return selection, nil
}

func intervalLiteral(value time.Duration) string {
	// The input is bounded by SelectRouteTarget; sending a simple integer value
	// avoids embedding SQL duration text while retaining microsecond precision.
	return fmt.Sprintf("%d microseconds", value.Microseconds())
}

// SetUpstreamAccountStatus is the immediate lifecycle boundary used by admin
// disable/delete actions. It removes sticky links in the same transaction, so
// the next request cannot continue using an account that has been removed.
func (s *PlatformStore) SetUpstreamAccountStatus(ctx context.Context, accountID, status string) error {
	accountID = strings.TrimSpace(accountID)
	status = strings.TrimSpace(strings.ToLower(status))
	if accountID == "" || !validUpstreamStatus(status) {
		return fmt.Errorf("%w: upstream account status", ErrInvalidPlatformModel)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `UPDATE upstream_accounts SET status=$2,updated_at=now() WHERE id=$1`, accountID, status)
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrNotFound
	}
	if status != "active" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM route_affinities WHERE upstream_account_id=$1`, accountID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteUpstreamAccount is a hard lifecycle boundary.  It first disables the
// account and removes every sticky association in the same transaction, then
// deletes the encrypted credential row.  Historical usage remains because its
// foreign key is intentionally SET NULL rather than CASCADE.
func (s *PlatformStore) DeleteUpstreamAccount(ctx context.Context, accountID string) error {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return ErrNotFound
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE upstream_accounts SET status='disabled',updated_at=now() WHERE id=$1`, accountID)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM route_affinities WHERE upstream_account_id=$1`, accountID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM upstream_accounts WHERE id=$1`, accountID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PlatformStore) SetProviderConnectionStatus(ctx context.Context, connectionID, status string) error {
	connectionID = strings.TrimSpace(connectionID)
	status = strings.TrimSpace(strings.ToLower(status))
	if connectionID == "" || !validProviderStatus(status) {
		return fmt.Errorf("%w: provider connection status", ErrInvalidPlatformModel)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE provider_connections SET status=$2,updated_at=now() WHERE id=$1`, connectionID, status)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrNotFound
	}
	if status != "active" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM route_affinities WHERE upstream_account_id IN (SELECT id FROM upstream_accounts WHERE connection_id=$1)`, connectionID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *PlatformStore) DeleteProviderConnection(ctx context.Context, connectionID string) error {
	connectionID = strings.TrimSpace(connectionID)
	if connectionID == "" {
		return ErrNotFound
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM route_affinities WHERE upstream_account_id IN (SELECT id FROM upstream_accounts WHERE connection_id=$1)`, connectionID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM provider_connections WHERE id=$1`, connectionID)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrNotFound
	}
	return tx.Commit()
}

func (s *PlatformStore) encryptPlatformSecret(plain, purpose string) (string, error) {
	plain = strings.TrimSpace(plain)
	if plain == "" {
		return "", nil
	}
	if len(plain) > 1<<20 {
		return "", errors.New("platform credential is too large")
	}
	if s.vault == nil {
		return "", errors.New("platform secret storage requires LITE_MASTER_KEY")
	}
	return s.vault.Encrypt(plain, purpose)
}

func (s *PlatformStore) decryptPlatformSecret(encrypted, purpose string) (string, error) {
	if strings.TrimSpace(encrypted) == "" {
		return "", nil
	}
	if s.vault == nil {
		return "", errors.New("platform secret storage requires LITE_MASTER_KEY")
	}
	return s.vault.Decrypt(encrypted, purpose)
}

func (s *PlatformStore) CreateRouteTarget(ctx context.Context, input ModelRouteTargetInput) (*ModelRouteTarget, error) {
	input.Protocol = strings.TrimSpace(strings.ToLower(input.Protocol))
	input.UpstreamModelID = strings.TrimSpace(input.UpstreamModelID)
	if input.ModelID == "" || input.RoutePoolID == "" || !input.ProductScope.Valid() || !validProtocol(input.Protocol) || input.UpstreamModelID == "" || input.Priority < 0 {
		return nil, fmt.Errorf("%w: route target", ErrInvalidPlatformModel)
	}
	target := &ModelRouteTarget{ID: newPlatformID(), ModelID: input.ModelID, ProductScope: input.ProductScope, Protocol: input.Protocol, RoutePoolID: input.RoutePoolID, UpstreamModelID: input.UpstreamModelID, Priority: input.Priority, Enabled: input.Enabled}
	err := s.db.QueryRowContext(ctx, `INSERT INTO model_route_targets(id, model_id, product_scope, protocol, route_pool_id, upstream_model_id, priority, enabled) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id::text`, target.ID, target.ModelID, target.ProductScope, target.Protocol, target.RoutePoolID, target.UpstreamModelID, target.Priority, target.Enabled).Scan(&target.ID)
	if err != nil {
		return nil, err
	}
	return target, nil
}

func (s *PlatformStore) ListRouteTargets(ctx context.Context, modelID string) ([]ModelRouteTarget, error) {
	query := `SELECT id::text, model_id::text, product_scope, protocol, route_pool_id::text, upstream_model_id, priority, enabled FROM model_route_targets`
	args := []any{}
	if strings.TrimSpace(modelID) != "" {
		query += ` WHERE model_id=$1`
		args = append(args, modelID)
	}
	query += ` ORDER BY priority, upstream_model_id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]ModelRouteTarget, 0)
	for rows.Next() {
		var target ModelRouteTarget
		if err := rows.Scan(&target.ID, &target.ModelID, &target.ProductScope, &target.Protocol, &target.RoutePoolID, &target.UpstreamModelID, &target.Priority, &target.Enabled); err != nil {
			return nil, err
		}
		result = append(result, target)
	}
	return result, rows.Err()
}

func (s *PlatformStore) ReserveTokens(ctx context.Context, walletID, referenceID string, tokens int64) (*TokenReservation, error) {
	walletID, referenceID = strings.TrimSpace(walletID), strings.TrimSpace(referenceID)
	if walletID == "" || referenceID == "" || tokens <= 0 {
		return nil, fmt.Errorf("%w: token reservation", ErrInvalidPlan)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM ledger_entries WHERE wallet_account_id=$1 AND entry_type='reserve' AND reference_type='request' AND reference_id=$2)`, walletID, referenceID).Scan(&exists); err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("duplicate token reservation reference")
	}
	rows, err := tx.QueryContext(ctx, `SELECT id::text, granted_tokens, reserved_tokens, settled_tokens FROM quota_buckets WHERE wallet_account_id=$1 AND window_kind IN ('monthly','rolling_5h') AND starts_at <= now() AND ends_at > now() FOR UPDATE`, walletID)
	if err != nil {
		return nil, err
	}
	type bucket struct {
		id                         string
		granted, reserved, settled int64
	}
	buckets := make(map[string]bucket, 2)
	for rows.Next() {
		var value bucket
		if err := rows.Scan(&value.id, &value.granted, &value.reserved, &value.settled); err != nil {
			_ = rows.Close()
			return nil, err
		}
		buckets[value.id] = value
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if len(buckets) != 2 {
		return nil, ErrQuotaExceeded
	}
	for _, value := range buckets {
		if value.granted-value.reserved-value.settled < tokens {
			return nil, ErrQuotaExceeded
		}
	}
	for _, value := range buckets {
		if _, err := tx.ExecContext(ctx, `UPDATE quota_buckets SET reserved_tokens=reserved_tokens+$2, updated_at=now() WHERE id=$1`, value.id, tokens); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO ledger_entries(id, wallet_account_id, quota_bucket_id, entry_type, tokens, reference_type, reference_id, reason) VALUES ($1,$2,$3,'reserve',$4,'request',$5,'request quota hold')`, newPlatformID(), walletID, value.id, tokens, referenceID); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &TokenReservation{ReferenceID: referenceID, WalletID: walletID, Tokens: tokens, ReservedAt: time.Now().UTC()}, nil
}

// EnsureWallet creates an isolated balance for exactly one product surface.
// It is intentionally impossible for callers to obtain a combined Chat and
// Agent wallet from this method.
func (s *PlatformStore) EnsureWallet(ctx context.Context, userID string, scope ProductScope) (string, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" || !scope.Valid() {
		return "", fmt.Errorf("%w: wallet", ErrInvalidPlan)
	}
	walletID := newPlatformID()
	if err := s.db.QueryRowContext(ctx, `INSERT INTO wallet_accounts(id, user_id, product_scope) VALUES ($1,$2,$3) ON CONFLICT (user_id, product_scope) DO UPDATE SET updated_at=wallet_accounts.updated_at RETURNING id::text`, walletID, userID, scope).Scan(&walletID); err != nil {
		return "", err
	}
	return walletID, nil
}

// GrantQuota creates a fixed, auditable bucket. The caller has to create one
// monthly and one rolling bucket for a product scope; ReserveTokens then locks
// both before any upstream request begins.
func (s *PlatformStore) GrantQuota(ctx context.Context, walletID string, input QuotaBucketInput) (string, error) {
	walletID = strings.TrimSpace(walletID)
	input.WindowKind = strings.TrimSpace(strings.ToLower(input.WindowKind))
	input.Reference = strings.TrimSpace(input.Reference)
	input.Reason = strings.TrimSpace(input.Reason)
	if walletID == "" || (input.WindowKind != "monthly" && input.WindowKind != "rolling_5h" && input.WindowKind != "grant") || input.Tokens < 0 || !input.EndsAt.After(input.StartsAt) {
		return "", fmt.Errorf("%w: quota bucket", ErrInvalidPlan)
	}
	bucketID := newPlatformID()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO quota_buckets(id, wallet_account_id, window_kind, starts_at, ends_at, granted_tokens) VALUES ($1,$2,$3,$4,$5,$6)`, bucketID, walletID, input.WindowKind, input.StartsAt.UTC(), input.EndsAt.UTC(), input.Tokens); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO ledger_entries(id, wallet_account_id, quota_bucket_id, entry_type, tokens, reference_type, reference_id, reason) VALUES ($1,$2,$3,'grant',$4,'quota_bucket',$5,$6)`, newPlatformID(), walletID, bucketID, input.Tokens, input.Reference, input.Reason); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return bucketID, nil
}

// SettleReservedTokens turns the request hold into actual use and releases the
// surplus atomically. A failed or disconnected upstream request must call
// ReleaseReservedTokens instead when it did not perform billable work.
func (s *PlatformStore) SettleReservedTokens(ctx context.Context, walletID, referenceID string, actualTokens int64) error {
	if actualTokens < 0 {
		return fmt.Errorf("%w: negative settlement", ErrInvalidPlan)
	}
	return s.finishReservedTokens(ctx, walletID, referenceID, actualTokens, false)
}

func (s *PlatformStore) ReleaseReservedTokens(ctx context.Context, walletID, referenceID string) error {
	return s.finishReservedTokens(ctx, walletID, referenceID, 0, true)
}

func (s *PlatformStore) finishReservedTokens(ctx context.Context, walletID, referenceID string, actualTokens int64, releaseOnly bool) error {
	walletID, referenceID = strings.TrimSpace(walletID), strings.TrimSpace(referenceID)
	if walletID == "" || referenceID == "" {
		return fmt.Errorf("%w: token settlement", ErrInvalidPlan)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var alreadyFinished bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM ledger_entries WHERE wallet_account_id=$1 AND entry_type IN ('settle','release') AND reference_type='request' AND reference_id=$2)`, walletID, referenceID).Scan(&alreadyFinished); err != nil {
		return err
	}
	if alreadyFinished {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT b.id::text, b.granted_tokens, b.reserved_tokens, b.settled_tokens, l.tokens FROM ledger_entries l JOIN quota_buckets b ON b.id=l.quota_bucket_id WHERE l.wallet_account_id=$1 AND l.entry_type='reserve' AND l.reference_type='request' AND l.reference_id=$2 FOR UPDATE`, walletID, referenceID)
	if err != nil {
		return err
	}
	type heldBucket struct {
		id                               string
		granted, reserved, settled, held int64
	}
	var buckets []heldBucket
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
	for _, bucket := range buckets {
		settle := actualTokens
		if releaseOnly {
			settle = 0
		}
		if bucket.reserved < bucket.held || bucket.granted-bucket.reserved-bucket.settled+bucket.held < settle {
			return ErrQuotaExceeded
		}
		if _, err := tx.ExecContext(ctx, `UPDATE quota_buckets SET reserved_tokens=reserved_tokens-$2, settled_tokens=settled_tokens+$3, updated_at=now() WHERE id=$1`, bucket.id, bucket.held, settle); err != nil {
			return err
		}
		if settle > 0 {
			if _, err := tx.ExecContext(ctx, `INSERT INTO ledger_entries(id, wallet_account_id, quota_bucket_id, entry_type, tokens, reference_type, reference_id, reason) VALUES ($1,$2,$3,'settle',$4,'request',$5,'actual token use')`, newPlatformID(), walletID, bucket.id, settle, referenceID); err != nil {
				return err
			}
		}
		released := bucket.held - settle
		if released > 0 {
			if _, err := tx.ExecContext(ctx, `INSERT INTO ledger_entries(id, wallet_account_id, quota_bucket_id, entry_type, tokens, reference_type, reference_id, reason) VALUES ($1,$2,$3,'release',$4,'request',$5,'unused token hold released')`, newPlatformID(), walletID, bucket.id, released, referenceID); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func validateProviderConnectionInput(input *ProviderConnectionInput) error {
	input.ProviderKind = strings.TrimSpace(strings.ToLower(input.ProviderKind))
	input.ProviderName = strings.TrimSpace(strings.ToLower(input.ProviderName))
	input.Status = strings.TrimSpace(strings.ToLower(input.Status))
	if !validProviderKind(input.ProviderKind) || !providerNamePattern.MatchString(input.ProviderName) || !validProviderStatus(input.Status) {
		return fmt.Errorf("%w: provider connection", ErrInvalidPlatformModel)
	}
	if input.ProviderKind == "oauth" {
		// OAuth endpoints are kept in audited provider settings. A generic entry
		// cannot claim an integration works before its official metadata exists.
		input.BaseURL = strings.TrimSpace(input.BaseURL)
	} else {
		baseURL, err := normalizeProviderBaseURL(input.BaseURL)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidPlatformModel, err)
		}
		input.BaseURL = baseURL
	}
	if len(input.Settings) == 0 {
		input.Settings = json.RawMessage(`{}`)
	}
	if !isJSONObject(input.Settings) {
		return fmt.Errorf("%w: provider settings must be a JSON object", ErrInvalidPlatformModel)
	}
	return nil
}

func validateUpstreamAccountInput(input *UpstreamAccountInput) error {
	input.ConnectionID = strings.TrimSpace(input.ConnectionID)
	input.ProxyPoolID = strings.TrimSpace(input.ProxyPoolID)
	input.Label = strings.TrimSpace(input.Label)
	input.ExternalReference = strings.TrimSpace(input.ExternalReference)
	input.Status = strings.TrimSpace(strings.ToLower(input.Status))
	if input.ConnectionID == "" || input.Label == "" || len(input.Label) > 160 || len(input.ExternalReference) > 512 || !validUpstreamStatus(input.Status) {
		return fmt.Errorf("%w: upstream account", ErrInvalidPlatformModel)
	}
	if len(input.ModelCatalog) == 0 {
		input.ModelCatalog = json.RawMessage(`[]`)
	}
	if len(input.QuotaState) == 0 {
		input.QuotaState = json.RawMessage(`{}`)
	}
	if !isJSONArray(input.ModelCatalog) || !isJSONObject(input.QuotaState) {
		return fmt.Errorf("%w: upstream account catalog or quota", ErrInvalidPlatformModel)
	}
	return nil
}

func normalizeProviderBaseURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" {
		return "", errors.New("provider base URL must be an absolute URL without credentials, query, or fragment")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", errors.New("provider base URL must use HTTPS or local HTTP")
	}
	hostname := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if hostname == "" || len(hostname) > 253 {
		return "", errors.New("provider base URL host is invalid")
	}
	if parsed.Scheme == "http" && hostname != "localhost" && !isLoopbackHost(hostname) {
		return "", errors.New("provider base URL must use HTTPS unless it is loopback")
	}
	if port := parsed.Port(); port != "" {
		if _, err := net.LookupPort("tcp", port); err != nil {
			return "", errors.New("provider base URL port is invalid")
		}
	}
	parsed.Path = strings.TrimRight(parsed.EscapedPath(), "/")
	return strings.TrimRight(parsed.String(), "/"), nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	address, err := netip.ParseAddr(host)
	return err == nil && address.IsLoopback()
}

func validatePlatformModelInput(input *PlatformModelInput) error {
	input.ModelKey = strings.TrimSpace(strings.ToLower(input.ModelKey))
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.Description = strings.TrimSpace(input.Description)
	input.Category = strings.TrimSpace(strings.ToLower(input.Category))
	input.Status = strings.TrimSpace(strings.ToLower(input.Status))
	if !modelKeyPattern.MatchString(input.ModelKey) || input.DisplayName == "" || !validModelCategory(input.Category) || !validModelStatus(input.Status) {
		return ErrInvalidPlatformModel
	}
	if len(input.Capabilities) == 0 {
		input.Capabilities = json.RawMessage(`{}`)
	}
	if len(input.Billing) == 0 {
		input.Billing = json.RawMessage(`{}`)
	}
	if !isJSONObject(input.Capabilities) || !isJSONObject(input.Billing) {
		return fmt.Errorf("%w: capabilities and billing must be JSON objects", ErrInvalidPlatformModel)
	}
	return nil
}

func validatePlanInput(input *PlanInput) error {
	input.Code = strings.TrimSpace(strings.ToLower(input.Code))
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.Description = strings.TrimSpace(input.Description)
	input.Status = strings.TrimSpace(strings.ToLower(input.Status))
	if !planCodePattern.MatchString(input.Code) || input.DisplayName == "" || !validPlanStatus(input.Status) || input.SortOrder < 0 {
		return ErrInvalidPlan
	}
	return nil
}

func validatePlanVersionInput(input *PlanVersionInput) error {
	input.Currency = strings.TrimSpace(strings.ToUpper(input.Currency))
	if !currencyPattern.MatchString(input.Currency) || input.MonthlyPriceMinor < 0 || input.ChatMonthlyTokens < 0 || input.AgentMonthlyTokens < 0 || input.ChatRolling5HTokens < 0 || input.AgentRolling5HTokens < 0 {
		return ErrInvalidPlan
	}
	if len(input.Entitlements) == 0 {
		input.Entitlements = json.RawMessage(`{}`)
	}
	if len(input.ModelRules) == 0 {
		input.ModelRules = json.RawMessage(`{}`)
	}
	if !isJSONObject(input.Entitlements) || !isJSONObject(input.ModelRules) {
		return fmt.Errorf("%w: plan JSON must be objects", ErrInvalidPlan)
	}
	return nil
}

func isJSONObject(value json.RawMessage) bool {
	var object map[string]json.RawMessage
	return json.Unmarshal(value, &object) == nil
}

func isJSONArray(value json.RawMessage) bool {
	var array []json.RawMessage
	return json.Unmarshal(value, &array) == nil
}

func validProtocol(value string) bool {
	return value == "responses" || value == "chat_completions" || value == "messages" || value == "generate_content"
}

func normalizePlatformProtocols(values []string) ([]string, error) {
	if len(values) == 0 {
		values = []string{"responses", "chat_completions", "messages", "generate_content"}
	}
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" || seen[value] {
			continue
		}
		if !validProtocol(value) {
			return nil, ErrInvalidPlatformModel
		}
		seen[value] = true
		result = append(result, value)
	}
	if len(result) == 0 {
		return nil, ErrInvalidPlatformModel
	}
	return result, nil
}

func platformProtocolPlaceholders(start int, values []string) (string, []any) {
	parts := make([]string, len(values))
	args := make([]any, len(values))
	for i, value := range values {
		parts[i] = fmt.Sprintf("$%d", start+i)
		args[i] = value
	}
	return strings.Join(parts, ","), args
}

func validModelCategory(value string) bool {
	return value == "chat" || value == "image" || value == "audio" || value == "embedding" || value == "multimodal"
}

func validModelStatus(value string) bool {
	return value == "draft" || value == "active" || value == "disabled"
}
func validProviderKind(value string) bool {
	return value == "oauth" || value == "openai_compatible" || value == "anthropic_compatible" || value == "gemini_compatible"
}
func validProviderStatus(value string) bool {
	return value == "draft" || value == "active" || value == "disabled" || value == "error"
}
func validUpstreamStatus(value string) bool {
	return value == "active" || value == "disabled" || value == "cooldown" || value == "reauthorization_required" || value == "exhausted"
}
func validPlanStatus(value string) bool {
	return value == "draft" || value == "active" || value == "retired"
}

var (
	modelKeyPattern            = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	planCodePattern            = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	currencyPattern            = regexp.MustCompile(`^[A-Z]{3}$`)
	providerNamePattern        = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	paymentProviderTypePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
)

func newPlatformID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic("cryptographic random source unavailable: " + err.Error())
	}
	// RFC 4122 version 4 UUID, generated locally so no database extension or
	// superuser permission is required on modest self-hosted PostgreSQL nodes.
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	hexValue := hex.EncodeToString(raw[:])
	return hexValue[0:8] + "-" + hexValue[8:12] + "-" + hexValue[12:16] + "-" + hexValue[16:20] + "-" + hexValue[20:]
}
