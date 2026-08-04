package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrPaymentProviderUnavailable = errors.New("payment provider cannot be enabled before verified merchant integration")

type PaymentProvider struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	ProviderType     string    `json:"provider_type"`
	MerchantID       string    `json:"merchant_id"`
	Enabled          bool      `json:"enabled"`
	HealthStatus     string    `json:"health_status"`
	LastError        string    `json:"last_error"`
	HasConfiguration bool      `json:"has_configuration"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type PaymentProviderInput struct {
	ProviderType  string          `json:"provider_type"`
	MerchantID    string          `json:"merchant_id"`
	Configuration json.RawMessage `json:"configuration"`
	Enabled       bool            `json:"enabled"`
}

type PaymentOrder struct {
	ID              string          `json:"id"`
	TenantID        string          `json:"tenant_id"`
	UserID          string          `json:"user_id"`
	UserEmail       string          `json:"user_email,omitempty"`
	ProviderID      string          `json:"provider_id,omitempty"`
	OrderNo         string          `json:"order_no"`
	ProductScope    ProductScope    `json:"product_scope"`
	AmountMinor     int64           `json:"amount_minor"`
	Currency        string          `json:"currency"`
	Status          string          `json:"status"`
	ProductSnapshot json.RawMessage `json:"product_snapshot"`
	ProviderTradeNo string          `json:"provider_trade_no,omitempty"`
	ExpiresAt       time.Time       `json:"expires_at"`
	PaidAt          *time.Time      `json:"paid_at,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

func (s *PlatformStore) ListPaymentProviders(ctx context.Context) ([]PaymentProvider, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id::text,tenant_id::text,provider_type,merchant_id,enabled,health_status,last_error,configuration_enc <> '',created_at,updated_at FROM payment_providers ORDER BY provider_type,merchant_id,created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PaymentProvider, 0)
	for rows.Next() {
		var item PaymentProvider
		if err := rows.Scan(&item.ID, &item.TenantID, &item.ProviderType, &item.MerchantID, &item.Enabled, &item.HealthStatus, &item.LastError, &item.HasConfiguration, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PlatformStore) CreatePaymentProvider(ctx context.Context, input PaymentProviderInput) (*PaymentProvider, error) {
	if err := validatePaymentProviderInput(&input); err != nil {
		return nil, err
	}
	if input.Enabled {
		return nil, ErrPaymentProviderUnavailable
	}
	encrypted, err := s.encryptPlatformSecret(string(input.Configuration), "platform-payment-provider-configuration")
	if err != nil {
		return nil, err
	}
	item := &PaymentProvider{ID: newPlatformID(), TenantID: DefaultPlatformTenantID(), ProviderType: input.ProviderType, MerchantID: input.MerchantID, Enabled: false, HealthStatus: "unconfigured", HasConfiguration: encrypted != ""}
	err = s.db.QueryRowContext(ctx, `INSERT INTO payment_providers(id,tenant_id,provider_type,merchant_id,configuration_enc,enabled,health_status,last_error)
VALUES($1,$2,$3,$4,$5,false,'unconfigured','verified merchant connector is not configured')
RETURNING created_at,updated_at`, item.ID, item.TenantID, item.ProviderType, item.MerchantID, encrypted).Scan(&item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return nil, err
	}
	item.LastError = "verified merchant connector is not configured"
	return item, nil
}

func (s *PlatformStore) SetPaymentProviderEnabled(ctx context.Context, id string, enabled bool) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return ErrNotFound
	}
	if enabled {
		return ErrPaymentProviderUnavailable
	}
	result, err := s.db.ExecContext(ctx, `UPDATE payment_providers SET enabled=false,health_status='unconfigured',last_error='verified merchant connector is not configured',updated_at=now() WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrNotFound
	}
	return nil
}

func (s *PlatformStore) ListPaymentOrders(ctx context.Context, limit int) ([]PaymentOrder, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT o.id::text,o.tenant_id::text,o.user_id::text,COALESCE(u.email,''),COALESCE(o.provider_id::text,''),o.order_no,o.product_scope,o.amount_minor,o.currency,o.status,o.product_snapshot,o.provider_trade_no,o.expires_at,o.paid_at,o.created_at,o.updated_at
FROM payment_orders o LEFT JOIN users u ON u.id=o.user_id
ORDER BY o.created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PaymentOrder, 0)
	for rows.Next() {
		var item PaymentOrder
		var paid sql.NullTime
		if err := rows.Scan(&item.ID, &item.TenantID, &item.UserID, &item.UserEmail, &item.ProviderID, &item.OrderNo, &item.ProductScope, &item.AmountMinor, &item.Currency, &item.Status, &item.ProductSnapshot, &item.ProviderTradeNo, &item.ExpiresAt, &paid, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		if paid.Valid {
			value := paid.Time
			item.PaidAt = &value
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func validatePaymentProviderInput(input *PaymentProviderInput) error {
	input.ProviderType = strings.TrimSpace(strings.ToLower(input.ProviderType))
	input.MerchantID = truncate(strings.TrimSpace(input.MerchantID), 160)
	if !paymentProviderTypePattern.MatchString(input.ProviderType) || input.MerchantID == "" {
		return fmt.Errorf("%w: payment provider", ErrInvalidPlan)
	}
	if len(input.Configuration) == 0 {
		input.Configuration = json.RawMessage(`{}`)
	}
	if !isJSONObject(input.Configuration) {
		return fmt.Errorf("%w: payment provider configuration", ErrInvalidPlan)
	}
	return nil
}
