package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
)

const (
	providerProbeTimeout        = 30 * time.Second
	providerResponseMax         = int64(4 << 20)
	providerAnthropicAPIVersion = "2023-06-01"
)

var (
	ErrProviderNotConfigured   = errors.New("provider connector is not configured")
	ErrProviderProtocolSupport = errors.New("provider protocol is not implemented")
	ErrUnsafeProviderTarget    = errors.New("provider target is unsafe")
)

// ProviderHealthResult is deliberately safe to expose to an administrator.
// Credentials, response bodies and request headers are never included.
type ProviderHealthResult struct {
	ConnectionID string    `json:"connection_id"`
	ProviderKind string    `json:"provider_kind"`
	ProviderName string    `json:"provider_name"`
	Healthy      bool      `json:"healthy"`
	StatusCode   int       `json:"status_code,omitempty"`
	Detail       string    `json:"detail"`
	CheckedAt    time.Time `json:"checked_at"`
}

type UpstreamModelSnapshot struct {
	ID           string          `json:"id"`
	RealModelID  string          `json:"real_model_id"`
	Descriptor   json.RawMessage `json:"descriptor"`
	Capabilities json.RawMessage `json:"capabilities"`
	Status       string          `json:"status"`
	DiscoveredAt time.Time       `json:"discovered_at"`
}

type providerSecretConnection struct {
	ProviderConnection
	CredentialEncrypted string
}

type providerAccountConnection struct {
	Account             UpstreamAccount
	CredentialEncrypted string
	Connection          providerSecretConnection
}

// TestProviderConnection performs a bounded, SSRF-protected protocol check.
// Only connector types with an actual public API contract are probed.  OAuth
// is intentionally not guessed: its own official connector must provide the
// refresh and health implementation before it can be marked usable.
func (s *PlatformStore) TestProviderConnection(ctx context.Context, connectionID string) (ProviderHealthResult, error) {
	connection, err := s.providerConnectionWithSecret(ctx, connectionID)
	if err != nil {
		return ProviderHealthResult{}, err
	}
	result := ProviderHealthResult{ConnectionID: connection.ID, ProviderKind: connection.ProviderKind, ProviderName: connection.ProviderName, CheckedAt: time.Now().UTC()}
	if connection.Status == "disabled" || connection.Status == "draft" {
		result.Detail = "连接当前未启用"
		return result, ErrProviderNotConfigured
	}
	credential, err := s.decryptPlatformSecret(connection.CredentialEncrypted, "platform-provider-credential")
	if err != nil {
		return result, err
	}
	if strings.TrimSpace(credential) == "" {
		result.Detail = "尚未保存管理端凭据"
		return result, ErrProviderNotConfigured
	}
	if connection.ProviderKind == "oauth" {
		result.Detail = "OAuth 连接器尚未完成官方端点配置，不能执行通用探测"
		return result, ErrProviderProtocolSupport
	}
	_, status, err := s.discoverProviderModels(ctx, connection.ProviderConnection, credential)
	result.StatusCode = status
	if err != nil {
		result.Detail = safeProviderDetail(err)
		_ = s.setProviderHealth(context.Background(), connection.ID, false, result.Detail)
		return result, err
	}
	result.Healthy = true
	result.Detail = "模型发现请求成功"
	if err := s.setProviderHealth(context.Background(), connection.ID, true, ""); err != nil {
		return result, err
	}
	return result, nil
}

// SyncUpstreamAccountModels discovers the models that a real endpoint can
// return.  Discovery creates only private upstream snapshots; publication to
// any product remains an explicit administrator action through platform model
// and route-target APIs.
func (s *PlatformStore) SyncUpstreamAccountModels(ctx context.Context, accountID string) ([]UpstreamModelSnapshot, error) {
	loaded, err := s.providerAccountWithSecret(ctx, accountID)
	if err != nil {
		return nil, err
	}
	if loaded.Account.Status != "active" || loaded.Connection.Status != "active" {
		return nil, ErrProviderNotConfigured
	}
	if loaded.Connection.ProviderKind == "oauth" {
		return nil, ErrProviderProtocolSupport
	}
	credential, err := s.upstreamCredential(loaded)
	if err != nil {
		return nil, err
	}
	models, _, err := s.discoverProviderModels(ctx, loaded.Connection.ProviderConnection, credential)
	if err != nil {
		_ = s.setUpstreamAccountError(context.Background(), loaded.Account.ID, safeProviderDetail(err))
		return nil, err
	}
	encoded, err := json.Marshal(models)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE upstream_accounts SET model_catalog=$2::jsonb,last_error='',last_used_at=now(),updated_at=now() WHERE id=$1 AND status='active'`, loaded.Account.ID, string(encoded)); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE upstream_model_snapshots SET status='unknown',updated_at=now() WHERE upstream_account_id=$1`, loaded.Account.ID); err != nil {
		return nil, err
	}
	for _, model := range models {
		if _, err := tx.ExecContext(ctx, `INSERT INTO upstream_model_snapshots(id,upstream_account_id,real_model_id,descriptor,capabilities,status,discovered_at,updated_at) VALUES($1,$2,$3,$4::jsonb,$5::jsonb,'active',now(),now()) ON CONFLICT(upstream_account_id,real_model_id) DO UPDATE SET descriptor=excluded.descriptor,capabilities=excluded.capabilities,status='active',discovered_at=now(),updated_at=now()`, newPlatformID(), loaded.Account.ID, model.RealModelID, string(model.Descriptor), string(model.Capabilities)); err != nil {
			return nil, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE provider_connections SET last_health_at=now(),last_error='',updated_at=now() WHERE id=$1`, loaded.Connection.ID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.ListUpstreamModelSnapshots(ctx, loaded.Account.ID)
}

func (s *PlatformStore) ListUpstreamModelSnapshots(ctx context.Context, accountID string) ([]UpstreamModelSnapshot, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id::text,real_model_id,descriptor,capabilities,status,discovered_at FROM upstream_model_snapshots WHERE upstream_account_id=$1 ORDER BY real_model_id`, strings.TrimSpace(accountID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]UpstreamModelSnapshot, 0)
	for rows.Next() {
		var item UpstreamModelSnapshot
		if err := rows.Scan(&item.ID, &item.RealModelID, &item.Descriptor, &item.Capabilities, &item.Status, &item.DiscoveredAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PlatformStore) providerConnectionWithSecret(ctx context.Context, id string) (providerSecretConnection, error) {
	var item providerSecretConnection
	err := s.db.QueryRowContext(ctx, `SELECT id::text,tenant_id::text,provider_kind,provider_name,base_url,settings,status,last_health_at,last_error,credential_enc,created_at,updated_at FROM provider_connections WHERE id=$1`, strings.TrimSpace(id)).Scan(&item.ID, &item.TenantID, &item.ProviderKind, &item.ProviderName, &item.BaseURL, &item.Settings, &item.Status, &item.LastHealthAt, &item.LastError, &item.CredentialEncrypted, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return item, ErrNotFound
	}
	item.HasCredential = strings.TrimSpace(item.CredentialEncrypted) != ""
	return item, err
}

func (s *PlatformStore) providerAccountWithSecret(ctx context.Context, id string) (providerAccountConnection, error) {
	var item providerAccountConnection
	var cooldown, reset, lastUsed sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT a.id::text,a.connection_id::text,COALESCE(a.proxy_pool_id::text,''),a.label,a.external_account_ref_hash,a.model_catalog,a.quota_state,a.status,a.health_score,a.cooldown_until,a.reset_at,a.last_used_at,a.last_error,a.credential_enc,a.created_at,a.updated_at,c.id::text,c.tenant_id::text,c.provider_kind,c.provider_name,c.base_url,c.settings,c.status,c.last_health_at,c.last_error,c.credential_enc,c.created_at,c.updated_at FROM upstream_accounts a JOIN provider_connections c ON c.id=a.connection_id WHERE a.id=$1`, strings.TrimSpace(id)).Scan(&item.Account.ID, &item.Account.ConnectionID, &item.Account.ProxyPoolID, &item.Account.Label, &item.Account.ExternalReferenceHash, &item.Account.ModelCatalog, &item.Account.QuotaState, &item.Account.Status, &item.Account.HealthScore, &cooldown, &reset, &lastUsed, &item.Account.LastError, &item.CredentialEncrypted, &item.Account.CreatedAt, &item.Account.UpdatedAt, &item.Connection.ID, &item.Connection.TenantID, &item.Connection.ProviderKind, &item.Connection.ProviderName, &item.Connection.BaseURL, &item.Connection.Settings, &item.Connection.Status, &item.Connection.LastHealthAt, &item.Connection.LastError, &item.Connection.CredentialEncrypted, &item.Connection.CreatedAt, &item.Connection.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return item, ErrNotFound
	}
	if err != nil {
		return item, err
	}
	if cooldown.Valid {
		item.Account.CooldownUntil = &cooldown.Time
	}
	if reset.Valid {
		item.Account.ResetAt = &reset.Time
	}
	if lastUsed.Valid {
		item.Account.LastUsedAt = &lastUsed.Time
	}
	item.Account.HasCredential = strings.TrimSpace(item.CredentialEncrypted) != ""
	item.Connection.HasCredential = strings.TrimSpace(item.Connection.CredentialEncrypted) != ""
	return item, nil
}

func (s *PlatformStore) upstreamCredential(item providerAccountConnection) (string, error) {
	if strings.TrimSpace(item.CredentialEncrypted) != "" {
		plain, err := s.decryptPlatformSecret(item.CredentialEncrypted, "platform-upstream-account-credential")
		if err != nil {
			return "", err
		}
		var envelope map[string]string
		if json.Unmarshal([]byte(plain), &envelope) == nil {
			for _, key := range []string{"api_key", "credential", "access_token"} {
				if value := strings.TrimSpace(envelope[key]); value != "" {
					return value, nil
				}
			}
		}
		if strings.TrimSpace(plain) != "" {
			return plain, nil
		}
	}
	plain, err := s.decryptPlatformSecret(item.Connection.CredentialEncrypted, "platform-provider-credential")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(plain) == "" {
		return "", ErrProviderNotConfigured
	}
	return plain, nil
}

func (s *PlatformStore) setProviderHealth(ctx context.Context, id string, healthy bool, detail string) error {
	status := ""
	if !healthy {
		status = "error"
	}
	query := `UPDATE provider_connections SET last_health_at=now(),last_error=$2,updated_at=now()`
	args := []any{id, truncate(detail, 500)}
	if status != "" {
		query += `,status=$3`
		args = append(args, status)
	} else {
		// A successful explicit administrator test may recover a connection
		// from automatic error state, but it can never revive a deliberately
		// disabled or draft configuration.
		query += `,status=CASE WHEN status='error' THEN 'active' ELSE status END`
	}
	query += ` WHERE id=$1 AND status<>'disabled'`
	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNotFound
	}
	return nil
}
func (s *PlatformStore) setUpstreamAccountError(ctx context.Context, id, detail string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE upstream_accounts SET last_error=$2,updated_at=now() WHERE id=$1`, id, truncate(detail, 500))
	return err
}

func (s *PlatformStore) discoverProviderModels(ctx context.Context, connection ProviderConnection, credential string) ([]UpstreamModelSnapshot, int, error) {
	endpoint, headers, err := providerModelEndpoint(connection, credential)
	if err != nil {
		return nil, 0, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, providerProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	client := safeProviderHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, providerResponseMax+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if int64(len(body)) > providerResponseMax {
		return nil, resp.StatusCode, errors.New("provider model response exceeds 4 MiB")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.StatusCode, fmt.Errorf("provider returned HTTP %d", resp.StatusCode)
	}
	models, err := parseProviderModels(connection.ProviderKind, body)
	return models, resp.StatusCode, err
}

func providerModelEndpoint(connection ProviderConnection, credential string) (string, map[string]string, error) {
	base, err := url.Parse(connection.BaseURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return "", nil, ErrProviderNotConfigured
	}
	if err = validateProviderEndpointHost(base); err != nil {
		return "", nil, err
	}
	credential = strings.TrimSpace(credential)
	if credential == "" {
		return "", nil, ErrProviderNotConfigured
	}
	switch connection.ProviderKind {
	case "openai_compatible":
		return appendProviderPath(base, "models").String(), map[string]string{"Authorization": "Bearer " + credential, "Accept": "application/json"}, nil
	case "anthropic_compatible":
		return appendProviderPath(base, "models").String(), map[string]string{"X-API-Key": credential, "Anthropic-Version": providerAnthropicAPIVersion, "Accept": "application/json"}, nil
	case "gemini_compatible":
		endpoint := appendProviderPath(base, "models")
		query := endpoint.Query()
		query.Set("key", credential)
		endpoint.RawQuery = query.Encode()
		return endpoint.String(), map[string]string{"Accept": "application/json"}, nil
	default:
		return "", nil, ErrProviderProtocolSupport
	}
}

func appendProviderPath(base *url.URL, suffix string) *url.URL {
	copy := *base
	copy.RawQuery = ""
	copy.Fragment = ""
	copy.Path = path.Join("/", copy.Path, suffix)
	return &copy
}

func parseProviderModels(kind string, body []byte) ([]UpstreamModelSnapshot, error) {
	var envelope struct {
		Data   []json.RawMessage `json:"data"`
		Models []json.RawMessage `json:"models"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, errors.New("provider model response is not valid JSON")
	}
	entries := envelope.Data
	if kind == "gemini_compatible" {
		entries = envelope.Models
	}
	if len(entries) == 0 {
		return nil, errors.New("provider returned no models")
	}
	if len(entries) > 1000 {
		return nil, errors.New("provider returned too many models")
	}
	items := make([]UpstreamModelSnapshot, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		var fields map[string]json.RawMessage
		if json.Unmarshal(entry, &fields) != nil {
			return nil, errors.New("provider model list contains a non-object entry")
		}
		id := rawJSONString(fields["id"])
		if id == "" {
			id = rawJSONString(fields["name"])
		}
		id = strings.TrimSpace(id)
		if id == "" || len(id) > 256 || strings.ContainsAny(id, "\x00\r\n") {
			return nil, errors.New("provider returned an invalid model identifier")
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		compact, err := compactJSONObject(entry)
		if err != nil {
			return nil, err
		}
		caps := json.RawMessage(`{}`)
		items = append(items, UpstreamModelSnapshot{ID: newPlatformID(), RealModelID: id, Descriptor: compact, Capabilities: caps, Status: "active", DiscoveredAt: time.Now().UTC()})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].RealModelID < items[j].RealModelID })
	return items, nil
}
func compactJSONObject(raw json.RawMessage) (json.RawMessage, error) {
	var value map[string]json.RawMessage
	if json.Unmarshal(raw, &value) != nil || value == nil {
		return nil, errors.New("provider model descriptor is not an object")
	}
	result, err := json.Marshal(value)
	return json.RawMessage(result), err
}

func safeProviderHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = safeProviderDialContext
	transport.ResponseHeaderTimeout = providerProbeTimeout
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.MaxIdleConnsPerHost = 2
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("provider redirects are not allowed") }}
}
func safeProviderDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := resolveProviderHost(ctx, host)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	var last error
	for _, ip := range ips {
		connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return connection, nil
		}
		last = err
	}
	if last == nil {
		last = ErrUnsafeProviderTarget
	}
	return nil, last
}
func validateProviderEndpointHost(endpoint *url.URL) error {
	_, err := resolveProviderHost(context.Background(), endpoint.Hostname())
	return err
}
func resolveProviderHost(ctx context.Context, host string) ([]netip.Addr, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return nil, ErrUnsafeProviderTarget
	}
	if direct, err := netip.ParseAddr(host); err == nil {
		if !allowedProviderAddress(direct) {
			return nil, ErrUnsafeProviderTarget
		}
		return []netip.Addr{direct}, nil
	}
	values, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve provider host: %w", err)
	}
	if len(values) == 0 {
		return nil, ErrUnsafeProviderTarget
	}
	for _, value := range values {
		if !allowedProviderAddress(value) {
			return nil, ErrUnsafeProviderTarget
		}
	}
	return values, nil
}
func allowedProviderAddress(value netip.Addr) bool {
	value = value.Unmap()
	return value.IsLoopback() || (!value.IsPrivate() && !value.IsLinkLocalUnicast() && !value.IsLinkLocalMulticast() && !value.IsMulticast() && !value.IsUnspecified())
}
func safeProviderDetail(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, ErrProviderNotConfigured):
		return "连接或凭据尚未配置"
	case errors.Is(err, ErrProviderProtocolSupport):
		return "该连接器尚未实现此协议"
	case errors.Is(err, ErrUnsafeProviderTarget):
		return "上游地址被 SSRF 策略拒绝"
	}
	return truncate(strings.ReplaceAll(strings.ReplaceAll(err.Error(), "\n", " "), "\r", " "), 180)
}
