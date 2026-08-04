package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

const platformPortableFormat = "friendgate-platform-postgres"

type platformPortablePayload struct {
	Format     string                         `json:"format"`
	Version    int                            `json:"version"`
	ExportedAt time.Time                      `json:"exported_at"`
	Tables     []platformPortableTablePayload `json:"tables"`
}

type platformPortableTablePayload struct {
	Name    string          `json:"name"`
	Columns []string        `json:"columns"`
	Rows    json.RawMessage `json:"rows"`
}

var platformPortableTableOrder = []string{
	"tenants",
	"users",
	"user_auth_identities",
	"user_devices",
	"platform_models",
	"product_model_publications",
	"provider_connections",
	"proxy_pools",
	"proxy_endpoints",
	"upstream_accounts",
	"upstream_model_snapshots",
	"route_pools",
	"route_pool_members",
	"model_route_targets",
	"plans",
	"plan_versions",
	"subscriptions",
	"wallet_accounts",
	"quota_buckets",
	"ledger_entries",
	"projects",
	"api_keys_v2",
	"api_key_scopes",
	"usage_records",
	"audit_events",
	"payment_providers",
	"payment_orders",
	"invitations_v2",
	"ip_bans_v2",
	"legacy_import_runs",
	"legacy_identity_map",
	"platform_settings",
	"administrators",
	"chat_conversations",
	"chat_messages",
}

var platformPortableTruncateTables = append([]string{
	"user_sessions",
	"route_affinities",
	"platform_device_auth_flows",
	"platform_device_sessions",
	"platform_device_nonces",
	"agent_sub_keys",
}, platformPortableTableOrder...)

var platformPortableEncryptedColumns = map[string]map[string]string{
	"administrators":       {"totp_secret_enc": "platform-admin-totp"},
	"user_auth_identities": {"credential_enc": "platform-user-auth-credential"},
	"user_devices":         {"mac_enc": "platform-device-mac"},
	"provider_connections": {"credential_enc": "platform-provider-credential"},
	"proxy_endpoints":      {"endpoint_enc": "platform-proxy-endpoint"},
	"upstream_accounts":    {"credential_enc": "platform-upstream-account-credential"},
	"api_keys_v2":          {"key_enc": "platform-api-key"},
	"payment_providers":    {"configuration_enc": "platform-payment-provider-configuration"},
}

func (s *PlatformStore) createPlatformPortableBackupFile(ctx context.Context, passphrase, directory string) (path string, size int64, resultErr error) {
	if s == nil {
		return "", 0, ErrPlatformDatabaseUnavailable
	}
	payload, err := s.createPlatformPortablePayload(ctx)
	if err != nil {
		return "", 0, err
	}
	if err := s.preparePlatformPortablePayload(ctx, &payload, s.vault, s.vault); err != nil {
		return "", 0, err
	}
	payloadPath, err := writePlatformPortablePayloadFile(directory, payload)
	if err != nil {
		return "", 0, err
	}
	defer os.Remove(payloadPath)

	output, err := os.CreateTemp(directory, ".infinite-ai-platform-export-*.fgbackup")
	if err != nil {
		return "", 0, err
	}
	path = output.Name()
	defer func() {
		if resultErr != nil {
			_ = output.Close()
			_ = os.Remove(path)
		}
	}()
	if err := output.Chmod(0o600); err != nil {
		return path, 0, err
	}
	if err := writePortableBackupEnvelopeWithMagic(output, payloadPath, s.vault.key, passphrase, platformBackupPayloadMagic); err != nil {
		return path, 0, err
	}
	if err := output.Sync(); err != nil {
		return path, 0, err
	}
	if err := output.Close(); err != nil {
		return path, 0, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return path, 0, err
	}
	return path, info.Size(), nil
}

func (s *PlatformStore) createPlatformPortablePayload(ctx context.Context) (platformPortablePayload, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return platformPortablePayload{}, err
	}
	defer tx.Rollback()
	payload := platformPortablePayload{Format: platformPortableFormat, Version: portableBackupVersion, ExportedAt: time.Now().UTC(), Tables: make([]platformPortableTablePayload, 0, len(platformPortableTableOrder))}
	for _, table := range platformPortableTableOrder {
		columns, err := platformPortableColumns(ctx, tx, table)
		if err != nil {
			return platformPortablePayload{}, err
		}
		rows, err := exportPlatformPortableTable(ctx, tx, table, columns)
		if err != nil {
			return platformPortablePayload{}, err
		}
		payload.Tables = append(payload.Tables, platformPortableTablePayload{Name: table, Columns: columns, Rows: rows})
	}
	if err := tx.Commit(); err != nil {
		return platformPortablePayload{}, err
	}
	return payload, nil
}

func writePlatformPortablePayloadFile(directory string, payload platformPortablePayload) (path string, resultErr error) {
	file, err := os.CreateTemp(directory, ".infinite-ai-platform-payload-*.json")
	if err != nil {
		return "", err
	}
	path = file.Name()
	defer func() {
		if resultErr != nil {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return path, err
	}
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(payload); err != nil {
		return path, err
	}
	if err := file.Sync(); err != nil {
		return path, err
	}
	if err := file.Close(); err != nil {
		return path, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return path, err
	}
	if info.Size() <= 0 || info.Size() > portableBackupMaxDatabase {
		return path, errors.New("PostgreSQL portable payload exceeds backup limit")
	}
	return path, nil
}

func exportPlatformPortableTable(ctx context.Context, tx *sql.Tx, table string, columns []string) (json.RawMessage, error) {
	columnList := quotePGIdentifierList(columns)
	query := fmt.Sprintf(`SELECT COALESCE(jsonb_agg(to_jsonb(row_data)), '[]'::jsonb)::text FROM (SELECT %s FROM %s) AS row_data`, columnList, quotePGIdentifier(table))
	var raw string
	if err := tx.QueryRowContext(ctx, query).Scan(&raw); err != nil {
		return nil, err
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = "[]"
	}
	if !json.Valid([]byte(raw)) {
		return nil, fmt.Errorf("%w: exported table JSON", errInvalidPortableBackup)
	}
	return json.RawMessage(raw), nil
}

func platformPortableColumns(ctx context.Context, queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, table string) ([]string, error) {
	rows, err := queryer.QueryContext(ctx, `SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name=$1 ORDER BY ordinal_position`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns := make([]string, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		columns = append(columns, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(columns) == 0 {
		return nil, fmt.Errorf("%w: missing platform table %s", errInvalidPortableBackup, table)
	}
	return columns, nil
}

func (s *Server) restorePlatformPortablePayloadAuthorized(ctx context.Context, payloadPath string, sourceMasterKey []byte, authorization *portableBackupAuthorization) (portableRestoreSummary, error) {
	platform := s.store.Platform()
	if platform == nil {
		return portableRestoreSummary{}, ErrPlatformDatabaseUnavailable
	}
	payload, err := readPlatformPortablePayloadFile(payloadPath)
	if err != nil {
		return portableRestoreSummary{}, err
	}
	sourceVault, err := NewVault(sourceMasterKey)
	if err != nil {
		return portableRestoreSummary{}, errInvalidPortableBackup
	}
	defer zeroPortableBytes(sourceVault.key)
	if err := platform.preparePlatformPortablePayload(ctx, &payload, sourceVault, platform.vault); err != nil {
		return portableRestoreSummary{}, err
	}
	requestDone, finishRestore, err := s.beginPortableRestoreGeneration(ctx)
	if err != nil {
		return portableRestoreSummary{}, err
	}
	defer finishRestore()
	if authorization != nil {
		authCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		csrf, valid := s.store.AdminSession(authCtx, authorization.Token, authorization.IP)
		cancel()
		if !valid || csrf == "" || subtleCompare(csrf, authorization.CSRF) != 1 {
			return portableRestoreSummary{}, errPortableAdminAuthorization
		}
	}
	summary, err := platform.restorePlatformPortablePayload(ctx, &payload)
	if err != nil {
		return portableRestoreSummary{}, err
	}
	summary.CancelledRequests = len(requestDone)
	return summary, nil
}

func readPlatformPortablePayloadFile(path string) (platformPortablePayload, error) {
	info, err := os.Stat(path)
	if err != nil {
		return platformPortablePayload{}, err
	}
	if info.Size() <= 0 || info.Size() > portableBackupMaxDatabase {
		return platformPortablePayload{}, fmt.Errorf("%w: platform payload size", errInvalidPortableBackup)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return platformPortablePayload{}, err
	}
	var payload platformPortablePayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return platformPortablePayload{}, fmt.Errorf("%w: platform payload JSON", errInvalidPortableBackup)
	}
	return payload, nil
}

func (s *PlatformStore) preparePlatformPortablePayload(ctx context.Context, payload *platformPortablePayload, sourceVault, targetVault *Vault) error {
	if payload == nil || payload.Format != platformPortableFormat || payload.Version != portableBackupVersion {
		return fmt.Errorf("%w: platform payload format", errInvalidPortableBackup)
	}
	if sourceVault == nil || targetVault == nil {
		return fmt.Errorf("%w: platform vault", errInvalidPortableBackup)
	}
	expected := make(map[string]bool, len(platformPortableTableOrder))
	for _, table := range platformPortableTableOrder {
		expected[table] = false
	}
	for index := range payload.Tables {
		table := &payload.Tables[index]
		if _, ok := expected[table.Name]; !ok {
			return fmt.Errorf("%w: unexpected platform table %s", errInvalidPortableBackup, table.Name)
		}
		if expected[table.Name] {
			return fmt.Errorf("%w: duplicate platform table %s", errInvalidPortableBackup, table.Name)
		}
		expected[table.Name] = true
		currentColumns, err := platformPortableColumns(ctx, s.db, table.Name)
		if err != nil {
			return err
		}
		if !sameStringSlice(currentColumns, table.Columns) {
			return fmt.Errorf("%w: platform table schema %s", errInvalidPortableBackup, table.Name)
		}
		if err := reencryptPlatformPortableRows(table, sourceVault, targetVault); err != nil {
			return err
		}
	}
	for table, seen := range expected {
		if !seen {
			return fmt.Errorf("%w: missing platform table %s", errInvalidPortableBackup, table)
		}
	}
	return nil
}

func reencryptPlatformPortableRows(table *platformPortableTablePayload, sourceVault, targetVault *Vault) error {
	var rows []map[string]json.RawMessage
	if len(table.Rows) == 0 || json.Unmarshal(table.Rows, &rows) != nil {
		return fmt.Errorf("%w: platform table rows", errInvalidPortableBackup)
	}
	purposes := platformPortableEncryptedColumns[table.Name]
	columns := make(map[string]bool, len(table.Columns))
	for _, column := range table.Columns {
		columns[column] = true
		if strings.HasSuffix(column, "_enc") && purposes[column] == "" && platformPortableRowsHaveValue(rows, column) {
			return fmt.Errorf("%w: unsupported encrypted platform column %s.%s", errInvalidPortableBackup, table.Name, column)
		}
	}
	for rowIndex := range rows {
		row := rows[rowIndex]
		for column, purpose := range purposes {
			if !columns[column] {
				continue
			}
			encrypted, ok, err := platformPortableJSONString(row[column])
			if err != nil {
				return err
			}
			if !ok || strings.TrimSpace(encrypted) == "" {
				continue
			}
			plain, err := sourceVault.Decrypt(encrypted, purpose)
			if err != nil {
				return fmt.Errorf("%w: platform encrypted value %s.%s", errInvalidPortableBackup, table.Name, column)
			}
			if err := validatePlatformPortableSecret(table.Name, row, column, plain); err != nil {
				return err
			}
			reencrypted, err := targetVault.Encrypt(plain, purpose)
			if err != nil {
				return err
			}
			encoded, _ := json.Marshal(reencrypted)
			row[column] = encoded
		}
	}
	encoded, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	table.Rows = encoded
	return nil
}

func validatePlatformPortableSecret(table string, row map[string]json.RawMessage, column, plain string) error {
	switch table {
	case "api_keys_v2":
		hash, hashOK, hashErr := platformPortableJSONString(row["key_hash"])
		status, statusOK, statusErr := platformPortableJSONString(row["status"])
		if hashErr != nil || statusErr != nil || !hashOK || !statusOK || (plain != "" && tokenHash(plain) != hash) || (status != "deleted" && plain == "") {
			return fmt.Errorf("%w: platform API key hash", errInvalidPortableBackup)
		}
	case "user_devices":
		if column != "mac_enc" || strings.TrimSpace(plain) == "" {
			return nil
		}
		hash, hashOK, hashErr := platformPortableJSONString(row["mac_hash"])
		if hashErr != nil || !hashOK || tokenHash(plain) != hash {
			return fmt.Errorf("%w: platform device MAC", errInvalidPortableBackup)
		}
	case "administrators":
		if column != "totp_secret_enc" || strings.TrimSpace(plain) == "" {
			return nil
		}
		if _, ok := totpValue(plain, time.Now().Unix()/30); !ok {
			return fmt.Errorf("%w: platform administrator TOTP", errInvalidPortableBackup)
		}
	}
	return nil
}

func platformPortableRowsHaveValue(rows []map[string]json.RawMessage, column string) bool {
	for _, row := range rows {
		value, ok, err := platformPortableJSONString(row[column])
		if err == nil && ok && strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func platformPortableJSONString(raw json.RawMessage) (string, bool, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", false, nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false, fmt.Errorf("%w: platform string value", errInvalidPortableBackup)
	}
	return value, true, nil
}

func (s *PlatformStore) restorePlatformPortablePayload(ctx context.Context, payload *platformPortablePayload) (portableRestoreSummary, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return portableRestoreSummary{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "TRUNCATE TABLE "+quotePGIdentifierList(platformPortableTruncateTables)+" RESTART IDENTITY CASCADE"); err != nil {
		return portableRestoreSummary{}, err
	}
	tableByName := make(map[string]platformPortableTablePayload, len(payload.Tables))
	for _, table := range payload.Tables {
		tableByName[table.Name] = table
	}
	summary := portableRestoreSummary{}
	for _, name := range platformPortableTableOrder {
		table := tableByName[name]
		insert := fmt.Sprintf(`INSERT INTO %s (%s) SELECT %s FROM jsonb_populate_recordset(NULL::%s, $1::jsonb)`, quotePGIdentifier(name), quotePGIdentifierList(table.Columns), quotePGIdentifierList(table.Columns), quotePGIdentifier(name))
		result, err := tx.ExecContext(ctx, insert, string(table.Rows))
		if err != nil {
			return portableRestoreSummary{}, fmt.Errorf("%w: restore platform table %s", errInvalidPortableBackup, name)
		}
		rows, _ := result.RowsAffected()
		summary.Tables++
		summary.Rows += rows
	}
	if err := tx.Commit(); err != nil {
		return portableRestoreSummary{}, err
	}
	return summary, nil
}

func sameStringSlice(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func quotePGIdentifierList(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, quotePGIdentifier(value))
	}
	return strings.Join(quoted, ",")
}

func quotePGIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}
