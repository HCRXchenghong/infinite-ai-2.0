package app

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	modelManifestBodyLimit = int64(4 << 20)
	modelSyncWorkers       = 3
	maxModelsPerAccount    = 1000
	maxModelIDBytes        = 256
	modelSyncInterval      = 30 * time.Minute
	modelSyncTimeout       = 3 * time.Minute
)

var (
	ErrModelNotAvailable       = errors.New("requested model is not available")
	ErrModelCatalogUnavailable = errors.New("model catalog has no successful snapshot")
)

// ModelDescriptor is the compact administrator-facing projection. The full
// official model object is retained separately and is used for the Codex
// /models manifest so future reasoning/tool capability fields are not lost.
type ModelDescriptor struct {
	ID      string `json:"id"`
	Object  string `json:"object,omitempty"`
	OwnedBy string `json:"owned_by,omitempty"`
}

type AccountModelCatalog struct {
	AccountID   int64    `json:"account_id"`
	AccountName string   `json:"account_name"`
	Models      []string `json:"models"`
	UpdatedAt   int64    `json:"updated_at"`
	Error       string   `json:"error,omitempty"`
}

type ModelCatalog struct {
	Models     []ModelDescriptor     `json:"models"`
	Accounts   []AccountModelCatalog `json:"accounts"`
	ModelCount int                   `json:"model_count"`
	UpdatedAt  int64                 `json:"updated_at"`
}

type storedOfficialModel struct {
	ID      string
	Object  string
	OwnedBy string
	Raw     json.RawMessage
}

type parsedOfficialManifest struct {
	Raw    json.RawMessage
	Models []storedOfficialModel
}

// parseOfficialModelManifest validates the stable Codex envelope while
// retaining every unknown top-level and per-model field verbatim as JSON.
func parseOfficialModelManifest(body []byte) (*parsedOfficialManifest, error) {
	if len(body) == 0 || int64(len(body)) > modelManifestBodyLimit {
		return nil, errors.New("model manifest is empty or exceeds the size limit")
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil || envelope == nil {
		return nil, errors.New("model manifest is not a JSON object")
	}
	rawModels, exists := envelope["models"]
	if !exists {
		return nil, errors.New("model manifest is missing the models array")
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(rawModels, &entries); err != nil || entries == nil {
		return nil, errors.New("model manifest models field is not an array")
	}
	if len(entries) > maxModelsPerAccount {
		return nil, fmt.Errorf("model manifest contains more than %d models", maxModelsPerAccount)
	}

	seen := make(map[string]bool, len(entries))
	models := make([]storedOfficialModel, 0, len(entries))
	for _, entry := range entries {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(entry, &fields); err != nil || fields == nil {
			return nil, errors.New("model manifest contains a non-object model entry")
		}
		id := rawJSONString(fields["slug"])
		if id == "" {
			id = rawJSONString(fields["id"])
		}
		id = strings.TrimSpace(id)
		if id == "" || len(id) > maxModelIDBytes || strings.ContainsAny(id, "\x00\r\n") {
			return nil, errors.New("model manifest contains an invalid model identifier")
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		var compact bytes.Buffer
		if err := json.Compact(&compact, entry); err != nil {
			return nil, errors.New("model manifest contains invalid model JSON")
		}
		models = append(models, storedOfficialModel{
			ID: id, Object: strings.TrimSpace(rawJSONString(fields["object"])),
			OwnedBy: strings.TrimSpace(rawJSONString(fields["owned_by"])), Raw: append(json.RawMessage(nil), compact.Bytes()...),
		})
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, body); err != nil {
		return nil, errors.New("model manifest cannot be compacted")
	}
	return &parsedOfficialManifest{Raw: append(json.RawMessage(nil), compact.Bytes()...), Models: models}, nil
}

func rawJSONString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return ""
	}
	return value
}

// ReplaceAccountModels atomically replaces one live account's complete
// snapshot. The account predicate is checked inside the transaction so a sync
// which started before account deletion cannot restore model mappings.
func (s *Store) ReplaceAccountModels(ctx context.Context, accountID int64, manifest *parsedOfficialManifest) error {
	if manifest == nil {
		return errors.New("model manifest is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var live int
	if err = tx.QueryRowContext(ctx, `SELECT 1 FROM accounts WHERE id=? AND active=1 AND access_token_enc<>''`, accountID).Scan(&live); errors.Is(err, sql.ErrNoRows) {
		return ErrNoAccount
	} else if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM account_models WHERE account_id=?`, accountID); err != nil {
		return err
	}
	now := time.Now().Unix()
	for _, model := range manifest.Models {
		if _, err = tx.ExecContext(ctx, `INSERT INTO account_models(account_id,model_id,model_json,model_object,owned_by,updated_at) VALUES(?,?,?,?,?,?)`,
			accountID, model.ID, string(model.Raw), model.Object, model.OwnedBy, now); err != nil {
			return err
		}
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO account_model_snapshots(account_id,manifest_json,updated_at,error)
		SELECT id,?,?,'' FROM accounts WHERE id=? AND active=1 AND access_token_enc<>''
		ON CONFLICT(account_id) DO UPDATE SET manifest_json=excluded.manifest_json,updated_at=excluded.updated_at,error=''`,
		string(manifest.Raw), now, accountID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrNoAccount
	}
	return tx.Commit()
}

// RecordAccountModelSyncError retains the last good manifest/models and only
// updates its error marker. A deleted or disabled account cannot gain a new
// snapshot/error row through a late sync result.
func (s *Store) RecordAccountModelSyncError(ctx context.Context, accountID int64, detail string) error {
	detail = truncate(detail, 500)
	result, err := s.db.ExecContext(ctx, `INSERT INTO account_model_snapshots(account_id,manifest_json,updated_at,error)
		SELECT id,'',0,? FROM accounts WHERE id=? AND active=1 AND access_token_enc<>''
		ON CONFLICT(account_id) DO UPDATE SET error=excluded.error`, detail, accountID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrNoAccount
	}
	return nil
}

func (s *Store) ListModelCatalog(ctx context.Context) (*ModelCatalog, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT a.id,a.name,COALESCE(snapshot.updated_at,0),COALESCE(snapshot.error,''),
		COALESCE(model.model_id,''),COALESCE(model.model_object,''),COALESCE(model.owned_by,'')
	FROM accounts a
	LEFT JOIN account_model_snapshots snapshot ON snapshot.account_id=a.id
	LEFT JOIN account_models model ON model.account_id=a.id
	WHERE a.active=1 AND a.access_token_enc<>''
	ORDER BY a.id,model.model_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	catalog := &ModelCatalog{Models: make([]ModelDescriptor, 0), Accounts: make([]AccountModelCatalog, 0)}
	union := make(map[string]ModelDescriptor)
	accountIndex := make(map[int64]int)
	for rows.Next() {
		var accountID, updatedAt int64
		var accountName, syncError, modelID, object, ownedBy string
		if err := rows.Scan(&accountID, &accountName, &updatedAt, &syncError, &modelID, &object, &ownedBy); err != nil {
			return nil, err
		}
		index, exists := accountIndex[accountID]
		if !exists {
			index = len(catalog.Accounts)
			accountIndex[accountID] = index
			catalog.Accounts = append(catalog.Accounts, AccountModelCatalog{AccountID: accountID, AccountName: accountName, Models: make([]string, 0), UpdatedAt: updatedAt, Error: syncError})
			if updatedAt > catalog.UpdatedAt {
				catalog.UpdatedAt = updatedAt
			}
		}
		if modelID == "" {
			continue
		}
		catalog.Accounts[index].Models = append(catalog.Accounts[index].Models, modelID)
		if _, exists := union[modelID]; !exists {
			union[modelID] = ModelDescriptor{ID: modelID, Object: object, OwnedBy: ownedBy}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(union))
	for id := range union {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		catalog.Models = append(catalog.Models, union[id])
	}
	catalog.ModelCount = len(catalog.Models)
	return catalog, nil
}

// MergedOfficialModelManifest uses the newest live account snapshot as the
// top-level template, replacing only its models array with the active-account
// union. Every unknown official field on both levels is preserved.
func (s *Store) MergedOfficialModelManifest(ctx context.Context) ([]byte, error) {
	var template string
	err := s.db.QueryRowContext(ctx, `SELECT snapshot.manifest_json
	FROM account_model_snapshots snapshot JOIN accounts a ON a.id=snapshot.account_id
	WHERE a.active=1 AND a.access_token_enc<>'' AND snapshot.updated_at>0 AND snapshot.manifest_json<>''
	ORDER BY snapshot.updated_at DESC,a.id LIMIT 1`).Scan(&template)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrModelCatalogUnavailable
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT model.model_id,model.model_json
	FROM account_models model
	JOIN accounts a ON a.id=model.account_id
	JOIN account_model_snapshots snapshot ON snapshot.account_id=model.account_id AND snapshot.updated_at>0
	WHERE a.active=1 AND a.access_token_enc<>''
	ORDER BY model.model_id,snapshot.updated_at DESC,a.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := make(map[string]bool)
	models := make([]json.RawMessage, 0)
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		models = append(models, json.RawMessage(raw))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal([]byte(template), &envelope); err != nil || envelope == nil {
		return nil, errors.New("stored model manifest template is invalid")
	}
	mergedModels, err := json.Marshal(models)
	if err != nil {
		return nil, err
	}
	envelope["models"] = mergedModels
	return json.Marshal(envelope)
}

// SelectAccountForModel preserves the existing Key+session affinity. Requests
// which name a model fail closed until a real live catalog exists, then route
// only to accounts advertising it. An existing session is never silently moved
// when its bound account does not support a later model request.
func (s *Store) SelectAccountForModel(ctx context.Context, keyID int64, sessionHash, requestedModel string, ttl time.Duration) (*Account, error) {
	now := time.Now().Unix()
	expiresAt := time.Now().Add(ttl).Unix()
	requestedModel = strings.TrimSpace(requestedModel)
	if len(requestedModel) > maxModelIDBytes || strings.ContainsAny(requestedModel, "\x00\r\n") {
		return nil, ErrModelNotAvailable
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var keyActive int
	if err = tx.QueryRowContext(ctx, `SELECT 1 FROM api_keys WHERE id=? AND status='active'`, keyID).Scan(&keyActive); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrKeyInactive
	} else if err != nil {
		return nil, err
	}

	catalogActive := false
	if requestedModel != "" {
		var snapshots int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM account_model_snapshots snapshot
			JOIN accounts a ON a.id=snapshot.account_id
			WHERE a.active=1 AND a.access_token_enc<>'' AND snapshot.updated_at>0 AND snapshot.manifest_json<>''`).Scan(&snapshots); err != nil {
			return nil, err
		}
		catalogActive = snapshots > 0
		if !catalogActive {
			return nil, ErrModelCatalogUnavailable
		}
		var supported int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM account_models model JOIN accounts a ON a.id=model.account_id
				WHERE model.model_id=? AND a.active=1 AND a.access_token_enc<>''`, requestedModel).Scan(&supported); err != nil {
			return nil, err
		}
		if supported == 0 {
			return nil, ErrModelNotAvailable
		}
	}

	var accountID int64
	if sessionHash != "" {
		err = tx.QueryRowContext(ctx, `SELECT affinity.account_id FROM session_affinities affinity
			JOIN accounts a ON a.id=affinity.account_id
			WHERE affinity.key_id=? AND affinity.session_hash=? AND affinity.expires_at>?
			  AND a.active=1 AND a.access_token_enc<>''`, keyID, sessionHash, now).Scan(&accountID)
		if err == nil {
			if catalogActive && requestedModel != "" {
				var supported int
				if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM account_models WHERE account_id=? AND model_id=?`, accountID, requestedModel).Scan(&supported); err != nil {
					return nil, err
				}
				if supported == 0 {
					return nil, ErrModelNotAvailable
				}
			}
			if _, err = tx.ExecContext(ctx, `UPDATE session_affinities SET expires_at=?,last_used_at=? WHERE key_id=? AND session_hash=?`, expiresAt, now, keyID, sessionHash); err != nil {
				return nil, err
			}
			if err = tx.Commit(); err != nil {
				return nil, err
			}
			return s.GetAccount(ctx, accountID)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM session_affinities WHERE key_id=? AND session_hash=?`, keyID, sessionHash); err != nil {
			return nil, err
		}
	}

	query := `SELECT a.id FROM accounts a
		LEFT JOIN session_affinities affinity ON affinity.account_id=a.id AND affinity.expires_at>?
		WHERE a.active=1 AND a.access_token_enc<>'' AND a.cooldown_until<=?`
	args := []any{now, now}
	if catalogActive && requestedModel != "" {
		query += ` AND EXISTS(SELECT 1 FROM account_models model WHERE model.account_id=a.id AND model.model_id=?)`
		args = append(args, requestedModel)
	}
	query += ` GROUP BY a.id ORDER BY COUNT(affinity.account_id),a.last_used_at,a.id LIMIT 1`
	if err = tx.QueryRowContext(ctx, query, args...).Scan(&accountID); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoAccount
	} else if err != nil {
		return nil, err
	}
	if sessionHash != "" {
		if _, err = tx.ExecContext(ctx, `INSERT INTO session_affinities(key_id,session_hash,account_id,expires_at,last_used_at,created_at)
			VALUES(?,?,?,?,?,?) ON CONFLICT(key_id,session_hash) DO UPDATE SET
			account_id=excluded.account_id,expires_at=excluded.expires_at,last_used_at=excluded.last_used_at`,
			keyID, sessionHash, accountID, expiresAt, now, now); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetAccount(ctx, accountID)
}

func (s *Server) fetchAccountModelManifest(ctx context.Context, accountID int64) (*parsedOfficialManifest, error) {
	lock := s.accountLifecycleMutex(accountID)
	lock.Lock()
	defer lock.Unlock()
	return s.fetchAccountModelManifestLocked(ctx, accountID)
}

func (s *Server) fetchAccountModelManifestLocked(ctx context.Context, accountID int64) (*parsedOfficialManifest, error) {
	account, err := s.refreshAccountIfNeededLocked(ctx, &Account{ID: accountID})
	if err != nil {
		return nil, err
	}
	if !account.Active || strings.TrimSpace(account.AccessToken) == "" {
		return nil, ErrNoAccount
	}
	endpoint, err := url.Parse(s.cfg.UpstreamBaseURL)
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" || endpoint.Fragment != "" {
		return nil, errors.New("invalid Codex upstream URL")
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/models"
	query := endpoint.Query()
	query.Set("client_version", defaultCodexVersion)
	endpoint.RawQuery = query.Encode()
	callCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(callCtx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+account.AccessToken)
	request.Header.Set("ChatGPT-Account-ID", account.ChatGPTAccountID)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Originator", "codex_cli_rs")
	request.Header.Set("Version", defaultCodexVersion)
	request.Header.Set("User-Agent", defaultCodexUA)
	enforceCodexIdentity(request.Header, defaultCodexVersion)
	response, err := s.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("models request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("models upstream status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, modelManifestBodyLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read models response: %w", err)
	}
	if int64(len(body)) > modelManifestBodyLimit {
		return nil, errors.New("models response exceeds the size limit")
	}
	return parseOfficialModelManifest(body)
}

// syncAccountModels holds the account lifecycle lock through credential use
// and snapshot persistence. Account deletion therefore waits for the entire
// operation and then removes its result instead of returning while an old
// credential request or a late snapshot write is still in progress.
func (s *Server) syncAccountModels(ctx context.Context, accountID int64) error {
	lock := s.accountLifecycleMutex(accountID)
	lock.Lock()
	defer lock.Unlock()
	manifest, fetchErr := s.fetchAccountModelManifestLocked(ctx, accountID)
	if fetchErr == nil {
		return s.store.ReplaceAccountModels(ctx, accountID, manifest)
	}
	if errors.Is(fetchErr, ErrNoAccount) || errors.Is(fetchErr, ErrNotFound) {
		return fetchErr
	}
	if saveErr := s.store.RecordAccountModelSyncError(ctx, accountID, safeProxyError(fetchErr)); saveErr != nil {
		return fmt.Errorf("persist model sync error: %w", saveErr)
	}
	return nil
}

func (s *Server) RefreshAccountModels(ctx context.Context) (*ModelCatalog, error) {
	accounts, err := s.store.ListAccounts(ctx)
	if err != nil {
		return nil, err
	}
	active := make([]Account, 0, len(accounts))
	for _, account := range accounts {
		if account.Active {
			active = append(active, account)
		}
	}
	workers := modelSyncWorkers
	if workers > len(active) {
		workers = len(active)
	}
	jobs := make(chan int64)
	var wait sync.WaitGroup
	var failureMu sync.Mutex
	var persistenceFailures []error
	for i := 0; i < workers; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for accountID := range jobs {
				if syncErr := s.syncAccountModels(ctx, accountID); syncErr == nil || errors.Is(syncErr, ErrNoAccount) || errors.Is(syncErr, ErrNotFound) {
					continue
				} else {
					failureMu.Lock()
					persistenceFailures = append(persistenceFailures, fmt.Errorf("account %d model sync persistence: %w", accountID, syncErr))
					failureMu.Unlock()
				}
			}
		}()
	}
	for _, account := range active {
		select {
		case jobs <- account.ID:
		case <-ctx.Done():
			close(jobs)
			wait.Wait()
			return nil, ctx.Err()
		}
	}
	close(jobs)
	wait.Wait()
	if err := errors.Join(persistenceFailures...); err != nil {
		return nil, err
	}
	return s.store.ListModelCatalog(ctx)
}

func (s *Server) modelSyncLoop(ctx context.Context) {
	run := func() {
		if !s.beginRuntimeOperation() {
			return
		}
		defer s.restoreGate.RUnlock()
		syncCtx, cancel := context.WithTimeout(ctx, modelSyncTimeout)
		defer cancel()
		if _, err := s.RefreshAccountModels(syncCtx); err != nil && !errors.Is(err, context.Canceled) {
			slog.Warn("automatic Codex model synchronization failed", "error", safeProxyError(err))
		}
	}
	run()
	ticker := time.NewTicker(modelSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func (s *Server) syncNewAccountMetadata(accountID int64) {
	if !s.beginRuntimeOperation() {
		return
	}
	defer s.restoreGate.RUnlock()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := s.syncAccountModels(ctx, accountID); err != nil && !errors.Is(err, ErrNoAccount) && !errors.Is(err, ErrNotFound) {
		slog.Warn("new account model synchronization failed", "account_id", accountID, "error", safeProxyError(err))
	}
	if _, err := s.syncAccountQuota(ctx, accountID); err != nil {
		s.store.MarkAccountQuotaError(context.Background(), accountID, err.Error())
	}
}

func (s *Server) adminAccountModels(w http.ResponseWriter, r *http.Request) {
	catalog, err := s.store.ListModelCatalog(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "model_catalog_failed", "读取模型目录失败")
		return
	}
	writeJSON(w, http.StatusOK, catalog)
}

func (s *Server) adminRefreshAccountModels(w http.ResponseWriter, r *http.Request) {
	catalog, err := s.RefreshAccountModels(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "model_refresh_failed", "刷新模型目录失败")
		return
	}
	failures := 0
	for _, account := range catalog.Accounts {
		if account.Error != "" {
			failures++
		}
	}
	_ = s.store.Audit(r.Context(), "admin", "models.refreshed", "accounts", s.realIP(r), map[string]any{
		"accounts": len(catalog.Accounts), "models": catalog.ModelCount, "account_failures": failures,
	})
	writeJSON(w, http.StatusOK, catalog)
}

func (s *Server) serveStoredModelManifest(w http.ResponseWriter, r *http.Request) int {
	body, err := s.store.MergedOfficialModelManifest(r.Context())
	if errors.Is(err, ErrModelCatalogUnavailable) {
		writeError(w, http.StatusServiceUnavailable, "model_catalog_unavailable", "模型目录尚未完成真实同步")
		return http.StatusServiceUnavailable
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "model_catalog_failed", "读取模型目录失败")
		return http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
	return http.StatusOK
}
