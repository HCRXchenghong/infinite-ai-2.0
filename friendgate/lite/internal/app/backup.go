package app

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Portable backups deliberately use a small, versioned binary envelope rather
// than replacing the live SQLite file. The encrypted payload contains a
// consistent, session-free SQLite snapshot and the source vault key. Restore
// reads that snapshot through a separate read-only connection, decrypts every
// vault-protected value with the source key, and writes it under the current
// installation key in one target transaction.
const (
	portableBackupMagic          = "FGLTBK01"
	portableBackupPayloadMagic   = "FGLTDB01"
	portableBackupVersion        = 1
	portableBackupKDFIterations  = uint32(600_000)
	portableBackupMaxIterations  = uint32(2_000_000)
	portableBackupSaltBytes      = 16
	portableBackupNoncePrefixLen = 4
	portableBackupChunkBytes     = 1 << 20
	portableBackupHeaderBytes    = 8 + 4 + portableBackupSaltBytes + portableBackupNoncePrefixLen + 4 + 8
	portableBackupInnerBytes     = 8 + 32 + 8
	portableBackupMaxDatabase    = int64(4 << 30)
	portableBackupMaxUpload      = portableBackupMaxDatabase + 64<<20
	portableBackupMaxPassphrase  = 4096
)

var (
	errInvalidPortableBackup      = errors.New("invalid portable backup")
	errPortableAdminAuthorization = errors.New("portable backup administrator authorization expired")
	errPortableBackupBansAdmin    = errors.New("portable backup bans the importing administrator")
	portableExportMu              sync.Mutex
	portableImportMu              sync.Mutex
)

type portableBackupAuthorization struct {
	Token string
	CSRF  string
	IP    string
}

type portableRestoreSummary struct {
	Tables            int   `json:"tables"`
	Rows              int64 `json:"rows"`
	CancelledRequests int   `json:"cancelled_requests"`
	CacheDegraded     bool  `json:"cache_degraded"`
}

type portableTableSpec struct {
	name    string
	columns []string
	// optional tables were introduced after portable backup v1 shipped. An
	// older, otherwise-valid snapshot restores them as empty instead of making
	// the entire backup unusable.
	optional bool
}

var portableTableSpecs = []portableTableSpec{
	{name: "settings", columns: []string{"key", "value", "updated_at"}},
	{name: "accounts", columns: []string{
		"id", "name", "access_token_enc", "refresh_token_enc", "chatgpt_account_id", "client_id", "active", "max_concurrency", "expires_at", "last_used_at", "last_error", "cooldown_until", "plan_type", "quota_5h_used", "quota_5h_reset_at", "quota_7d_used", "quota_7d_reset_at", "quota_updated_at", "quota_error", "reset_credits", "reset_credit_times", "created_at", "updated_at",
	}},
	{name: "account_model_snapshots", optional: true, columns: []string{"account_id", "manifest_json", "updated_at", "error"}},
	{name: "account_models", optional: true, columns: []string{"account_id", "model_id", "model_json", "model_object", "owned_by", "updated_at"}},
	{name: "api_keys", columns: []string{"id", "role", "key_hash", "key_enc", "masked_key", "account_id", "quota_requests", "used_requests", "status", "last_used_at", "created_at", "updated_at"}},
	{name: "key_ips", columns: []string{"id", "key_id", "ip", "family", "device_note", "device_group", "created_at", "last_seen_at"}},
	{name: "key_devices", optional: true, columns: []string{"id", "key_id", "device_token_hash", "device_note", "created_at", "last_seen_at"}},
	{name: "session_affinities", columns: []string{"key_id", "session_hash", "account_id", "expires_at", "last_used_at", "created_at"}},
	{name: "invitations", columns: []string{"id", "role", "token_hash", "token_enc", "code_hash", "status", "account_id", "quota_requests", "expires_at", "verified_ip", "device_note", "binding_mode", "device_token_hash", "claim_session_hash", "probe_token_hash", "verified_at", "api_key_id", "generated_at", "reveal_until", "created_at"}},
	{name: "invitation_ips", columns: []string{"invitation_id", "ip", "family", "created_at"}},
	{name: "usage_logs", columns: []string{"id", "key_id", "account_id", "ip", "method", "path", "model", "status", "duration_ms", "input_tokens", "output_tokens", "total_tokens", "request_id", "error", "created_at"}},
	{name: "audit_logs", columns: []string{"id", "actor", "action", "target", "ip", "detail", "created_at"}},
	{name: "security_events", columns: []string{"id", "ip", "kind", "path", "detail", "created_at"}},
	{name: "ip_failures", columns: []string{"ip", "window_start", "attempts", "last_attempt"}},
	{name: "status_failures", columns: []string{"ip", "status", "window_start", "attempts", "last_attempt"}},
	{name: "banned_ips", columns: []string{"ip", "reason", "attempts", "created_at", "expires_at", "ban_group", "scope"}},
}

var portableDeleteOrder = []string{
	"invitation_ips", "session_affinities", "key_ips", "key_devices", "invitations", "api_keys", "account_models", "account_model_snapshots", "accounts",
	"usage_logs", "audit_logs", "security_events", "ip_failures", "status_failures", "banned_ips", "settings", "admin_sessions",
}

var portableSequenceTables = []string{"accounts", "api_keys", "key_ips", "key_devices", "invitations", "usage_logs", "audit_logs", "security_events"}

// adminExportBackup is intended to be registered below adminOnly as:
//
//	POST /api/system/backup/export
//
// The passphrase is accepted only in a JSON body so it never enters a URL or
// access log. The resulting file is already authenticated and encrypted before
// any response headers are committed.
func (s *Server) adminExportBackup(w http.ResponseWriter, r *http.Request) {
	setPortableBackupNoStore(w)
	var body struct {
		Passphrase string `json:"passphrase"`
	}
	if !decodeJSON(w, r, 8<<10, &body) {
		return
	}
	if err := validatePortableBackupPassphrase(body.Passphrase); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_passphrase", "备份口令必须为 12 到 4096 字节")
		return
	}

	portableExportMu.Lock()
	if _, ok := s.authorizePortableBackupAdmin(w, r); !ok {
		portableExportMu.Unlock()
		return
	}
	path, size, err := s.store.createPortableBackupFile(r.Context(), body.Passphrase, portableBackupDirectory(s))
	portableExportMu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "backup_export_failed", "创建加密备份失败")
		return
	}
	defer os.Remove(path)

	file, err := os.Open(path)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "backup_export_failed", "读取加密备份失败")
		return
	}
	defer file.Close()

	filename := "friendgate-portable-" + time.Now().Format("20060102-150405") + ".fgbackup"
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.WriteHeader(http.StatusOK)
	written, copyErr := io.Copy(w, file)
	if copyErr != nil || written != size {
		if copyErr == nil {
			copyErr = io.ErrShortWrite
		}
		s.setSecurityRuntimeFailure("backup_export_stream", fmt.Errorf("stream encrypted backup: %w", copyErr))
		return
	}
	s.setSecurityRuntimeFailure("backup_export_stream", nil)
	s.store.Audit(context.Background(), "admin", "backup.exported", "portable-v1", s.realIP(r), map[string]any{"bytes": size})
}

// adminImportBackup is intended to be registered below adminOnly as:
//
//	POST /api/system/backup/import
//
// It accepts multipart fields "passphrase" and "backup". The uploaded file is
// streamed to a private temporary file instead of ParseMultipartForm's /tmp
// spool, because the production container intentionally has a small tmpfs.
func (s *Server) adminImportBackup(w http.ResponseWriter, r *http.Request) {
	setPortableBackupNoStore(w)
	uploadPath, passphrase, err := s.receivePortableBackupMultipart(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_backup_upload", "备份文件或上传格式无效")
		return
	}
	defer os.Remove(uploadPath)
	if err := validatePortableBackupPassphrase(passphrase); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_passphrase", "备份口令必须为 12 到 4096 字节")
		return
	}

	portableImportMu.Lock()
	authorization, ok := s.authorizePortableBackupAdmin(w, r)
	if !ok {
		portableImportMu.Unlock()
		return
	}
	summary, err := s.restorePortableBackupFileAuthorized(r.Context(), uploadPath, passphrase, &authorization)
	if err != nil {
		portableImportMu.Unlock()
		if errors.Is(err, errPortableAdminAuthorization) {
			http.SetCookie(w, expiredCookie(adminCookieName, s.cfg.SecureCookies))
			writeError(w, http.StatusUnauthorized, "admin_session_expired", "恢复前复核失败：登录已失效，备份未提交")
			return
		}
		if errors.Is(err, errPortableBackupBansAdmin) {
			writeError(w, http.StatusConflict, "restore_would_ban_admin", "备份中的全局 IP 封禁会锁定当前管理员，已拒绝导入")
			return
		}
		if errors.Is(err, errInvalidPortableBackup) {
			writeError(w, http.StatusBadRequest, "invalid_backup", "备份文件、口令或备份内容无效")
			return
		}
		if errors.Is(err, ErrRequestDrainTimeout) || errors.Is(err, errBackupRestoreActive) {
			writeError(w, http.StatusServiceUnavailable, "restore_busy", "旧请求或后台任务未能在限时内退出，备份未提交，请稍后重试")
			return
		}
		writeError(w, http.StatusInternalServerError, "backup_restore_failed", "恢复备份失败，备份未提交")
		return
	}

	// The restored administrator credentials and TOTP factor may differ from the
	// current session. Every session was removed in the restore transaction, and
	// the browser cookie is explicitly expired before returning.
	http.SetCookie(w, expiredCookie(adminCookieName, s.cfg.SecureCookies))
	// Rejoin the restored generation while the process-wide import mutex still
	// excludes another import. This keeps the success audit inside the same
	// generation instead of allowing a late audit from import A to appear after
	// a concurrent import B has replaced the database again.
	if s.beginRuntimeOperation() {
		s.store.Audit(context.Background(), "admin", "backup.restored", "portable-v1", s.realIP(r), map[string]any{
			"tables": summary.Tables, "rows": summary.Rows, "cancelled_requests": summary.CancelledRequests, "cache_degraded": summary.CacheDegraded,
		})
		s.restoreGate.RUnlock()
	}
	portableImportMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "requires_relogin": true, "tables": summary.Tables, "rows": summary.Rows,
		"cancelled_requests": summary.CancelledRequests, "cache_degraded": summary.CacheDegraded,
	})
}

// Backup handlers are registered below adminOnly, but they may wait behind a
// long export/import after that middleware has authenticated them. Revalidate
// inside the relevant serialization lock so a request authorized by a session from generation
// A cannot export or overwrite generation B after A's sessions were removed.
func (s *Server) authorizePortableBackupAdmin(w http.ResponseWriter, r *http.Request) (portableBackupAuthorization, bool) {
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "origin_rejected", "请求来源不受信任")
		return portableBackupAuthorization{}, false
	}
	cookie, err := r.Cookie(adminCookieName)
	if err != nil {
		http.SetCookie(w, expiredCookie(adminCookieName, s.cfg.SecureCookies))
		writeError(w, http.StatusUnauthorized, "admin_auth_required", "请先登录")
		return portableBackupAuthorization{}, false
	}
	ip := s.realIP(r)
	csrf, ok := s.store.AdminSession(r.Context(), cookie.Value, ip)
	if !ok {
		http.SetCookie(w, expiredCookie(adminCookieName, s.cfg.SecureCookies))
		writeError(w, http.StatusUnauthorized, "admin_session_expired", "登录已失效")
		return portableBackupAuthorization{}, false
	}
	provided := r.Header.Get("X-CSRF-Token")
	if provided == "" || provided != csrf {
		writeError(w, http.StatusForbidden, "csrf_failed", "安全校验失败，请刷新页面")
		return portableBackupAuthorization{}, false
	}
	return portableBackupAuthorization{Token: cookie.Value, CSRF: provided, IP: ip}, true
}

func setPortableBackupNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

func validatePortableBackupPassphrase(passphrase string) error {
	if len(passphrase) < 12 || len(passphrase) > portableBackupMaxPassphrase {
		return errors.New("invalid passphrase length")
	}
	return nil
}

func portableBackupDirectory(s *Server) string {
	directory := filepath.Dir(s.cfg.DatabasePath)
	if strings.TrimSpace(directory) == "" || directory == "." {
		directory = s.cfg.DataDir
	}
	if strings.TrimSpace(directory) == "" {
		directory = os.TempDir()
	}
	return directory
}

func (s *Server) receivePortableBackupMultipart(w http.ResponseWriter, r *http.Request) (path, passphrase string, resultErr error) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/form-data" {
		return "", "", errInvalidPortableBackup
	}
	r.Body = http.MaxBytesReader(w, r.Body, portableBackupMaxUpload)
	reader, err := r.MultipartReader()
	if err != nil {
		return "", "", errInvalidPortableBackup
	}
	defer func() {
		if resultErr != nil && path != "" {
			_ = os.Remove(path)
		}
	}()
	seenPassphrase, seenBackup := false, false
	for {
		part, nextErr := reader.NextPart()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return path, "", errInvalidPortableBackup
		}
		name := part.FormName()
		switch name {
		case "passphrase":
			if seenPassphrase {
				_ = part.Close()
				return path, "", errInvalidPortableBackup
			}
			seenPassphrase = true
			value, readErr := io.ReadAll(io.LimitReader(part, portableBackupMaxPassphrase+1))
			_ = part.Close()
			if readErr != nil || len(value) > portableBackupMaxPassphrase {
				return path, "", errInvalidPortableBackup
			}
			passphrase = string(value)
		case "backup":
			if seenBackup {
				_ = part.Close()
				return path, "", errInvalidPortableBackup
			}
			seenBackup = true
			file, createErr := os.CreateTemp(portableBackupDirectory(s), ".friendgate-upload-*.fgbackup")
			if createErr != nil {
				_ = part.Close()
				return path, "", createErr
			}
			path = file.Name()
			_ = file.Chmod(0o600)
			written, copyErr := io.Copy(file, io.LimitReader(part, portableBackupMaxUpload+1))
			closeErr := file.Close()
			_ = part.Close()
			if copyErr != nil || closeErr != nil || written <= portableBackupHeaderBytes || written > portableBackupMaxUpload {
				return path, "", errInvalidPortableBackup
			}
		default:
			_ = part.Close()
			return path, "", errInvalidPortableBackup
		}
	}
	if !seenPassphrase || !seenBackup || path == "" {
		return path, "", errInvalidPortableBackup
	}
	return path, passphrase, nil
}

func (s *Store) createPortableBackupFile(ctx context.Context, passphrase, directory string) (path string, size int64, resultErr error) {
	snapshotPath, err := s.createSessionFreeSQLiteSnapshot(ctx, directory)
	if err != nil {
		return "", 0, err
	}
	defer os.Remove(snapshotPath)
	// Refuse to produce a deceptively successful but unrestorable archive. This
	// verifies schema, administrator recovery state, every declared ciphertext,
	// and plaintext/hash binding against the snapshot that will be encrypted.
	snapshotDB, err := openPortableSQLite(snapshotPath, true)
	if err != nil {
		return "", 0, err
	}
	validationErr := validatePortableSnapshot(ctx, snapshotDB)
	if validationErr == nil {
		validationErr = preflightPortableSnapshot(ctx, snapshotDB, s.vault, "")
	}
	closeErr := snapshotDB.Close()
	if validationErr != nil {
		return "", 0, validationErr
	}
	if closeErr != nil {
		return "", 0, closeErr
	}

	output, err := os.CreateTemp(directory, ".friendgate-export-*.fgbackup")
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
	if err := writePortableBackupEnvelope(output, snapshotPath, s.vault.key, passphrase); err != nil {
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

func (s *Store) createSessionFreeSQLiteSnapshot(ctx context.Context, directory string) (path string, resultErr error) {
	placeholder, err := os.CreateTemp(directory, ".friendgate-snapshot-*.db")
	if err != nil {
		return "", err
	}
	path = placeholder.Name()
	if err := placeholder.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	if err := os.Remove(path); err != nil {
		return "", err
	}
	defer func() {
		if resultErr != nil {
			_ = os.Remove(path)
		}
	}()

	// VACUUM INTO takes a transactionally consistent snapshot while compacting
	// free pages. The path is generated by this process; quote it as a SQLite
	// string literal rather than accepting any user-controlled SQL.
	statement := "VACUUM INTO " + sqliteStringLiteral(path)
	if _, err := s.db.ExecContext(ctx, statement); err != nil {
		return path, fmt.Errorf("create SQLite backup snapshot: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return path, err
	}

	db, err := openPortableSQLite(path, false)
	if err != nil {
		return path, err
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM admin_sessions"); err != nil {
		_ = db.Close()
		return path, fmt.Errorf("remove backup sessions: %w", err)
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM settings WHERE key LIKE 'oauth_flow:%'"); err != nil {
		_ = db.Close()
		return path, fmt.Errorf("remove backup OAuth flows: %w", err)
	}
	// Compact again so deleted session tokens cannot remain in free pages inside
	// the encrypted archive and can never be restored accidentally.
	if _, err := db.ExecContext(ctx, "VACUUM"); err != nil {
		_ = db.Close()
		return path, fmt.Errorf("compact session-free snapshot: %w", err)
	}
	if err := checkPortableSQLite(ctx, db); err != nil {
		_ = db.Close()
		return path, err
	}
	if err := db.Close(); err != nil {
		return path, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return path, err
	}
	if info.Size() <= 0 || info.Size() > portableBackupMaxDatabase {
		return path, errors.New("SQLite backup snapshot exceeds portable backup limit")
	}
	return path, nil
}

func sqliteStringLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func openPortableSQLite(path string, readOnly bool) (*sql.DB, error) {
	query := "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	if readOnly {
		query = "?mode=ro&immutable=1&_pragma=query_only(1)&_pragma=foreign_keys(1)"
	}
	dsn := (&url.URL{Scheme: "file", Path: path}).String() + query
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func checkPortableSQLite(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, "PRAGMA integrity_check")
	if err != nil {
		return fmt.Errorf("check SQLite backup integrity: %w", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			return err
		}
		count++
		if result != "ok" {
			return errors.New("SQLite backup integrity check failed")
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if count != 1 {
		return errors.New("SQLite backup integrity result is invalid")
	}
	return nil
}

func writePortableBackupEnvelope(output io.Writer, snapshotPath string, sourceMasterKey []byte, passphrase string) error {
	if len(sourceMasterKey) != 32 {
		return errors.New("source vault key is invalid")
	}
	snapshot, err := os.Open(snapshotPath)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	info, err := snapshot.Stat()
	if err != nil {
		return err
	}
	if info.Size() <= 0 || info.Size() > portableBackupMaxDatabase {
		return errors.New("SQLite snapshot size is invalid")
	}
	payloadSize := uint64(portableBackupInnerBytes) + uint64(info.Size())

	header := make([]byte, portableBackupHeaderBytes)
	copy(header[:8], portableBackupMagic)
	binary.BigEndian.PutUint32(header[8:12], portableBackupKDFIterations)
	if _, err := rand.Read(header[12 : 12+portableBackupSaltBytes]); err != nil {
		return err
	}
	nonceOffset := 12 + portableBackupSaltBytes
	if _, err := rand.Read(header[nonceOffset : nonceOffset+portableBackupNoncePrefixLen]); err != nil {
		return err
	}
	chunkOffset := nonceOffset + portableBackupNoncePrefixLen
	binary.BigEndian.PutUint32(header[chunkOffset:chunkOffset+4], portableBackupChunkBytes)
	binary.BigEndian.PutUint64(header[chunkOffset+4:chunkOffset+12], payloadSize)
	if _, err := output.Write(header); err != nil {
		return err
	}

	derivedKey := pbkdf2SHA256([]byte(passphrase), header[12:12+portableBackupSaltBytes], int(portableBackupKDFIterations), 32)
	defer zeroPortableBytes(derivedKey)
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	inner := make([]byte, portableBackupInnerBytes)
	defer zeroPortableBytes(inner)
	copy(inner[:8], portableBackupPayloadMagic)
	copy(inner[8:40], sourceMasterKey)
	binary.BigEndian.PutUint64(inner[40:48], uint64(info.Size()))
	reader := io.MultiReader(bytes.NewReader(inner), snapshot)

	plain := make([]byte, portableBackupChunkBytes)
	defer zeroPortableBytes(plain)
	remaining := payloadSize
	for index := uint64(0); remaining > 0; index++ {
		want := uint64(portableBackupChunkBytes)
		if remaining < want {
			want = remaining
		}
		chunk := plain[:int(want)]
		if _, err := io.ReadFull(reader, chunk); err != nil {
			return err
		}
		nonce := portableChunkNonce(header[nonceOffset:nonceOffset+portableBackupNoncePrefixLen], index)
		aad := portableChunkAAD(header, index)
		ciphertext := aead.Seal(nil, nonce, chunk, aad)
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(ciphertext)))
		if _, err := output.Write(length[:]); err != nil {
			zeroPortableBytes(ciphertext)
			return err
		}
		if _, err := output.Write(ciphertext); err != nil {
			zeroPortableBytes(ciphertext)
			return err
		}
		zeroPortableBytes(ciphertext)
		remaining -= want
	}
	return nil
}

func portableChunkNonce(prefix []byte, index uint64) []byte {
	nonce := make([]byte, 12)
	copy(nonce[:4], prefix)
	binary.BigEndian.PutUint64(nonce[4:], index)
	return nonce
}

func portableChunkAAD(header []byte, index uint64) []byte {
	aad := make([]byte, len(header)+8)
	copy(aad, header)
	binary.BigEndian.PutUint64(aad[len(header):], index)
	return aad
}

func zeroPortableBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func (s *Server) restorePortableBackupFile(ctx context.Context, uploadPath, passphrase string) (portableRestoreSummary, error) {
	return s.restorePortableBackupFileAuthorized(ctx, uploadPath, passphrase, nil)
}

func (s *Server) restorePortableBackupFileAuthorized(ctx context.Context, uploadPath, passphrase string, authorization *portableBackupAuthorization) (portableRestoreSummary, error) {
	snapshotPath, sourceMasterKey, err := decryptPortableBackupFile(uploadPath, passphrase, portableBackupDirectory(s))
	if err != nil {
		return portableRestoreSummary{}, err
	}
	defer os.Remove(snapshotPath)
	defer zeroPortableBytes(sourceMasterKey)

	sourceVault, err := NewVault(sourceMasterKey)
	if err != nil {
		return portableRestoreSummary{}, errInvalidPortableBackup
	}
	defer zeroPortableBytes(sourceVault.key)
	sourceDB, err := openPortableSQLite(snapshotPath, true)
	if err != nil {
		return portableRestoreSummary{}, errInvalidPortableBackup
	}
	defer sourceDB.Close()
	if err := validatePortableSnapshot(ctx, sourceDB); err != nil {
		return portableRestoreSummary{}, fmt.Errorf("%w: snapshot validation", errInvalidPortableBackup)
	}
	adminIP := ""
	if authorization != nil {
		adminIP = authorization.IP
	}
	// Complete all content checks before closing admission or cancelling an old
	// request. Invalid vault values, a broken administrator factor, or a backup
	// which would ban the importing administrator therefore have no runtime side
	// effects and cannot strand this installation after commit.
	if err := preflightPortableSnapshot(ctx, sourceDB, sourceVault, adminIP); err != nil {
		return portableRestoreSummary{}, err
	}

	// Establish a generation boundary before modifying the target. Admission is
	// closed first, every request from the old database is cancelled and fully
	// drained, and only then may the single restore transaction begin. Therefore
	// an old request can never append usage or account state after the new data
	// commits. If draining times out, the target database is still untouched.
	s.keyRequestMu.Lock()
	if s.restoreInProgress {
		s.keyRequestMu.Unlock()
		return portableRestoreSummary{}, errBackupRestoreActive
	}
	s.restoreInProgress = true
	requestDone := make([]<-chan struct{}, 0)
	for keyID := range s.keyRequests {
		requestDone = append(requestDone, s.cancelKeyRequestsLocked(keyID)...)
	}
	s.keyRequestMu.Unlock()
	restoreGateLocked := false
	defer func() {
		s.keyRequestMu.Lock()
		s.restoreInProgress = false
		s.keyRequestMu.Unlock()
		if restoreGateLocked {
			s.restoreGate.Unlock()
		}
	}()

	if err := waitKeyRequests(ctx, requestDone); err != nil {
		s.setSecurityRuntimeFailure("backup_request_cancel", err)
		return portableRestoreSummary{}, err
	}
	s.setSecurityRuntimeFailure("backup_request_cancel", nil)
	if err := s.lockPortableRestoreGate(ctx); err != nil {
		s.setSecurityRuntimeFailure("backup_operation_drain", err)
		return portableRestoreSummary{}, err
	}
	restoreGateLocked = true
	s.setSecurityRuntimeFailure("backup_operation_drain", nil)
	if authorization != nil {
		authCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		csrf, valid := s.store.AdminSession(authCtx, authorization.Token, authorization.IP)
		cancel()
		if !valid || csrf == "" || csrf != authorization.CSRF {
			return portableRestoreSummary{}, errPortableAdminAuthorization
		}
	}

	summary, err := s.store.restorePortableSnapshot(ctx, sourceDB, sourceVault)
	if err != nil {
		return portableRestoreSummary{}, err
	}
	summary.CancelledRequests = len(requestDone)

	// Destroy transient secrets and state which belonged to the pre-restore
	// database. None of these values are part of a portable backup.
	s.oauthMu.Lock()
	s.oauthFlows = make(map[string]*openAIOAuthFlow)
	s.oauthMu.Unlock()
	s.setupMu.Lock()
	s.setupFlows = make(map[string]*adminSetupFlow)
	s.setupMu.Unlock()
	s.limitMu.Lock()
	s.limits = make(map[string]*attemptWindow)
	s.lastLimitSweep = time.Time{}
	s.limitMu.Unlock()
	s.refreshLocks.Range(func(key, _ any) bool {
		s.refreshLocks.Delete(key)
		return true
	})
	s.securityRuntimeMu.Lock()
	s.securityRuntime = make(map[string]securityRuntimeFailure)
	s.securityRuntimeMu.Unlock()

	// The durable commit must be followed by a real runtime reload before
	// admission reopens. A disconnected upload client must not cancel this step.
	// Configuration failure installs an explicitly protective fallback; ban
	// snapshot failure flips the cache into public fail-closed mode.
	runtimeCtx, cancelRuntimeReload := context.WithTimeout(context.Background(), 10*time.Second)
	securityConfig, configErr := loadPortableSecurityConfig(runtimeCtx, s.store.db)
	if configErr != nil {
		securityConfig = SecurityConfig{
			ProtectionEnabled: true, NginxProtection: true,
			Threshold404: 12, Threshold502: 30, WindowMinutes: 10, BanHours: 24,
		}
	}
	s.setSecurityConfig(securityConfig)
	s.setSecurityRuntimeFailure("backup_security_config", configErr)
	banErr := s.refreshBanCache(runtimeCtx)
	cancelRuntimeReload()
	summary.CacheDegraded = configErr != nil || banErr != nil
	return summary, nil
}

func (s *Server) lockPortableRestoreGate(ctx context.Context) error {
	drainCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), keyRequestDrainTimeout)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if s.restoreGate.TryLock() {
			return nil
		}
		select {
		case <-drainCtx.Done():
			return fmt.Errorf("%w: runtime operations: %v", ErrRequestDrainTimeout, drainCtx.Err())
		case <-ticker.C:
		}
	}
}

func decryptPortableBackupFile(uploadPath, passphrase, directory string) (snapshotPath string, sourceMasterKey []byte, resultErr error) {
	input, err := os.Open(uploadPath)
	if err != nil {
		return "", nil, fmt.Errorf("%w: open envelope", errInvalidPortableBackup)
	}
	defer input.Close()
	header := make([]byte, portableBackupHeaderBytes)
	if _, err := io.ReadFull(input, header); err != nil {
		return "", nil, fmt.Errorf("%w: short envelope", errInvalidPortableBackup)
	}
	if string(header[:8]) != portableBackupMagic {
		return "", nil, fmt.Errorf("%w: format", errInvalidPortableBackup)
	}
	iterations := binary.BigEndian.Uint32(header[8:12])
	if iterations < portableBackupKDFIterations || iterations > portableBackupMaxIterations {
		return "", nil, fmt.Errorf("%w: KDF", errInvalidPortableBackup)
	}
	nonceOffset := 12 + portableBackupSaltBytes
	chunkOffset := nonceOffset + portableBackupNoncePrefixLen
	chunkSize := binary.BigEndian.Uint32(header[chunkOffset : chunkOffset+4])
	payloadSize := binary.BigEndian.Uint64(header[chunkOffset+4 : chunkOffset+12])
	if chunkSize != portableBackupChunkBytes || payloadSize <= portableBackupInnerBytes || payloadSize > uint64(portableBackupMaxDatabase)+portableBackupInnerBytes {
		return "", nil, fmt.Errorf("%w: envelope limits", errInvalidPortableBackup)
	}

	derivedKey := pbkdf2SHA256([]byte(passphrase), header[12:12+portableBackupSaltBytes], int(iterations), 32)
	defer zeroPortableBytes(derivedKey)
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", nil, fmt.Errorf("%w: cipher", errInvalidPortableBackup)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil, fmt.Errorf("%w: cipher mode", errInvalidPortableBackup)
	}

	snapshot, err := os.CreateTemp(directory, ".friendgate-restore-*.db")
	if err != nil {
		return "", nil, err
	}
	snapshotPath = snapshot.Name()
	defer func() {
		if resultErr != nil {
			_ = snapshot.Close()
			_ = os.Remove(snapshotPath)
			zeroPortableBytes(sourceMasterKey)
		}
	}()
	if err := snapshot.Chmod(0o600); err != nil {
		return snapshotPath, nil, err
	}

	remaining := payloadSize
	var expectedDatabaseSize uint64
	var databaseWritten uint64
	for index := uint64(0); remaining > 0; index++ {
		plainSize := uint64(chunkSize)
		if remaining < plainSize {
			plainSize = remaining
		}
		var lengthRaw [4]byte
		if _, err := io.ReadFull(input, lengthRaw[:]); err != nil {
			return snapshotPath, nil, fmt.Errorf("%w: chunk length", errInvalidPortableBackup)
		}
		ciphertextSize := binary.BigEndian.Uint32(lengthRaw[:])
		if uint64(ciphertextSize) != plainSize+uint64(aead.Overhead()) {
			return snapshotPath, nil, fmt.Errorf("%w: chunk size", errInvalidPortableBackup)
		}
		ciphertext := make([]byte, ciphertextSize)
		if _, err := io.ReadFull(input, ciphertext); err != nil {
			zeroPortableBytes(ciphertext)
			return snapshotPath, nil, fmt.Errorf("%w: truncated chunk", errInvalidPortableBackup)
		}
		nonce := portableChunkNonce(header[nonceOffset:nonceOffset+portableBackupNoncePrefixLen], index)
		aad := portableChunkAAD(header, index)
		plain, err := aead.Open(nil, nonce, ciphertext, aad)
		zeroPortableBytes(ciphertext)
		if err != nil {
			return snapshotPath, nil, fmt.Errorf("%w: authentication", errInvalidPortableBackup)
		}
		if index == 0 {
			if len(plain) < portableBackupInnerBytes || string(plain[:8]) != portableBackupPayloadMagic {
				zeroPortableBytes(plain)
				return snapshotPath, nil, fmt.Errorf("%w: payload", errInvalidPortableBackup)
			}
			sourceMasterKey = append([]byte(nil), plain[8:40]...)
			expectedDatabaseSize = binary.BigEndian.Uint64(plain[40:48])
			if expectedDatabaseSize == 0 || expectedDatabaseSize > uint64(portableBackupMaxDatabase) || expectedDatabaseSize+portableBackupInnerBytes != payloadSize {
				zeroPortableBytes(plain)
				return snapshotPath, nil, fmt.Errorf("%w: database size", errInvalidPortableBackup)
			}
			written, writeErr := snapshot.Write(plain[portableBackupInnerBytes:])
			databaseWritten += uint64(written)
			zeroPortableBytes(plain)
			if writeErr != nil || written != len(plain)-portableBackupInnerBytes {
				return snapshotPath, nil, errors.New("write restored SQLite snapshot")
			}
		} else {
			written, writeErr := snapshot.Write(plain)
			databaseWritten += uint64(written)
			plainLength := len(plain)
			zeroPortableBytes(plain)
			if writeErr != nil || written != plainLength {
				return snapshotPath, nil, errors.New("write restored SQLite snapshot")
			}
		}
		remaining -= plainSize
	}
	if databaseWritten != expectedDatabaseSize {
		return snapshotPath, nil, fmt.Errorf("%w: payload length", errInvalidPortableBackup)
	}
	var trailing [1]byte
	if count, err := input.Read(trailing[:]); err != io.EOF || count != 0 {
		return snapshotPath, nil, fmt.Errorf("%w: trailing data", errInvalidPortableBackup)
	}
	if err := snapshot.Sync(); err != nil {
		return snapshotPath, nil, err
	}
	if err := snapshot.Close(); err != nil {
		return snapshotPath, nil, err
	}
	return snapshotPath, sourceMasterKey, nil
}

func validatePortableSnapshot(ctx context.Context, source *sql.DB) error {
	if err := checkPortableSQLite(ctx, source); err != nil {
		return err
	}
	for _, spec := range portableTableSpecs {
		rows, err := source.QueryContext(ctx, "PRAGMA table_info("+spec.name+")")
		if err != nil {
			return err
		}
		columns := make(map[string]bool, len(spec.columns))
		for rows.Next() {
			var cid int
			var name, dataType string
			var notNull, primaryKey int
			var defaultValue any
			if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
				_ = rows.Close()
				return err
			}
			columns[name] = true
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		_ = rows.Close()
		if len(columns) == 0 && spec.optional {
			continue
		}
		for _, column := range spec.columns {
			if !columns[column] {
				return errors.New("portable backup schema is incomplete")
			}
		}
	}
	var sessions int64
	if err := source.QueryRowContext(ctx, "SELECT COUNT(*) FROM admin_sessions").Scan(&sessions); err != nil || sessions != 0 {
		return errors.New("portable backup contains administrator sessions")
	}
	foreignRows, err := source.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return err
	}
	defer foreignRows.Close()
	if foreignRows.Next() {
		return errors.New("portable backup contains invalid foreign keys")
	}
	return foreignRows.Err()
}

func preflightPortableSnapshot(ctx context.Context, source *sql.DB, sourceVault *Vault, importingAdminIP string) error {
	for _, spec := range portableTableSpecs {
		switch spec.name {
		case "settings", "accounts", "api_keys", "invitations":
		default:
			continue
		}
		present, err := portableSourceTableExists(ctx, source, spec.name)
		if err != nil || !present {
			return fmt.Errorf("%w: encrypted table", errInvalidPortableBackup)
		}
		columnList := strings.Join(spec.columns, ",")
		rows, err := source.QueryContext(ctx, "SELECT "+columnList+" FROM "+spec.name)
		if err != nil {
			return fmt.Errorf("%w: encrypted rows", errInvalidPortableBackup)
		}
		for rows.Next() {
			values := make([]any, len(spec.columns))
			destinations := make([]any, len(spec.columns))
			for index := range values {
				destinations[index] = &values[index]
			}
			if err := rows.Scan(destinations...); err != nil {
				_ = rows.Close()
				return fmt.Errorf("%w: encrypted row scan", errInvalidPortableBackup)
			}
			// Re-encrypt into the same temporary Vault only to exercise every AAD,
			// ciphertext and hash. The mutated values are discarded and no target
			// row exists yet.
			if err := reencryptPortableRow(spec, values, sourceVault, sourceVault); err != nil {
				_ = rows.Close()
				return err
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return fmt.Errorf("%w: encrypted row iteration", errInvalidPortableBackup)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("%w: encrypted row close", errInvalidPortableBackup)
		}
	}
	if err := validatePortableAdministrator(ctx, source, sourceVault); err != nil {
		return fmt.Errorf("%w: administrator state", errInvalidPortableBackup)
	}
	if _, err := loadPortableSecurityConfig(ctx, source); err != nil {
		return fmt.Errorf("%w: security configuration", errInvalidPortableBackup)
	}
	var invalidStates int
	if err := source.QueryRowContext(ctx, `SELECT
(SELECT COUNT(*) FROM accounts WHERE active NOT IN (0,1))+
(SELECT COUNT(*) FROM api_keys WHERE status NOT IN ('active','disabled','deleted'))+
(SELECT COUNT(*) FROM invitations WHERE status NOT IN ('pending','verified','claimed','revoked','expired'))+
(SELECT COUNT(*) FROM banned_ips WHERE scope NOT IN ('all','public') OR TRIM(ip)='')`).Scan(&invalidStates); err != nil {
		return fmt.Errorf("%w: lifecycle state check", errInvalidPortableBackup)
	}
	if invalidStates != 0 {
		return fmt.Errorf("%w: invalid lifecycle state", errInvalidPortableBackup)
	}
	if importingAdminIP != "" && importingAdminIP != "unknown" {
		var blocked int
		err := source.QueryRowContext(ctx, `SELECT COUNT(*) FROM banned_ips
WHERE ip=? AND scope<>'public' AND (expires_at=0 OR expires_at>?)`, importingAdminIP, time.Now().Unix()).Scan(&blocked)
		if err != nil {
			return fmt.Errorf("%w: administrator ban check", errInvalidPortableBackup)
		}
		if blocked != 0 {
			return errPortableBackupBansAdmin
		}
	}
	return nil
}

func validatePortableAdministrator(ctx context.Context, source *sql.DB, sourceVault *Vault) error {
	keys := []string{
		"admin_username", "admin_password_hash", "admin_totp_secret_enc",
		"admin_totp_last_counter", "admin_initialized_at",
	}
	values := make(map[string]string, len(keys))
	rows, err := source.QueryContext(ctx, `SELECT key,value FROM settings
WHERE key IN ('admin_username','admin_password_hash','admin_totp_secret_enc','admin_totp_last_counter','admin_initialized_at')`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			_ = rows.Close()
			return err
		}
		values[key] = value
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, key := range keys {
		if strings.TrimSpace(values[key]) == "" {
			return errors.New("administrator setting is missing")
		}
	}
	username := strings.TrimSpace(values["admin_username"])
	if len(username) < 3 || len(username) > 64 || strings.ContainsAny(username, "\r\n\t") {
		return errors.New("administrator username is invalid")
	}
	if !validPortablePasswordHash(values["admin_password_hash"]) {
		return errors.New("administrator password hash is invalid")
	}
	initializedAt, err := strconv.ParseInt(values["admin_initialized_at"], 10, 64)
	if err != nil || initializedAt <= 0 {
		return errors.New("administrator initialization marker is invalid")
	}
	lastCounter, err := strconv.ParseInt(values["admin_totp_last_counter"], 10, 64)
	currentCounter := time.Now().Unix() / 30
	if err != nil || lastCounter < -1 || lastCounter > currentCounter+1 {
		return errors.New("administrator TOTP replay counter is invalid")
	}
	secret, err := sourceVault.Decrypt(values["admin_totp_secret_enc"], "admin-totp")
	if err != nil {
		return err
	}
	if _, ok := totpValue(secret, currentCounter); !ok {
		return errors.New("administrator TOTP secret is invalid")
	}
	return nil
}

func validPortablePasswordHash(encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 10_000 || iterations > 2_000_000 {
		return false
	}
	salt, saltErr := base64.RawURLEncoding.DecodeString(parts[2])
	digest, digestErr := base64.RawURLEncoding.DecodeString(parts[3])
	return saltErr == nil && digestErr == nil && len(salt) >= 16 && len(digest) == 32
}

func loadPortableSecurityConfig(ctx context.Context, db *sql.DB) (SecurityConfig, error) {
	config := SecurityConfig{NginxProtection: true, Threshold404: 12, Threshold502: 30, WindowMinutes: 10, BanHours: 24}
	rows, err := db.QueryContext(ctx, `SELECT key,value FROM settings WHERE key IN (
'security_protection_enabled','security_nginx_protection','security_threshold_404',
'security_threshold_502','security_window_minutes','security_ban_hours')`)
	if err != nil {
		return SecurityConfig{}, err
	}
	values := make(map[string]string, 6)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			_ = rows.Close()
			return SecurityConfig{}, err
		}
		values[key] = value
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return SecurityConfig{}, err
	}
	if err := rows.Close(); err != nil {
		return SecurityConfig{}, err
	}
	if value, exists := values["security_protection_enabled"]; exists {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return SecurityConfig{}, errors.New("invalid restored protection setting")
		}
		config.ProtectionEnabled = parsed
	}
	if value, exists := values["security_nginx_protection"]; exists {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return SecurityConfig{}, errors.New("invalid restored Nginx setting")
		}
		config.NginxProtection = parsed
	}
	parseBounded := func(key string, current, minimum, maximum int) (int, error) {
		value, exists := values[key]
		if !exists {
			return current, nil
		}
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < minimum || parsed > maximum {
			return 0, fmt.Errorf("invalid restored %s setting", key)
		}
		return parsed, nil
	}
	if config.Threshold404, err = parseBounded("security_threshold_404", config.Threshold404, 3, 10_000); err != nil {
		return SecurityConfig{}, err
	}
	if config.Threshold502, err = parseBounded("security_threshold_502", config.Threshold502, 3, 10_000); err != nil {
		return SecurityConfig{}, err
	}
	if config.WindowMinutes, err = parseBounded("security_window_minutes", config.WindowMinutes, 1, 1_440); err != nil {
		return SecurityConfig{}, err
	}
	if config.BanHours, err = parseBounded("security_ban_hours", config.BanHours, 1, 8_760); err != nil {
		return SecurityConfig{}, err
	}
	return config, nil
}

func (s *Store) restorePortableSnapshot(ctx context.Context, source *sql.DB, sourceVault *Vault) (portableRestoreSummary, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return portableRestoreSummary{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "PRAGMA defer_foreign_keys=ON"); err != nil {
		return portableRestoreSummary{}, err
	}
	for _, table := range portableDeleteOrder {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return portableRestoreSummary{}, err
		}
	}

	summary := portableRestoreSummary{}
	for _, spec := range portableTableSpecs {
		present, err := portableSourceTableExists(ctx, source, spec.name)
		if err != nil {
			return portableRestoreSummary{}, fmt.Errorf("%w: inspect table", errInvalidPortableBackup)
		}
		if !present && spec.optional {
			continue
		}
		if !present {
			return portableRestoreSummary{}, fmt.Errorf("%w: required table", errInvalidPortableBackup)
		}
		count, err := copyPortableTable(ctx, tx, source, spec, sourceVault, s.vault)
		if err != nil {
			return portableRestoreSummary{}, err
		}
		summary.Tables++
		summary.Rows += count
	}
	if err := resetPortableSequences(ctx, tx); err != nil {
		return portableRestoreSummary{}, err
	}
	foreignRows, err := tx.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return portableRestoreSummary{}, err
	}
	invalidForeignKey := foreignRows.Next()
	foreignErr := foreignRows.Err()
	_ = foreignRows.Close()
	if foreignErr != nil {
		return portableRestoreSummary{}, foreignErr
	}
	if invalidForeignKey {
		return portableRestoreSummary{}, fmt.Errorf("%w: foreign keys", errInvalidPortableBackup)
	}
	var sessions int64
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM admin_sessions").Scan(&sessions); err != nil {
		return portableRestoreSummary{}, err
	}
	if sessions != 0 {
		return portableRestoreSummary{}, errors.New("administrator sessions were not removed")
	}
	if err := tx.Commit(); err != nil {
		return portableRestoreSummary{}, err
	}
	return summary, nil
}

func portableSourceTableExists(ctx context.Context, source *sql.DB, name string) (bool, error) {
	var count int
	if err := source.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name=?`, name).Scan(&count); err != nil {
		return false, err
	}
	return count == 1, nil
}

func copyPortableTable(ctx context.Context, target *sql.Tx, source *sql.DB, spec portableTableSpec, sourceVault, targetVault *Vault) (int64, error) {
	columnList := strings.Join(spec.columns, ",")
	query := "SELECT " + columnList + " FROM " + spec.name
	if spec.name == "settings" {
		query += " WHERE key NOT LIKE 'oauth_flow:%'"
	}
	rows, err := source.QueryContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("%w: read table", errInvalidPortableBackup)
	}
	defer rows.Close()
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(spec.columns)), ",")
	insert := "INSERT INTO " + spec.name + "(" + columnList + ") VALUES(" + placeholders + ")"
	var count int64
	for rows.Next() {
		values := make([]any, len(spec.columns))
		destinations := make([]any, len(spec.columns))
		for index := range values {
			destinations[index] = &values[index]
		}
		if err := rows.Scan(destinations...); err != nil {
			return 0, fmt.Errorf("%w: scan table", errInvalidPortableBackup)
		}
		if err := reencryptPortableRow(spec, values, sourceVault, targetVault); err != nil {
			return 0, err
		}
		if _, err := target.ExecContext(ctx, insert, values...); err != nil {
			return 0, fmt.Errorf("%w: insert table", errInvalidPortableBackup)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("%w: iterate table", errInvalidPortableBackup)
	}
	return count, nil
}

func reencryptPortableRow(spec portableTableSpec, values []any, sourceVault, targetVault *Vault) error {
	index := make(map[string]int, len(spec.columns))
	for position, column := range spec.columns {
		index[column] = position
	}
	reencrypt := func(column, purpose string) error {
		position, ok := index[column]
		if !ok {
			return fmt.Errorf("%w: encrypted column", errInvalidPortableBackup)
		}
		encoded, ok := portableString(values[position])
		if !ok {
			return fmt.Errorf("%w: encrypted value type", errInvalidPortableBackup)
		}
		plain, err := sourceVault.Decrypt(encoded, purpose)
		if err != nil {
			return fmt.Errorf("%w: encrypted value", errInvalidPortableBackup)
		}
		reencrypted, err := targetVault.Encrypt(plain, purpose)
		if err != nil {
			return err
		}
		values[position] = reencrypted
		return nil
	}
	switch spec.name {
	case "accounts":
		if err := reencrypt("access_token_enc", "account-access"); err != nil {
			return err
		}
		if err := reencrypt("refresh_token_enc", "account-refresh"); err != nil {
			return err
		}
		access, err := targetVault.Decrypt(values[index["access_token_enc"]].(string), "account-access")
		if err != nil {
			return fmt.Errorf("%w: account access token", errInvalidPortableBackup)
		}
		active, ok := portableInt64(values[index["active"]])
		if !ok || (active != 0 && access == "") {
			return fmt.Errorf("%w: active account credentials", errInvalidPortableBackup)
		}
		return nil
	case "api_keys":
		if err := reencrypt("key_enc", "client-api-key"); err != nil {
			return err
		}
		plain, err := targetVault.Decrypt(values[index["key_enc"]].(string), "client-api-key")
		if err != nil {
			return fmt.Errorf("%w: API key", errInvalidPortableBackup)
		}
		hash, ok := portableString(values[index["key_hash"]])
		status, statusOK := portableString(values[index["status"]])
		if !ok || !statusOK || (plain != "" && tokenHash(plain) != hash) || (status != "deleted" && plain == "") {
			return fmt.Errorf("%w: API key hash", errInvalidPortableBackup)
		}
		return nil
	case "invitations":
		if err := reencrypt("token_enc", "invite-token"); err != nil {
			return err
		}
		plain, err := targetVault.Decrypt(values[index["token_enc"]].(string), "invite-token")
		if err != nil {
			return fmt.Errorf("%w: invitation", errInvalidPortableBackup)
		}
		hash, ok := portableString(values[index["token_hash"]])
		status, statusOK := portableString(values[index["status"]])
		if !ok || !statusOK || (plain != "" && tokenHash(plain) != hash) || ((status == "pending" || status == "verified") && plain == "") {
			return fmt.Errorf("%w: invitation hash", errInvalidPortableBackup)
		}
		return nil
	case "settings":
		key, keyOK := portableString(values[index["key"]])
		value, valueOK := portableString(values[index["value"]])
		if !keyOK || !valueOK {
			return fmt.Errorf("%w: setting", errInvalidPortableBackup)
		}
		if key == "admin_totp_secret_enc" {
			return reencrypt("value", "admin-totp")
		}
		// Never silently carry a future vault-encrypted setting under the old key.
		// A newer backup format must declare its purpose explicitly.
		if strings.HasSuffix(key, "_enc") && value != "" {
			return fmt.Errorf("%w: unsupported encrypted setting", errInvalidPortableBackup)
		}
	}
	return nil
}

func portableString(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case []byte:
		return string(typed), true
	default:
		return "", false
	}
}

func portableInt64(value any) (int64, bool) {
	switch typed := value.(type) {
	case int64:
		return typed, true
	case int:
		return int64(typed), true
	case []byte:
		parsed, err := strconv.ParseInt(string(typed), 10, 64)
		return parsed, err == nil
	case string:
		parsed, err := strconv.ParseInt(typed, 10, 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func resetPortableSequences(ctx context.Context, tx *sql.Tx) error {
	for _, table := range portableSequenceTables {
		if _, err := tx.ExecContext(ctx, "DELETE FROM sqlite_sequence WHERE name=?", table); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO sqlite_sequence(name,seq) SELECT ?,COALESCE(MAX(id),0) FROM "+table, table); err != nil {
			return err
		}
	}
	return nil
}

// portableBackupMetadata is intentionally non-secret and useful to future
// callers that need to display format support without parsing implementation
// constants. It is not included in API responses containing a passphrase.
func portableBackupMetadata() map[string]any {
	return map[string]any{
		"format": "friendgate-lite", "version": portableBackupVersion,
		"cipher": "AES-256-GCM", "kdf": "PBKDF2-HMAC-SHA256", "iterations": portableBackupKDFIterations,
	}
}
