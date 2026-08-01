package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultCodexUA      = "codex_cli_rs/0.144.1 (Ubuntu 22.4.0; x86_64) xterm-256color"
	defaultCodexVersion = "0.144.1"
	requestBodyMemory   = 128 << 10
)

var (
	errKeyAccessRevoked     = errors.New("API key access revoked while request was in flight")
	errAccountAccessRevoked = errors.New("ChatGPT account access revoked while request was in flight")
	errIPAccessBanned       = errors.New("source IP banned while request was in flight")
	errBackupRestoreActive  = errors.New("portable backup restore is in progress")
	ErrRequestDrainTimeout  = errors.New("timed out waiting for in-flight requests to exit")
)

const keyRequestDrainTimeout = 15 * time.Second

type proxyState struct {
	status          int
	requestID       string
	errText         string
	retryAfter      time.Duration
	responseCapture *tailCaptureReadCloser
	accessRevoked   bool
}

type keyRequestContextKey struct{}

type keyRequestRegistration struct {
	keyID     int64
	requestID uint64
}

func (s *Server) proxyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/health" {
			writeJSON(w, 200, map[string]string{"status": "ok"})
			return
		}
		s.serveProxy(w, r)
	})
}

func (s *Server) serveProxy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ip := s.realIP(r)
	suffix, ok := codexSuffix(r.URL.Path)
	if !ok || r.Method == http.MethodConnect || r.Method == http.MethodTrace || r.Method == http.MethodOptions {
		recordBan, recordErr := s.store.RecordUnauthorized(r.Context(), ip, "invalid_path", r.URL.Path, "unsupported Codex gateway path", s.cfg.BanThreshold, s.cfg.BanWindow, s.cfg.BanDuration)
		if recordErr != nil {
			s.setSecurityRuntimeFailure("unauthorized_ban", recordErr)
		} else {
			s.setSecurityRuntimeFailure("unauthorized_ban", nil)
		}
		if recordBan {
			s.activatePublicBan(r.Context(), ip, s.cfg.BanDuration)
			writeError(w, 403, "ip_banned", "异常访问次数过多，该 IP 已被封禁")
			return
		}
		writeError(w, 404, "not_found", "接口不存在")
		return
	}
	plainKey := extractAPIKey(r)
	deviceToken := extractDeviceToken(r)
	if plainKey == "" {
		s.rejectUnauthorized(w, r, ip, "missing_key", "missing API key", http.StatusUnauthorized)
		return
	}
	key, keyErr := s.store.AuthorizeKeyWithDevice(r.Context(), plainKey, ip, deviceToken)
	if keyErr != nil {
		if errors.Is(keyErr, ErrIPNotAllowed) {
			s.rejectUnauthorized(w, r, ip, "ip_not_allowed", "key exists but source IP is not authorized", http.StatusForbidden)
		} else if errors.Is(keyErr, ErrDeviceNotAllowed) {
			s.rejectUnauthorized(w, r, ip, "device_not_allowed", "key requires a registered device credential", http.StatusForbidden)
		} else {
			s.rejectUnauthorized(w, r, ip, "invalid_key", "unknown or disabled API key", http.StatusUnauthorized)
		}
		return
	}
	if r.ContentLength > s.cfg.MaxBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "请求内容超过网关限制")
		return
	}
	// Join the key/IP lifecycle before reading a potentially large body or using
	// any ChatGPT credential. The final admission below is the only place that
	// consumes request quota.
	r, preflightFinish, preflightErr := s.beginKeyMetadataRequestWithDevice(r, key.ID, ip, deviceToken)
	if preflightErr != nil {
		s.writeKeyAdmissionError(w, preflightErr)
		return
	}
	defer preflightFinish()
	if isResponsesWebSocket(r, suffix) {
		s.serveResponsesWebSocket(w, r, key, ip, suffix, start)
		return
	}
	if r.Method == http.MethodGet && suffix == "/models" {
		status := s.serveStoredModelManifest(w, r)
		item := UsageLog{IP: ip, Method: r.Method, Path: r.URL.Path, Model: "models", Status: status, DurationMS: time.Since(start).Milliseconds()}
		if err := s.store.LogUsage(context.Background(), key.ID, key.AccountID, item); err != nil {
			slog.Error("model manifest usage log persistence failed", "key_id", key.ID, "account_id", key.AccountID, "error", err)
		}
		return
	}
	// Read the complete bounded body before selecting an account. Large Codex
	// tool/image payloads spill to a private temporary file, so a model placed
	// after the old 128 KiB observation window cannot bypass model routing while
	// the exact original bytes are still replayed to the OAuth upstream.
	replayBody, fields, bodyErr := spoolRequestBody(w, r, s.cfg.MaxBodyBytes)
	if bodyErr != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(bodyErr, &maxBytesError) {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "请求内容超过网关限制")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_body", "读取请求内容失败")
		return
	}
	r.Body = replayBody
	defer replayBody.Close()
	promptCacheKey := truncate(fields["prompt_cache_key"], 256)
	requestedModel := fields["model"]
	if requestedModel == "" {
		requestedModel = strings.TrimSpace(r.URL.Query().Get("model"))
	}
	compactSeed, _ := randomToken(18)
	affinityHash := accountAffinityHash(r, key.ID, suffix, promptCacheKey, compactSeed)
	account, err := s.store.SelectAccountForModel(r.Context(), key.ID, affinityHash, requestedModel, s.cfg.StickyTTL)
	if err != nil {
		if cause := context.Cause(r.Context()); errors.Is(cause, errKeyAccessRevoked) || errors.Is(cause, errAccountAccessRevoked) || errors.Is(cause, errIPAccessBanned) {
			s.writeKeyAdmissionError(w, cause)
			return
		}
		if errors.Is(err, ErrKeyInactive) {
			writeError(w, http.StatusUnauthorized, "key_inactive", "该密钥已被停用或删除")
			return
		}
		if errors.Is(err, ErrModelNotAvailable) {
			writeError(w, http.StatusBadRequest, "model_not_available", "当前账号池不支持请求的模型")
			return
		}
		if errors.Is(err, ErrModelCatalogUnavailable) {
			writeError(w, http.StatusServiceUnavailable, "model_catalog_unavailable", "模型目录尚未完成真实同步")
			return
		}
		writeError(w, 503, "account_pool_unavailable", "ChatGPT 账号池当前没有可用账号")
		return
	}
	account, err = s.refreshAccountIfNeeded(r.Context(), account)
	if err != nil {
		if cause := context.Cause(r.Context()); errors.Is(cause, errKeyAccessRevoked) || errors.Is(cause, errAccountAccessRevoked) || errors.Is(cause, errIPAccessBanned) {
			s.writeKeyAdmissionError(w, cause)
			return
		}
		s.store.MarkAccountCooldown(context.Background(), account.ID, time.Now().Add(s.cfg.AccountCooldown).Unix(), err.Error())
		writeError(w, 502, "token_refresh_failed", "ChatGPT 授权已过期且刷新失败")
		return
	}
	r, finishRequest, err := s.beginKeyRequestWithDevice(r, key.ID, account.ID, ip, deviceToken)
	if err != nil {
		if errors.Is(err, errBackupRestoreActive) {
			writeError(w, http.StatusServiceUnavailable, "restore_in_progress", "系统正在恢复备份，请稍后重试")
			return
		}
		if errors.Is(err, ErrKeyInactive) || errors.Is(err, errKeyAccessRevoked) {
			writeError(w, http.StatusUnauthorized, "key_inactive", "该密钥已被停用或删除")
			return
		}
		if errors.Is(err, ErrIPNotAllowed) {
			writeError(w, http.StatusForbidden, "ip_not_allowed", "当前 IP 授权已被删除")
			return
		}
		if errors.Is(err, errIPAccessBanned) {
			writeError(w, http.StatusForbidden, "ip_banned", "来源 IP 已被安全策略封禁")
			return
		}
		if errors.Is(err, ErrNoAccount) {
			writeError(w, http.StatusServiceUnavailable, "account_pool_unavailable", "ChatGPT 账号已被停用或删除")
			return
		}
		writeError(w, 429, "quota_exceeded", "该密钥的可用额度已用完")
		return
	}
	defer finishRequest()
	s.store.TouchKeyIP(r.Context(), key.ID, ip)
	s.store.TouchKeyDevice(r.Context(), key.ID, deviceToken)
	state := &proxyState{status: 200}
	target, err := url.Parse(s.cfg.UpstreamBaseURL + suffix)
	if err != nil {
		writeError(w, 500, "upstream_invalid", "上游地址配置无效")
		return
	}
	proxy := &httputil.ReverseProxy{
		Transport:     s.client.Transport,
		FlushInterval: -1,
		Director: func(req *http.Request) {
			s.prepareUpstreamRequest(req, target, key, account, suffix, promptCacheKey, compactSeed)
		},
		ModifyResponse: func(resp *http.Response) error {
			state.status = resp.StatusCode
			state.requestID = resp.Header.Get("X-Request-ID")
			state.retryAfter = retryAfterDuration(resp.Header.Get("Retry-After"), s.cfg.AccountCooldown)
			if resp.StatusCode >= http.StatusBadRequest {
				state.errText = fmt.Sprintf("upstream status %d", resp.StatusCode)
			}
			resp.Header.Del("Set-Cookie")
			if resp.StatusCode != http.StatusSwitchingProtocols && resp.Body != nil {
				capture := newTailCaptureReadCloser(resp.Body, 128<<10)
				state.responseCapture = capture
				resp.Body = capture
			}
			return nil
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, proxyErr error) {
			cause := context.Cause(req.Context())
			if errors.Is(cause, errKeyAccessRevoked) {
				state.status = http.StatusUnauthorized
				state.errText = "key access revoked by administrator"
				state.accessRevoked = true
				writeError(rw, http.StatusUnauthorized, "key_inactive", "密钥或 IP 授权已被管理员停用")
				return
			}
			if errors.Is(cause, errAccountAccessRevoked) {
				state.status = http.StatusServiceUnavailable
				state.errText = "ChatGPT account access revoked by administrator"
				state.accessRevoked = true
				writeError(rw, http.StatusServiceUnavailable, "account_unavailable", "ChatGPT 账号已被管理员停用或删除")
				return
			}
			if errors.Is(cause, errIPAccessBanned) {
				state.status = http.StatusForbidden
				state.errText = "source IP banned by administrator or security policy"
				state.accessRevoked = true
				writeError(rw, http.StatusForbidden, "ip_banned", "来源 IP 已被安全策略封禁")
				return
			}
			state.status = http.StatusBadGateway
			state.errText = safeProxyError(proxyErr)
			writeError(rw, http.StatusBadGateway, "upstream_error", "连接 ChatGPT 上游失败")
		},
	}
	func() {
		defer func() {
			recovered := recover()
			if recovered == nil {
				return
			}
			// Once an SSE or another streamed response has sent its headers,
			// ReverseProxy reports a copy interruption with ErrAbortHandler
			// instead of invoking ErrorHandler. An administrator cancellation
			// is expected: retain the partial usage record and never append JSON
			// to the already-started upstream stream.
			cause := context.Cause(r.Context())
			if recovered == http.ErrAbortHandler && (errors.Is(cause, errKeyAccessRevoked) || errors.Is(cause, errAccountAccessRevoked) || errors.Is(cause, errIPAccessBanned)) {
				if errors.Is(cause, errIPAccessBanned) {
					state.errText = "source IP banned by administrator or security policy"
				} else if errors.Is(cause, errAccountAccessRevoked) {
					state.errText = "ChatGPT account access revoked by administrator"
				} else {
					state.errText = "key access revoked by administrator"
				}
				state.accessRevoked = true
				return
			}
			panic(recovered)
		}()
		proxy.ServeHTTP(w, r)
	}()
	// The standard library deliberately suppresses ErrAbortHandler while Go
	// tests are running. Checking the cancellation cause after ServeHTTP also
	// covers that path and any transport that ends the stream with a clean EOF.
	if errors.Is(context.Cause(r.Context()), errKeyAccessRevoked) {
		state.errText = "key access revoked by administrator"
		state.accessRevoked = true
	} else if errors.Is(context.Cause(r.Context()), errAccountAccessRevoked) {
		state.errText = "ChatGPT account access revoked by administrator"
		state.accessRevoked = true
	} else if errors.Is(context.Cause(r.Context()), errIPAccessBanned) {
		state.errText = "source IP banned by administrator or security policy"
		state.accessRevoked = true
	}
	input, output, total := int64(0), int64(0), int64(0)
	if state.responseCapture != nil {
		input, output, total = parseUsage(state.responseCapture.Bytes())
	}
	logItem := UsageLog{IP: ip, Method: r.Method, Path: r.URL.Path, Model: requestedModel, Status: state.status, DurationMS: time.Since(start).Milliseconds(), InputTokens: input, OutputTokens: output, TotalTokens: total, RequestID: state.requestID, Error: state.errText}
	if err := s.store.LogUsage(context.Background(), key.ID, account.ID, logItem); err != nil {
		slog.Error("usage log persistence failed", "key_id", key.ID, "account_id", account.ID, "request_id", state.requestID, "error", err)
	}
	if state.accessRevoked {
		return
	}
	accountError := ""
	if state.status == http.StatusTooManyRequests {
		accountError = fmt.Sprintf("upstream status %d", state.status)
		s.store.MarkAccountCooldown(context.Background(), account.ID, time.Now().Add(state.retryAfter).Unix(), accountError)
		return
	}
	if state.status == 401 || state.status == 403 || state.status >= 500 {
		accountError = fmt.Sprintf("upstream status %d", state.status)
	}
	s.store.MarkAccountResult(context.Background(), account.ID, accountError)
}

func (s *Server) writeKeyAdmissionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrKeyInactive), errors.Is(err, errKeyAccessRevoked):
		writeError(w, http.StatusUnauthorized, "key_inactive", "该密钥已被停用或删除")
	case errors.Is(err, errAccountAccessRevoked):
		writeError(w, http.StatusServiceUnavailable, "account_unavailable", "ChatGPT 账号已被管理员停用或删除")
	case errors.Is(err, ErrIPNotAllowed):
		writeError(w, http.StatusForbidden, "ip_not_allowed", "当前 IP 授权已被删除")
	case errors.Is(err, ErrDeviceNotAllowed):
		writeError(w, http.StatusForbidden, "device_not_allowed", "设备凭证缺失、无效或已被撤销")
	case errors.Is(err, errIPAccessBanned):
		writeError(w, http.StatusForbidden, "ip_banned", "来源 IP 已被安全策略封禁")
	case errors.Is(err, errBackupRestoreActive):
		writeError(w, http.StatusServiceUnavailable, "restore_in_progress", "数据恢复进行中，网关暂停接收请求")
	default:
		writeError(w, http.StatusInternalServerError, "key_authorization_failed", "密钥授权检查失败")
	}
}

// beginKeyRequest and the administrative key mutations share keyRequestMu.
// This creates a strict boundary: once a disable/delete/IP-removal response is
// returned, no request admitted under the old state can still reach upstream.
func (s *Server) beginKeyRequest(r *http.Request, keyID, accountID int64, ip string) (*http.Request, func(), error) {
	return s.beginKeyRequestWithDevice(r, keyID, accountID, ip, "")
}

func (s *Server) beginKeyRequestWithDevice(r *http.Request, keyID, accountID int64, ip, deviceToken string) (*http.Request, func(), error) {
	s.keyRequestMu.Lock()
	defer s.keyRequestMu.Unlock()
	if s.restoreInProgress {
		return r, func() {}, errBackupRestoreActive
	}
	if cause := context.Cause(r.Context()); cause != nil {
		return r, func() {}, cause
	}
	if s.isBannedCached(ip, "api") {
		return r, func() {}, errIPAccessBanned
	}
	if err := s.store.RequireActiveAccount(r.Context(), accountID); err != nil {
		return r, func() {}, err
	}
	if err := s.store.RequireAuthorizedKeyWithDevice(r.Context(), keyID, ip, deviceToken); err != nil {
		return r, func() {}, err
	}
	if err := s.store.ConsumeQuotaAuthorizedWithDevice(r.Context(), keyID, ip, deviceToken); err != nil {
		return r, func() {}, err
	}
	// A normal proxy request first joins the key/IP lifecycle without consuming
	// quota, before it reads the body or refreshes OAuth credentials. Promote that
	// same registration here instead of counting one logical request twice.
	if registration, ok := r.Context().Value(keyRequestContextKey{}).(keyRequestRegistration); ok && registration.keyID == keyID {
		if requests := s.keyRequests[keyID]; requests != nil {
			if active, exists := requests[registration.requestID]; exists {
				active.accountID = accountID
				requests[registration.requestID] = active
				return r, func() {}, nil
			}
		}
		return r, func() {}, ErrKeyInactive
	}
	return s.registerKeyRequestLocked(r, keyID, accountID, ip)
}

func (s *Server) beginKeyMetadataRequest(r *http.Request, keyID int64, ip string) (*http.Request, func(), error) {
	return s.beginKeyMetadataRequestWithDevice(r, keyID, ip, "")
}

func (s *Server) beginKeyMetadataRequestWithDevice(r *http.Request, keyID int64, ip, deviceToken string) (*http.Request, func(), error) {
	s.keyRequestMu.Lock()
	defer s.keyRequestMu.Unlock()
	if s.restoreInProgress {
		return r, func() {}, errBackupRestoreActive
	}
	if s.isBannedCached(ip, "api") {
		return r, func() {}, errIPAccessBanned
	}
	if err := s.store.RequireAuthorizedKeyWithDevice(r.Context(), keyID, ip, deviceToken); err != nil {
		return r, func() {}, err
	}
	return s.registerKeyRequestLocked(r, keyID, 0, ip)
}

// registerKeyRequestLocked records a request after its final authorization
// check. The caller must hold keyRequestMu.
func (s *Server) registerKeyRequestLocked(r *http.Request, keyID, accountID int64, ip string) (*http.Request, func(), error) {
	ctx, cancel := context.WithCancelCause(r.Context())
	done := make(chan struct{})
	s.keyRequestID++
	requestID := s.keyRequestID
	if s.keyRequests[keyID] == nil {
		s.keyRequests[keyID] = make(map[uint64]activeKeyRequest)
	}
	s.keyRequests[keyID][requestID] = activeKeyRequest{accountID: accountID, ip: ip, cancel: cancel, done: done}
	ctx = context.WithValue(ctx, keyRequestContextKey{}, keyRequestRegistration{keyID: keyID, requestID: requestID})
	var once sync.Once
	finish := func() {
		once.Do(func() {
			cancel(nil)
			s.keyRequestMu.Lock()
			delete(s.keyRequests[keyID], requestID)
			if len(s.keyRequests[keyID]) == 0 {
				delete(s.keyRequests, keyID)
			}
			s.keyRequestMu.Unlock()
			close(done)
		})
	}
	return r.WithContext(ctx), finish, nil
}

func (s *Server) cancelKeyRequestsLocked(keyID int64) []<-chan struct{} {
	requests := s.keyRequests[keyID]
	delete(s.keyRequests, keyID)
	done := make([]<-chan struct{}, 0, len(requests))
	for _, request := range requests {
		request.cancel(errKeyAccessRevoked)
		done = append(done, request.done)
	}
	return done
}

func waitKeyRequests(ctx context.Context, requests []<-chan struct{}) error {
	drainCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), keyRequestDrainTimeout)
	defer cancel()
	for _, done := range requests {
		select {
		case <-done:
		case <-drainCtx.Done():
			return fmt.Errorf("%w: %d request(s): %v", ErrRequestDrainTimeout, len(requests), drainCtx.Err())
		}
	}
	return nil
}

func (s *Server) cancelIPRequests(ips []string, wait bool) (int, error) {
	targets := make(map[string]bool, len(ips))
	for _, ip := range ips {
		targets[ip] = true
	}
	s.keyRequestMu.Lock()
	var pending []<-chan struct{}
	for keyID, requests := range s.keyRequests {
		for requestID, request := range requests {
			if !targets[request.ip] {
				continue
			}
			request.cancel(errIPAccessBanned)
			pending = append(pending, request.done)
			delete(requests, requestID)
		}
		if len(requests) == 0 {
			delete(s.keyRequests, keyID)
		}
	}
	s.keyRequestMu.Unlock()
	if wait {
		if err := waitKeyRequests(context.Background(), pending); err != nil {
			return len(pending), err
		}
	}
	return len(pending), nil
}

func (s *Server) cancelBannedIPRequests(ip string, wait bool) (int, error) {
	members, err := s.store.BanMembers(context.Background(), ip)
	if err != nil {
		s.setSecurityRuntimeFailure("ban_request_cancel", err)
		return 0, err
	}
	cancelled, err := s.cancelIPRequests(members, wait)
	s.setSecurityRuntimeFailure("ban_request_cancel", err)
	return cancelled, err
}

func (s *Server) revokeInvitation(ctx context.Context, id int64) error {
	s.keyRequestMu.Lock()
	defer s.keyRequestMu.Unlock()
	return s.store.RevokeInvitation(ctx, id)
}

func (s *Server) deleteInvitation(ctx context.Context, id int64) error {
	s.keyRequestMu.Lock()
	defer s.keyRequestMu.Unlock()
	return s.store.DeleteInvitation(ctx, id)
}

func (s *Server) updateAPIKeyState(ctx context.Context, id int64, status string, quota int64) (int, error) {
	s.keyRequestMu.Lock()
	if err := s.store.UpdateAPIKey(ctx, id, status, quota); err != nil {
		s.keyRequestMu.Unlock()
		return 0, err
	}
	var requests []<-chan struct{}
	if status != "active" {
		requests = s.cancelKeyRequestsLocked(id)
	}
	s.keyRequestMu.Unlock()
	if err := waitKeyRequests(ctx, requests); err != nil {
		return len(requests), err
	}
	return len(requests), nil
}

func (s *Server) deleteAPIKey(ctx context.Context, id int64) (int, error) {
	s.keyRequestMu.Lock()
	if err := s.store.DeleteAPIKey(ctx, id); err != nil {
		s.keyRequestMu.Unlock()
		return 0, err
	}
	requests := s.cancelKeyRequestsLocked(id)
	s.keyRequestMu.Unlock()
	if err := waitKeyRequests(ctx, requests); err != nil {
		return len(requests), err
	}
	return len(requests), nil
}

func (s *Server) deleteKeyIP(ctx context.Context, keyID, ipID int64) (int, error) {
	s.keyRequestMu.Lock()
	if err := s.store.DeleteKeyIP(ctx, keyID, ipID); err != nil {
		s.keyRequestMu.Unlock()
		return 0, err
	}
	// Cancel all requests for the key. This is deliberately conservative: the
	// administrator's ACL change cannot leave an untracked stream alive.
	requests := s.cancelKeyRequestsLocked(keyID)
	s.keyRequestMu.Unlock()
	if err := waitKeyRequests(ctx, requests); err != nil {
		return len(requests), err
	}
	return len(requests), nil
}

func accountAffinityHash(r *http.Request, keyID int64, suffix, promptCacheKey, compactSeed string) string {
	if suffix == "/models" || suffix == "/alpha/search" {
		return ""
	}
	seed := ""
	for _, name := range []string{"Session_ID", "Conversation_ID", "X-Session-Affinity", "X-Session-ID", "X-OpenCode-Session", "X-Conversation-ID"} {
		if value := strings.TrimSpace(r.Header.Get(name)); value != "" {
			seed = value
			break
		}
	}
	if seed == "" {
		seed = strings.TrimSpace(promptCacheKey)
	}
	if seed == "" && strings.HasPrefix(suffix, "/responses/compact") {
		seed = compactSeed
	}
	if seed == "" {
		seed = strings.TrimSpace(r.Header.Get("X-Codex-Installation-ID"))
	}
	if seed == "" {
		// Safe fallback for unusual clients without any conversation signal. This
		// favors continuity over quota spreading instead of randomly switching.
		seed = "key-default"
	}
	return tokenHash("key:" + strconv.FormatInt(keyID, 10) + "\x00" + seed)
}

func retryAfterDuration(value string, fallback time.Duration) time.Duration {
	value = strings.TrimSpace(value)
	if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
		d := time.Duration(seconds) * time.Second
		if d > 24*time.Hour {
			return 24 * time.Hour
		}
		return d
	}
	if when, err := http.ParseTime(value); err == nil && when.After(time.Now()) {
		d := time.Until(when)
		if d > 24*time.Hour {
			return 24 * time.Hour
		}
		return d
	}
	return fallback
}

func (s *Server) rejectUnauthorized(w http.ResponseWriter, r *http.Request, ip, kind, detail string, status int) {
	banned, recordErr := s.store.RecordUnauthorized(r.Context(), ip, kind, r.URL.Path, detail, s.cfg.BanThreshold, s.cfg.BanWindow, s.cfg.BanDuration)
	if recordErr != nil {
		s.setSecurityRuntimeFailure("unauthorized_ban", recordErr)
	} else {
		s.setSecurityRuntimeFailure("unauthorized_ban", nil)
	}
	if banned {
		s.activatePublicBan(r.Context(), ip, s.cfg.BanDuration)
		writeError(w, 403, "ip_banned", "未授权访问次数过多，该 IP 已被封禁")
		return
	}
	code := "unauthorized"
	message := "API Key 无效"
	if status == http.StatusForbidden {
		code = "ip_not_allowed"
		message = "当前 IP 未获得此密钥授权"
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="friendgate"`)
	writeError(w, status, code, message)
}

func codexSuffix(requestPath string) (string, bool) {
	if strings.Contains(requestPath, "\\") || strings.Contains(requestPath, "..") || strings.ContainsRune(requestPath, '\x00') {
		return "", false
	}
	var suffix string
	switch {
	case requestPath == "/v1":
		return "", false
	case strings.HasPrefix(requestPath, "/v1/"):
		suffix = strings.TrimPrefix(requestPath, "/v1")
	case requestPath == "/responses" || strings.HasPrefix(requestPath, "/responses/"):
		suffix = requestPath
	case requestPath == "/models":
		suffix = requestPath
	case requestPath == "/alpha/search":
		suffix = requestPath
	case requestPath == "/backend-api/codex":
		suffix = "/"
	case strings.HasPrefix(requestPath, "/backend-api/codex/"):
		suffix = strings.TrimPrefix(requestPath, "/backend-api/codex")
	default:
		return "", false
	}
	if suffix == "" || suffix[0] != '/' {
		return "", false
	}
	return suffix, true
}

func extractAPIKey(r *http.Request) string {
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(authorization), "bearer ") {
		return strings.TrimSpace(authorization[7:])
	}
	return strings.TrimSpace(r.Header.Get("X-API-Key"))
}

// Device credentials are opaque bearer values provisioned by an invitation or
// a trusted device agent. They are never forwarded to ChatGPT and are stored
// only as hashes. A raw X-FriendGate-Device-MAC header is intentionally not
// accepted: MAC addresses are not visible across public routing and are easy
// to forge at the HTTP layer.
func extractDeviceToken(r *http.Request) string {
	value := strings.TrimSpace(r.Header.Get("X-FriendGate-Device-Token"))
	if len(value) < 20 || len(value) > 512 {
		return ""
	}
	return value
}

var allowedProxyHeaders = map[string]bool{
	"accept": true, "accept-language": true, "content-type": true,
	"user-agent": true, "originator": true, "openai-beta": true,
	"conversation_id": true, "session_id": true, "x-codex-beta-features": true,
	"x-codex-installation-id": true, "x-codex-turn-state": true, "x-codex-turn-metadata": true,
	"x-codex-window-id":                      true,
	"x-openai-internal-codex-responses-lite": true,
	"sec-websocket-key":                      true, "sec-websocket-version": true, "sec-websocket-extensions": true,
	"sec-websocket-protocol": true, "upgrade": true, "connection": true, "if-none-match": true,
}

func (s *Server) prepareUpstreamRequest(req *http.Request, target *url.URL, key *APIKey, account *Account, suffix, promptCacheKey, compactSeed string) {
	original := req.Header.Clone()
	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host
	req.URL.Path = target.Path
	req.URL.RawPath = ""
	req.Host = target.Host
	req.Header = make(http.Header)
	for name, values := range original {
		if allowedProxyHeaders[strings.ToLower(name)] {
			for _, value := range values {
				req.Header.Add(name, value)
			}
		}
	}
	req.Header.Set("Authorization", "Bearer "+account.AccessToken)
	req.Header.Del("X-API-Key")
	req.Header.Del("Cookie")
	req.Header.Del("Forwarded")
	req.Header["X-Forwarded-For"] = nil
	req.Header.Set("ChatGPT-Account-ID", account.ChatGPTAccountID)
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", defaultCodexUA)
	}
	if req.Header.Get("Originator") == "" {
		req.Header.Set("Originator", "codex_cli_rs")
	}
	version := defaultCodexVersion
	if suffix == "/models" {
		if candidate := strings.TrimSpace(req.URL.Query().Get("client_version")); codexVersionAtLeast(candidate, "0.144.0") {
			version = candidate
		}
	}
	req.Header.Set("Version", version)
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	isResponses := suffix == "/responses" || strings.HasPrefix(suffix, "/responses/")
	if suffix == "/models" || suffix == "/alpha/search" {
		req.Header.Set("Accept", "application/json")
		req.Header.Del("OpenAI-Beta")
		req.Header.Del("Session_ID")
		req.Header.Del("Conversation_ID")
		if suffix == "/alpha/search" {
			req.Header.Del("X-Codex-Beta-Features")
			req.Header.Del("X-Codex-Turn-State")
		}
		enforceCodexIdentity(req.Header, version)
		return
	}
	if isResponses {
		// Match the current official Codex OAuth wire identity. A
		// downstream client cannot replace this with an unrelated beta surface.
		req.Header.Set("OpenAI-Beta", "responses=experimental")
	}
	if isResponses && strings.HasPrefix(suffix, "/responses/compact") {
		req.Header.Set("Accept", "application/json")
	} else if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/event-stream")
	}
	if !isResponses {
		enforceCodexIdentity(req.Header, version)
		return
	}
	clientSession := strings.TrimSpace(req.Header.Get("Session_ID"))
	clientConversation := strings.TrimSpace(req.Header.Get("Conversation_ID"))
	if strings.HasPrefix(suffix, "/responses/compact") && clientSession == "" {
		clientSession = clientConversation
		if clientSession == "" {
			clientSession = promptCacheKey
		}
		if clientSession == "" {
			clientSession = compactSeed
		}
	}
	if clientSession == "" {
		clientSession = promptCacheKey
	}
	if clientConversation == "" {
		clientConversation = promptCacheKey
	}
	// A current Codex client normally supplies session_id or prompt_cache_key.
	// The installation id is a safe deterministic fallback for future client
	// variants; the API-key namespace still makes two users' values distinct.
	fallback := strings.TrimSpace(req.Header.Get("X-Codex-Installation-ID"))
	if fallback == "" {
		fallback = "key-" + strconv.FormatInt(key.ID, 10)
	}
	if clientSession == "" {
		clientSession = fallback
	}
	if clientConversation == "" {
		clientConversation = fallback
	}
	if clientSession != "" {
		req.Header.Set("Session_ID", s.vault.Namespace("key", strconv.FormatInt(key.ID, 10), "session_id", clientSession))
	} else {
		req.Header.Del("Session_ID")
	}
	if clientConversation != "" {
		req.Header.Set("Conversation_ID", s.vault.Namespace("key", strconv.FormatInt(key.ID, 10), "conversation_id", clientConversation))
	} else {
		req.Header.Del("Conversation_ID")
	}
	enforceCodexIdentity(req.Header, version)
}

func (s *Server) refreshAccountIfNeeded(ctx context.Context, account *Account) (*Account, error) {
	lock := s.accountLifecycleMutex(account.ID)
	lock.Lock()
	defer lock.Unlock()
	return s.refreshAccountIfNeededLocked(ctx, account)
}

// refreshAccountIfNeededLocked always reloads the live row before returning a
// credential, even when the token does not need refreshing. The caller must
// hold the account lifecycle mutex for account.ID.
func (s *Server) refreshAccountIfNeededLocked(ctx context.Context, account *Account) (*Account, error) {
	fresh, err := s.store.GetAccount(ctx, account.ID)
	if err != nil {
		return nil, err
	}
	if !fresh.Active || strings.TrimSpace(fresh.AccessToken) == "" {
		return nil, ErrNoAccount
	}
	if fresh.ExpiresAt == 0 || fresh.ExpiresAt > time.Now().Add(5*time.Minute).Unix() {
		return fresh, nil
	}
	if fresh.RefreshToken == "" {
		if fresh.ExpiresAt > time.Now().Unix() {
			return fresh, nil
		}
		return nil, errors.New("refresh token missing")
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {fresh.RefreshToken}, "client_id": {fresh.ClientID}, "scope": {"openid profile email"}}
	refreshCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(refreshCtx, http.MethodPost, "https://auth.openai.com/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("User-Agent", "codex-cli/0.144.1")
	response, err := s.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("refresh request: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("refresh rejected with status %d", response.StatusCode)
	}
	var tokenResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if json.Unmarshal(body, &tokenResponse) != nil || tokenResponse.AccessToken == "" {
		return nil, errors.New("invalid token refresh response")
	}
	newAccountID, expiresAt := jwtAccountAndExpiry(tokenResponse.IDToken)
	if newAccountID == "" {
		newAccountID, expiresAt = jwtAccountAndExpiry(tokenResponse.AccessToken)
	}
	if newAccountID == "" {
		newAccountID = fresh.ChatGPTAccountID
	}
	if newAccountID != fresh.ChatGPTAccountID {
		return nil, errors.New("refreshed token belongs to a different ChatGPT account")
	}
	if expiresAt == 0 {
		expiresAt = time.Now().Unix() + tokenResponse.ExpiresIn
	}
	if tokenResponse.RefreshToken == "" {
		tokenResponse.RefreshToken = fresh.RefreshToken
	}
	if err := s.store.UpdateAccountTokens(ctx, fresh.ID, tokenResponse.AccessToken, tokenResponse.RefreshToken, expiresAt, newAccountID); err != nil {
		return nil, err
	}
	return s.store.GetAccount(ctx, fresh.ID)
}

func safeProxyError(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	for _, needle := range []string{"Bearer ", "sk-fg_"} {
		if index := strings.Index(message, needle); index >= 0 {
			message = message[:index] + "[redacted]"
		}
	}
	return truncate(message, 500)
}

type temporaryRequestBody struct {
	*os.File
	path      string
	closeOnce sync.Once
	closeErr  error
}

func (body *temporaryRequestBody) Close() error {
	body.closeOnce.Do(func() {
		body.closeErr = body.File.Close()
		var removeErr error
		if body.path != "" {
			removeErr = os.Remove(body.path)
		}
		if body.closeErr == nil && removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			body.closeErr = removeErr
		}
	})
	return body.closeErr
}

// spoolRequestBody retains small requests in memory and spills larger ones to
// a mode-0600 temporary file. It scans the entire raw JSON stream for the two
// routing fields without decoding or re-encoding any request content.
func spoolRequestBody(w http.ResponseWriter, r *http.Request, limit int64) (io.ReadCloser, map[string]string, error) {
	if r.Body == nil {
		return io.NopCloser(bytes.NewReader(nil)), map[string]string{}, nil
	}
	limited := http.MaxBytesReader(w, r.Body, limit)
	scanner := newTopLevelJSONStringScanner("model", "prompt_cache_key")
	var memory bytes.Buffer
	var temporary *temporaryRequestBody
	cleanup := func() {
		_ = limited.Close()
		if temporary != nil {
			_ = temporary.Close()
		}
	}
	writeChunk := func(chunk []byte) error {
		if temporary == nil && memory.Len()+len(chunk) <= requestBodyMemory {
			_, err := memory.Write(chunk)
			return err
		}
		if temporary == nil {
			file, err := os.CreateTemp("", "friendgate-request-*.body")
			if err != nil {
				return err
			}
			temporary = &temporaryRequestBody{File: file, path: file.Name()}
			// The target runtime is Linux: unlink the mode-0600 file while its
			// descriptor is open so a crash cannot leave plaintext request data.
			if err = os.Remove(temporary.path); err == nil {
				temporary.path = ""
			}
			if _, err = temporary.Write(memory.Bytes()); err != nil {
				return err
			}
			memory.Reset()
		}
		_, err := temporary.Write(chunk)
		return err
	}
	buffer := make([]byte, 32<<10)
	for {
		n, readErr := limited.Read(buffer)
		if n > 0 {
			scanner.Write(buffer[:n])
			if err := writeChunk(buffer[:n]); err != nil {
				cleanup()
				return nil, nil, err
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			cleanup()
			return nil, nil, readErr
		}
	}
	_ = limited.Close()
	if temporary == nil {
		return io.NopCloser(bytes.NewReader(memory.Bytes())), scanner.Fields(), nil
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		_ = temporary.Close()
		return nil, nil, err
	}
	return temporary, scanner.Fields(), nil
}

const maxScannedJSONStringBytes = 8 << 10

type topLevelJSONStringScanner struct {
	wanted          map[string]bool
	fields          map[string]string
	depth           int
	inString        bool
	escaped         bool
	expectKey       bool
	expectColon     bool
	expectValue     bool
	key             string
	captureKind     byte
	capture         []byte
	captureOverflow bool
}

func newTopLevelJSONStringScanner(fields ...string) *topLevelJSONStringScanner {
	wanted := make(map[string]bool, len(fields))
	for _, field := range fields {
		wanted[field] = true
	}
	return &topLevelJSONStringScanner{wanted: wanted, fields: make(map[string]string, len(fields))}
}

func (scanner *topLevelJSONStringScanner) Write(body []byte) {
	for _, character := range body {
		if scanner.inString {
			if scanner.escaped {
				scanner.captureByte(character)
				scanner.escaped = false
				continue
			}
			if character == '\\' {
				scanner.captureByte(character)
				scanner.escaped = true
				continue
			}
			if character == '"' {
				scanner.finishString()
				continue
			}
			scanner.captureByte(character)
			continue
		}

		switch character {
		case '"':
			scanner.inString = true
			scanner.capture = scanner.capture[:0]
			scanner.captureOverflow = false
			scanner.captureKind = 0
			if scanner.depth == 1 && scanner.expectKey {
				scanner.captureKind = 'k'
			} else if scanner.depth == 1 && scanner.expectValue && scanner.wanted[scanner.key] {
				scanner.captureKind = 'v'
			}
		case '{':
			scanner.depth++
			if scanner.depth == 1 {
				scanner.expectKey = true
			} else if scanner.depth == 2 && scanner.expectValue {
				scanner.expectValue = false
			}
		case '[':
			scanner.depth++
			if scanner.depth == 2 && scanner.expectValue {
				scanner.expectValue = false
			}
		case '}', ']':
			if scanner.depth > 0 {
				scanner.depth--
			}
		case ':':
			if scanner.depth == 1 && scanner.expectColon {
				scanner.expectColon = false
				scanner.expectValue = true
			}
		case ',':
			if scanner.depth == 1 {
				scanner.key = ""
				scanner.expectKey = true
				scanner.expectColon = false
				scanner.expectValue = false
			}
		case ' ', '\t', '\r', '\n':
		default:
			if scanner.depth == 1 && scanner.expectValue {
				scanner.expectValue = false
			}
		}
	}
}

func (scanner *topLevelJSONStringScanner) captureByte(character byte) {
	if scanner.captureKind == 0 || scanner.captureOverflow {
		return
	}
	if len(scanner.capture) >= maxScannedJSONStringBytes {
		scanner.captureOverflow = true
		return
	}
	scanner.capture = append(scanner.capture, character)
}

func (scanner *topLevelJSONStringScanner) finishString() {
	scanner.inString = false
	if scanner.captureKind == 0 {
		return
	}
	decoded := ""
	if !scanner.captureOverflow {
		quoted := make([]byte, 0, len(scanner.capture)+2)
		quoted = append(quoted, '"')
		quoted = append(quoted, scanner.capture...)
		quoted = append(quoted, '"')
		_ = json.Unmarshal(quoted, &decoded)
	}
	if scanner.captureKind == 'k' {
		scanner.key = decoded
		scanner.expectKey = false
		scanner.expectColon = decoded != ""
	} else {
		if scanner.captureOverflow {
			decoded = strings.Repeat("x", maxModelIDBytes+1)
		}
		scanner.fields[scanner.key] = decoded
		scanner.expectValue = false
	}
	scanner.captureKind = 0
}

func (scanner *topLevelJSONStringScanner) Fields() map[string]string {
	result := make(map[string]string, len(scanner.fields))
	for key, value := range scanner.fields {
		result[key] = value
	}
	return result
}

type tailCaptureReadCloser struct {
	source io.ReadCloser
	buffer []byte
	limit  int
}

func newTailCaptureReadCloser(source io.ReadCloser, limit int) *tailCaptureReadCloser {
	return &tailCaptureReadCloser{source: source, limit: limit}
}
func (c *tailCaptureReadCloser) Read(p []byte) (int, error) {
	n, err := c.source.Read(p)
	if n > 0 {
		c.buffer = append(c.buffer, p[:n]...)
		if len(c.buffer) > c.limit {
			copy(c.buffer, c.buffer[len(c.buffer)-c.limit:])
			c.buffer = c.buffer[:c.limit]
		}
	}
	return n, err
}
func (c *tailCaptureReadCloser) Close() error  { return c.source.Close() }
func (c *tailCaptureReadCloser) Bytes() []byte { return c.buffer }

// topLevelJSONString extracts a top-level string from the retained request
// prefix. It is intentionally a small JSON scanner instead of an unmarshal so
// extraction still succeeds when a very large tool input continues beyond the
// 128 KiB observation window.
func topLevelJSONString(body []byte, want string) string {
	depth := 0
	inString := false
	escaped := false
	start := -1
	var lastTopString string
	for i, b := range body {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if b == '\\' {
				escaped = true
				continue
			}
			if b == '"' {
				raw := body[start:i]
				quoted := make([]byte, 0, len(raw)+2)
				quoted = append(quoted, '"')
				quoted = append(quoted, raw...)
				quoted = append(quoted, '"')
				var decoded string
				if json.Unmarshal(quoted, &decoded) == nil && depth == 1 {
					lastTopString = decoded
				}
				inString = false
			}
			continue
		}
		switch b {
		case '"':
			inString = true
			start = i + 1
		case '{', '[':
			depth++
		case '}', ']':
			depth--
		case ':':
			if depth == 1 && lastTopString == want {
				j := i + 1
				for j < len(body) && (body[j] == ' ' || body[j] == '\t' || body[j] == '\r' || body[j] == '\n') {
					j++
				}
				if j < len(body) && body[j] == '"' {
					end := j + 1
					escape := false
					for end < len(body) {
						if escape {
							escape = false
						} else if body[end] == '\\' {
							escape = true
						} else if body[end] == '"' {
							var value string
							if json.Unmarshal(body[j:end+1], &value) == nil {
								return truncate(value, 256)
							}
							break
						}
						end++
					}
				}
			}
			lastTopString = ""
		case ',':
			if depth == 1 {
				lastTopString = ""
			}
		}
	}
	return ""
}

var officialCodexOriginators = map[string]bool{"codex_cli_rs": true, "codex-tui": true, "codex_vscode": true, "codex_vscode_copilot": true, "codex_app": true, "codex_chatgpt_desktop": true, "codex_atlas": true, "codex_exec": true, "codex_sdk_ts": true}

func enforceCodexIdentity(header http.Header, version string) {
	ua := strings.TrimSpace(header.Get("User-Agent"))
	origin, paired, ok := pairCodexIdentity(ua)
	if !ok {
		origin = "codex_cli_rs"
		paired = defaultCodexUA
	}
	header.Set("User-Agent", paired)
	header.Set("Originator", origin)
	if !codexVersionAtLeast(version, "0.144.0") {
		version = defaultCodexVersion
	}
	header.Set("Version", version)
}

func codexVersionAtLeast(got, minimum string) bool {
	parse := func(value string) ([3]int, bool) {
		var result [3]int
		parts := strings.SplitN(strings.TrimSpace(value), ".", 4)
		if len(parts) < 3 {
			return result, false
		}
		for i := 0; i < 3; i++ {
			digits := parts[i]
			if i == 2 {
				if cut := strings.IndexAny(digits, "-+"); cut >= 0 {
					digits = digits[:cut]
				}
			}
			value, err := strconv.Atoi(digits)
			if err != nil || value < 0 {
				return result, false
			}
			result[i] = value
		}
		return result, true
	}
	a, okA := parse(got)
	b, okB := parse(minimum)
	if !okA || !okB {
		return false
	}
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return true
}
func pairCodexIdentity(ua string) (string, string, bool) {
	slash := strings.IndexByte(ua, '/')
	if slash <= 0 {
		return "", "", false
	}
	leading := strings.TrimSpace(ua[:slash])
	if isOfficialOriginator(leading) {
		return canonicalOriginator(leading), canonicalOriginator(leading) + ua[slash:], true
	}
	last := strings.LastIndex(ua, "(")
	if last >= 0 {
		rest := ua[last+1:]
		if close := strings.Index(rest, ")"); close >= 0 {
			candidate := strings.TrimSpace(rest[:close])
			if semi := strings.Index(candidate, ";"); semi >= 0 {
				candidate = strings.TrimSpace(candidate[:semi])
			}
			if !strings.Contains(candidate, "/") && isOfficialOriginator(candidate) {
				candidate = canonicalOriginator(candidate)
				return candidate, candidate + ua[slash:], true
			}
		}
	}
	return "", "", false
}
func isOfficialOriginator(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	return officialCodexOriginators[normalized] || strings.HasPrefix(normalized, "codex ")
}
func canonicalOriginator(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if officialCodexOriginators[normalized] {
		return normalized
	}
	return strings.TrimSpace(value)
}
func parseUsage(body []byte) (int64, int64, int64) {
	var best map[string]any
	consume := func(raw []byte) {
		var value any
		if json.Unmarshal(raw, &value) == nil {
			findUsageMap(value, &best)
		}
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		consume(trimmed)
	} else {
		for _, line := range bytes.Split(body, []byte("\n")) {
			line = bytes.TrimSpace(line)
			if bytes.HasPrefix(line, []byte("data:")) {
				raw := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
				if !bytes.Equal(raw, []byte("[DONE]")) {
					consume(raw)
				}
			}
		}
	}
	if best == nil {
		return 0, 0, 0
	}
	input := numberField(best, "input_tokens")
	output := numberField(best, "output_tokens")
	total := numberField(best, "total_tokens")
	if total == 0 {
		total = input + output
	}
	return input, output, total
}
func findUsageMap(value any, best *map[string]any) {
	switch item := value.(type) {
	case map[string]any:
		if usage, ok := item["usage"].(map[string]any); ok {
			*best = usage
		}
		for _, child := range item {
			findUsageMap(child, best)
		}
	case []any:
		for _, child := range item {
			findUsageMap(child, best)
		}
	}
}
func numberField(value map[string]any, key string) int64 {
	switch number := value[key].(type) {
	case float64:
		return int64(number)
	case json.Number:
		result, _ := number.Int64()
		return result
	}
	return 0
}
