package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"hash"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// platformDesktopSessionRequest is the PostgreSQL replacement for the legacy
// SQLite desktop bridge. The public protocol stays compatible with the Linux
// application, but all session, device, user and quota authority is now in
// PostgreSQL.
func (s *Server) platformDesktopSessionRequest(r *http.Request) (*PlatformDeviceSessionAuth, error) {
	platform := s.store.Platform()
	if platform == nil {
		return nil, ErrPlatformDatabaseUnavailable
	}
	token := desktopBearer(r, "fgds_")
	if token == "" {
		return nil, ErrPlatformDeviceSession
	}
	auth, err := platform.PlatformDeviceSessionByAccess(r.Context(), token)
	if err != nil {
		return nil, err
	}
	if err := s.verifyPlatformDesktopRequest(r, platform, auth); err != nil {
		return nil, err
	}
	platform.TouchPlatformDeviceSession(r.Context(), auth.SessionID, s.realIP(r))
	return auth, nil
}

func (s *Server) verifyPlatformDesktopRequest(r *http.Request, platform *PlatformStore, auth *PlatformDeviceSessionAuth) error {
	if platform == nil || auth == nil || len(auth.PublicKey) != ed25519.PublicKeySize {
		return ErrPlatformDeviceSession
	}
	timestamp := strings.TrimSpace(r.Header.Get("X-Infinite-Device-Timestamp"))
	nonce := strings.TrimSpace(r.Header.Get("X-Infinite-Device-Nonce"))
	signatureRaw := strings.TrimSpace(r.Header.Get("X-Infinite-Device-Signature"))
	expectedBodyDigest, err := desktopExpectedBodyDigest(r)
	if err != nil {
		return ErrPlatformDeviceSession
	}
	unixTime, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || len(nonce) < 20 || len(nonce) > 160 {
		return ErrPlatformDeviceSession
	}
	now := time.Now().Unix()
	if unixTime < now-120 || unixTime > now+120 {
		return ErrPlatformDeviceSession
	}
	signature, err := base64.RawURLEncoding.DecodeString(signatureRaw)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(auth.PublicKey), []byte(desktopCanonicalRequest(r, timestamp, nonce)), signature) {
		return ErrPlatformDeviceSession
	}
	proof := desktopMACProof(r)
	if proof == "" || subtle.ConstantTimeCompare([]byte(proof), []byte(auth.MACProofHash)) != 1 {
		_ = platform.RequirePlatformDeviceMACReverification(r.Context(), auth.DeviceID)
		// The database revocation rejects the next request.  Also interrupt an
		// already-running stream for this device so a changed MAC binding takes
		// effect immediately rather than after an upstream response completes.
		cancelCtx, cancel := context.WithTimeout(context.Background(), keyRequestDrainTimeout)
		if _, cancelErr := s.cancelPlatformDeviceRequests(cancelCtx, auth.DeviceID); cancelErr != nil {
			s.setSecurityRuntimeFailure("platform_device_mac_reverify_cancel", cancelErr)
		}
		cancel()
		return ErrPlatformDeviceMACChanged
	}
	if auth.SessionID != "" {
		if err := platform.ConsumePlatformDeviceNonce(r.Context(), auth.SessionID, nonce, time.Unix(now+180, 0).UTC()); err != nil {
			return err
		}
	}
	if r.Body == nil || r.Body == http.NoBody {
		empty := sha256.Sum256(nil)
		if subtle.ConstantTimeCompare(empty[:], expectedBodyDigest) != 1 {
			return ErrDesktopBodyTampered
		}
	} else {
		r.Body = &desktopDigestReadCloser{reader: r.Body, hash: newDesktopSHA256(), expected: expectedBodyDigest}
	}
	return nil
}

// newDesktopSHA256 keeps the stream verifier in this file independent from
// implementation details of Go's default transport while using the exact same
// digest wire format as the released desktop client.
func newDesktopSHA256() hash.Hash { return sha256.New() }

func (s *Server) platformDesktopAuthStart(w http.ResponseWriter, r *http.Request) {
	platform := s.store.Platform()
	if platform == nil {
		writeError(w, http.StatusServiceUnavailable, "platform_unavailable", "统一数据库尚未就绪")
		return
	}
	ip := s.realIP(r)
	if !s.allowAttempt("platform-desktop-start:"+ip, 20, 10*time.Minute) {
		writeError(w, http.StatusTooManyRequests, "desktop_auth_throttled", "登录请求过于频繁")
		return
	}
	var body struct {
		PublicKey  string `json:"public_key"`
		DeviceName string `json:"device_name"`
		Platform   string `json:"platform"`
		MAC        string `json:"mac"`
	}
	if !decodeJSON(w, r, 32<<10, &body) {
		return
	}
	publicKey, err := parseDesktopPublicKey(body.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_device_key", "设备公钥无效")
		return
	}
	deviceCode, err := randomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "auth_start_failed", "无法创建登录请求")
		return
	}
	var userCode string
	for attempt := 0; attempt < 4; attempt++ {
		left, leftErr := randomDigits(4)
		right, rightErr := randomDigits(4)
		if leftErr != nil || rightErr != nil {
			err = ErrPlatformDeviceFlowExpired
			break
		}
		userCode = left + "-" + right
		err = platform.CreatePlatformDeviceAuthFlow(r.Context(), PlatformDeviceFlowInput{DeviceCode: deviceCode, UserCode: userCode, PublicKey: publicKey, DeviceName: body.DeviceName, Platform: body.Platform, MAC: body.MAC, RequestIP: ip, TTL: s.cfg.DesktopFlowTTL})
		if err == nil {
			break
		}
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "auth_start_failed", "无法创建设备授权请求")
		return
	}
	verificationURL := strings.TrimRight(s.cfg.PublicPortalURL, "/") + "/?code=" + userCode
	_ = platform.RecordPlatformAudit(r.Context(), "desktop", "agent.device_auth.started", "device", tokenHash(string(publicKey)), ip, map[string]string{"platform": truncate(strings.TrimSpace(body.Platform), 80)})
	writeJSON(w, http.StatusCreated, map[string]any{"device_code": deviceCode, "user_code": userCode, "verification_uri": s.cfg.PublicPortalURL, "verification_uri_complete": verificationURL, "expires_at": time.Now().Add(s.cfg.DesktopFlowTTL).Unix(), "interval": 2})
}

func (s *Server) platformDesktopAuthPoll(w http.ResponseWriter, r *http.Request) {
	platform := s.store.Platform()
	if platform == nil {
		writeError(w, http.StatusServiceUnavailable, "platform_unavailable", "统一数据库尚未就绪")
		return
	}
	var body struct {
		DeviceCode string `json:"device_code"`
	}
	raw, ok := decodeDesktopSignedJSON(w, r, 8<<10, &body)
	if !ok {
		return
	}
	flow, err := platform.PlatformDeviceFlowByDeviceCode(r.Context(), body.DeviceCode)
	if err != nil {
		writeError(w, http.StatusGone, "authorization_expired", "网页登录请求已失效")
		return
	}
	if err := verifyDesktopBodyBytes(r, raw); err != nil {
		writeError(w, http.StatusUnauthorized, "desktop_body_tampered", "设备请求内容校验失败")
		return
	}
	auth := &PlatformDeviceSessionAuth{PublicKey: flow.PublicKey, MACProofHash: flow.MACProof}
	if err := s.verifyPlatformDesktopRequest(r, platform, auth); err != nil {
		platformDesktopAuthError(w, err)
		return
	}
	access, refresh, session, err := platform.ConsumeApprovedPlatformDeviceFlow(r.Context(), body.DeviceCode, s.cfg.DesktopAccessTTL, s.cfg.DesktopRefreshTTL)
	if errors.Is(err, ErrPlatformDeviceFlowPending) {
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "authorization_pending"})
		return
	}
	if err != nil {
		platformDesktopAuthError(w, err)
		return
	}
	_ = platform.RecordPlatformAudit(r.Context(), "desktop", "agent.device_auth.completed", "device", session.DeviceID, s.realIP(r), map[string]string{"user_id": session.UserID})
	writeJSON(w, http.StatusOK, map[string]any{"status": "authorized", "access_token": access, "refresh_token": refresh, "access_expires_at": session.AccessExpires.Unix(), "refresh_expires_at": session.RefreshExpires.Unix()})
}

func (s *Server) platformDesktopAuthRefresh(w http.ResponseWriter, r *http.Request) {
	platform := s.store.Platform()
	refresh := desktopBearer(r, "fgdr_")
	if platform == nil || refresh == "" {
		writeError(w, http.StatusUnauthorized, "refresh_invalid", "桌面登录已失效")
		return
	}
	auth, err := platform.PlatformDeviceSessionByRefresh(r.Context(), refresh)
	if err != nil || s.verifyPlatformDesktopRequest(r, platform, auth) != nil {
		writeError(w, http.StatusUnauthorized, "refresh_invalid", "桌面登录已失效")
		return
	}
	access, next, accessExpiry, refreshExpiry, err := platform.RotatePlatformDeviceSession(r.Context(), auth.SessionID, refresh, s.cfg.DesktopAccessTTL, s.cfg.DesktopRefreshTTL)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "refresh_invalid", "桌面登录已失效")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": access, "refresh_token": next, "access_expires_at": accessExpiry.Unix(), "refresh_expires_at": refreshExpiry.Unix()})
}

func (s *Server) platformDesktopSessionStatus(w http.ResponseWriter, r *http.Request) {
	auth, err := s.platformDesktopSessionRequest(r)
	if err != nil {
		platformDesktopAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "session_id": auth.SessionID, "email": auth.UserEmail, "display_name": auth.DisplayName, "device_name": auth.DeviceName, "provisioned": true})
}

func (s *Server) platformDesktopSessionWatch(w http.ResponseWriter, r *http.Request) {
	auth, err := s.platformDesktopSessionRequest(r)
	if err != nil {
		platformDesktopAuthError(w, err)
		return
	}
	timer := time.NewTimer(25 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer timer.Stop()
	defer ticker.Stop()
	token := desktopBearer(r, "fgds_")
	for {
		select {
		case <-r.Context().Done():
			return
		case <-timer.C:
			writeJSON(w, http.StatusOK, map[string]string{"status": "active"})
			return
		case <-ticker.C:
			current, currentErr := s.store.Platform().PlatformDeviceSessionByAccess(r.Context(), token)
			if currentErr != nil || current.SessionID != auth.SessionID {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"status": "revoked"})
				return
			}
		}
	}
}

func (s *Server) platformDesktopSessionLogout(w http.ResponseWriter, r *http.Request) {
	auth, err := s.platformDesktopSessionRequest(r)
	if err != nil {
		platformDesktopAuthError(w, err)
		return
	}
	if err := s.store.Platform().RevokePlatformDeviceSession(r.Context(), auth.SessionID, auth.UserID, auth.DeviceID); err != nil {
		writeError(w, http.StatusInternalServerError, "logout_failed", "退出登录失败")
		return
	}
	_ = s.store.Platform().RecordPlatformAudit(r.Context(), "desktop", "agent.session.logged_out", "device", auth.DeviceID, s.realIP(r), map[string]string{"user_id": auth.UserID, "session_id": auth.SessionID})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) platformDesktopPolicyGet(w http.ResponseWriter, r *http.Request) {
	auth, err := s.platformDesktopSessionRequest(r)
	if err != nil {
		platformDesktopAuthError(w, err)
		return
	}
	models, err := s.store.Platform().ListPlatformProductModelsForUserProtocols(r.Context(), auth.UserID, ProductScopeAgent, []string{"responses", "chat_completions", "messages", "generate_content"})
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "desktop_models_failed", "读取 Agent 模型目录失败")
		return
	}
	allowed := make([]string, 0, len(models))
	for _, model := range models {
		if model.Available {
			allowed = append(allowed, model.ModelKey)
		}
	}
	defaultModel := ""
	if len(allowed) > 0 {
		defaultModel = allowed[0]
	}
	writeJSON(w, http.StatusOK, map[string]any{"registration_enabled": false, "public_api_enabled": false, "official_desktop_only": true, "gateway_base_url": s.cfg.PublicAPIURL, "provider_name": "Infinite AI", "default_model": defaultModel, "allowed_models": allowed, "system_prompt": ""})
}

func (s *Server) platformPortalCurrentUser(r *http.Request) (*PlatformUser, error) {
	cookie, err := r.Cookie(platformUserCookieName)
	if err != nil {
		return nil, err
	}
	platform := s.store.Platform()
	if platform == nil {
		return nil, ErrPlatformDatabaseUnavailable
	}
	return platform.PlatformUserSession(r.Context(), cookie.Value, s.realIP(r), r.UserAgent())
}

func (s *Server) platformPortalDeviceFlow(w http.ResponseWriter, r *http.Request) {
	platform := s.store.Platform()
	if platform == nil {
		writeError(w, http.StatusServiceUnavailable, "platform_unavailable", "统一数据库尚未就绪")
		return
	}
	if !s.allowAttempt("platform-portal-device-flow:"+s.realIP(r), 60, 10*time.Minute) {
		writeError(w, http.StatusTooManyRequests, "device_flow_throttled", "设备授权查询过于频繁")
		return
	}
	flow, err := platform.PlatformDeviceFlowByUserCode(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		writeError(w, http.StatusGone, "authorization_expired", "授权码无效或已过期")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"device_name": flow.DeviceName, "platform": flow.Platform, "request_ip": flow.RequestIP, "status": flow.Status, "expires_at": flow.ExpiresAt.Unix()})
}

func (s *Server) platformPortalApproveDeviceFlow(w http.ResponseWriter, r *http.Request) {
	user, err := s.platformPortalCurrentUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "user_auth_required", "请先登录")
		return
	}
	var body struct {
		UserCode string `json:"user_code"`
	}
	if !decodeJSON(w, r, 8<<10, &body) {
		return
	}
	platform := s.store.Platform()
	flow, err := platform.PlatformDeviceFlowByUserCode(r.Context(), body.UserCode)
	if err != nil {
		writeError(w, http.StatusGone, "authorization_expired", "授权码无效或已过期")
		return
	}
	if err := platform.ApprovePlatformDeviceFlow(r.Context(), body.UserCode, user.ID, s.realIP(r)); err != nil {
		writeError(w, http.StatusGone, "authorization_expired", "授权码无效或已使用")
		return
	}
	_ = platform.RecordPlatformAudit(r.Context(), "user", "agent.device.approved", "device_flow", flow.ID, s.realIP(r), map[string]string{"user_id": user.ID})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) platformPortalDevices(w http.ResponseWriter, r *http.Request) {
	user, err := s.platformPortalCurrentUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "user_auth_required", "请先登录")
		return
	}
	items, err := s.store.Platform().ListPlatformDevices(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "devices_failed", "读取设备失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) platformPortalRevokeDevice(w http.ResponseWriter, r *http.Request) {
	user, err := s.platformPortalCurrentUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "user_auth_required", "请先登录")
		return
	}
	if err := s.store.Platform().RevokePlatformDevice(r.Context(), r.PathValue("id"), user.ID); err != nil {
		writeError(w, http.StatusNotFound, "device_not_found", "设备不存在或已经退出")
		return
	}
	if _, err := s.cancelPlatformDeviceRequests(r.Context(), r.PathValue("id")); err != nil {
		s.setSecurityRuntimeFailure("platform_device_revoke_cancel", err)
	}
	_ = s.store.Platform().RecordPlatformAudit(r.Context(), "user", "agent.device.revoked", "device", r.PathValue("id"), s.realIP(r), map[string]string{"user_id": user.ID})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) platformPortalProjects(w http.ResponseWriter, r *http.Request) {
	user, err := s.platformPortalCurrentUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "user_auth_required", "请先登录")
		return
	}
	platform := s.store.Platform()
	switch r.Method {
	case http.MethodGet:
		items, err := platform.ListPlatformProjects(r.Context(), user.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "projects_failed", "读取项目失败")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		var input PlatformProjectInput
		if !decodeJSON(w, r, 32<<10, &input) {
			return
		}
		item, err := platform.CreatePlatformProject(r.Context(), user.ID, input)
		if err != nil {
			writeError(w, http.StatusBadRequest, "project_invalid", "项目配置无效")
			return
		}
		_ = platform.RecordPlatformAudit(r.Context(), "user", "agent.project.created", "project", item.ID, s.realIP(r), map[string]string{"user_id": user.ID})
		writeJSON(w, http.StatusCreated, item)
	default:
		w.Header().Set("Allow", "GET, POST")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "请求方法不允许")
	}
}

func (s *Server) platformPortalProject(w http.ResponseWriter, r *http.Request) {
	user, err := s.platformPortalCurrentUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "user_auth_required", "请先登录")
		return
	}
	platform, id := s.store.Platform(), r.PathValue("id")
	switch r.Method {
	case http.MethodPatch:
		var patch PlatformProjectPatch
		if !decodeJSON(w, r, 32<<10, &patch) {
			return
		}
		item, err := platform.UpdatePlatformProject(r.Context(), user.ID, id, patch)
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "project_not_found", "项目不存在")
			return
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, "project_invalid", "项目配置无效")
			return
		}
		_ = platform.RecordPlatformAudit(r.Context(), "user", "agent.project.updated", "project", id, s.realIP(r), map[string]string{"user_id": user.ID})
		writeJSON(w, http.StatusOK, item)
	case http.MethodDelete:
		if err := platform.DeletePlatformProject(r.Context(), user.ID, id); err != nil {
			writeError(w, http.StatusNotFound, "project_not_found", "项目不存在")
			return
		}
		_ = platform.RecordPlatformAudit(r.Context(), "user", "agent.project.deleted", "project", id, s.realIP(r), map[string]string{"user_id": user.ID})
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "PATCH, DELETE")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "请求方法不允许")
	}
}

func (s *Server) platformDesktopAgentSubKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		auth, err := s.platformDesktopSessionRequest(r)
		if err != nil {
			platformDesktopAuthError(w, err)
			return
		}
		items, err := s.store.Platform().ListPlatformAgentSubKeys(r.Context(), auth.UserID, auth.DeviceID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "sub_keys_failed", "读取本地子 Key 失败")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
		return
	case http.MethodPost:
	default:
		w.Header().Set("Allow", "GET, POST")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "请求方法不允许")
		return
	}
	var body struct {
		ProjectID  string `json:"project_id"`
		TTLSeconds int64  `json:"ttl_seconds"`
	}
	raw, ok := decodeDesktopSignedJSON(w, r, 16<<10, &body)
	if !ok {
		return
	}
	if err := verifyDesktopBodyBytes(r, raw); err != nil {
		writeError(w, http.StatusUnauthorized, "desktop_body_tampered", "设备请求内容校验失败")
		return
	}
	auth, err := s.platformDesktopSessionRequest(r)
	if err != nil {
		platformDesktopAuthError(w, err)
		return
	}
	ttl := time.Duration(body.TTLSeconds) * time.Second
	if ttl == 0 {
		ttl = time.Hour
	}
	item, plain, err := s.store.Platform().CreatePlatformAgentSubKey(r.Context(), auth.UserID, auth.DeviceID, body.ProjectID, ttl)
	if err != nil {
		writeError(w, http.StatusBadRequest, "sub_key_invalid", "本地子 Key 配置无效")
		return
	}
	_ = s.store.Platform().RecordPlatformAudit(r.Context(), "desktop", "agent.sub_key.created", "agent_sub_key", item.ID, s.realIP(r), map[string]string{"user_id": auth.UserID, "device_id": auth.DeviceID})
	writeJSON(w, http.StatusCreated, map[string]any{"key": item, "plain_key": plain, "expires_at": item.ExpiresAt.Unix()})
}

func (s *Server) platformDesktopAgentSubKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", http.MethodDelete)
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "请求方法不允许")
		return
	}
	var body struct{}
	raw, ok := decodeDesktopSignedJSON(w, r, 4<<10, &body)
	if !ok {
		return
	}
	if err := verifyDesktopBodyBytes(r, raw); err != nil {
		writeError(w, http.StatusUnauthorized, "desktop_body_tampered", "设备请求内容校验失败")
		return
	}
	auth, err := s.platformDesktopSessionRequest(r)
	if err != nil {
		platformDesktopAuthError(w, err)
		return
	}
	if err := s.store.Platform().RevokePlatformAgentSubKey(r.Context(), r.PathValue("id"), auth.UserID); err != nil {
		writeError(w, http.StatusNotFound, "sub_key_not_found", "本地子 Key 不存在")
		return
	}
	_ = s.store.Platform().RecordPlatformAudit(r.Context(), "desktop", "agent.sub_key.revoked", "agent_sub_key", r.PathValue("id"), s.realIP(r), map[string]string{"user_id": auth.UserID, "device_id": auth.DeviceID})
	w.WriteHeader(http.StatusNoContent)
}

func platformDesktopAuthError(w http.ResponseWriter, err error) {
	status, code, message := http.StatusUnauthorized, "desktop_session_invalid", "桌面登录已失效"
	if errors.Is(err, ErrPlatformDeviceFlowPending) {
		status, code, message = http.StatusAccepted, "authorization_pending", "等待网页授权"
	} else if errors.Is(err, ErrPlatformDeviceFlowExpired) {
		status, code, message = http.StatusGone, "authorization_expired", "网页登录请求已失效"
	} else if errors.Is(err, ErrPlatformDeviceMACChanged) {
		status, code, message = http.StatusUnauthorized, "desktop_mac_changed", "网卡信息已变化，请重新网页验证"
	} else if errors.Is(err, ErrReplayDetected) {
		status, code, message = http.StatusConflict, "desktop_replay_detected", "请求签名已使用"
	}
	writeError(w, status, code, message)
}
