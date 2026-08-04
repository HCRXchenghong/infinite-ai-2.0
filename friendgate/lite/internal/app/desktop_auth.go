package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"
)

const userCookieName = "infinite_ai_user"

func desktopCanonicalRequest(r *http.Request, timestamp, nonce string) string {
	return r.Method + "\n" + r.URL.RequestURI() + "\n" + timestamp + "\n" + nonce + "\n" + strings.TrimSpace(r.Header.Get("X-Infinite-Content-SHA256")) + "\n" + strings.TrimSpace(r.Header.Get("X-Infinite-Device-MAC-Hash"))
}

func desktopBodyDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func desktopExpectedBodyDigest(r *http.Request) ([]byte, error) {
	value := strings.TrimSpace(r.Header.Get("X-Infinite-Content-SHA256"))
	digest, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(digest) != sha256.Size || base64.RawURLEncoding.EncodeToString(digest) != value {
		return nil, ErrDesktopSessionInvalid
	}
	return digest, nil
}

type desktopDigestReadCloser struct {
	reader      io.ReadCloser
	hash        hash.Hash
	expected    []byte
	terminalErr error
	checked     bool
}

func (r *desktopDigestReadCloser) Read(buffer []byte) (int, error) {
	if r.terminalErr != nil {
		err := r.terminalErr
		r.terminalErr = nil
		return 0, err
	}
	n, err := r.reader.Read(buffer)
	if n > 0 {
		_, _ = r.hash.Write(buffer[:n])
	}
	if errors.Is(err, io.EOF) && !r.checked {
		r.checked = true
		if subtle.ConstantTimeCompare(r.hash.Sum(nil), r.expected) != 1 {
			if n > 0 {
				r.terminalErr = ErrDesktopBodyTampered
				return n, nil
			}
			return 0, ErrDesktopBodyTampered
		}
	}
	return n, err
}

func (r *desktopDigestReadCloser) Close() error { return r.reader.Close() }

func verifyDesktopBodyBytes(r *http.Request, body []byte) error {
	expected, err := desktopExpectedBodyDigest(r)
	if err != nil {
		return err
	}
	actual := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(actual[:], expected) != 1 {
		return ErrDesktopBodyTampered
	}
	return nil
}

func parseDesktopPublicKey(encoded string) (ed25519.PublicKey, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 public key")
	}
	return ed25519.PublicKey(decoded), nil
}

func (s *Server) verifyDesktopRequest(r *http.Request, publicKey string, sessionID int64) error {
	key, err := parseDesktopPublicKey(publicKey)
	if err != nil {
		return ErrDesktopSessionInvalid
	}
	timestamp := strings.TrimSpace(r.Header.Get("X-Infinite-Device-Timestamp"))
	nonce := strings.TrimSpace(r.Header.Get("X-Infinite-Device-Nonce"))
	signatureRaw := strings.TrimSpace(r.Header.Get("X-Infinite-Device-Signature"))
	expectedBodyDigest, err := desktopExpectedBodyDigest(r)
	if err != nil {
		return ErrDesktopSessionInvalid
	}
	unixTime, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || len(nonce) < 20 || len(nonce) > 160 {
		return ErrDesktopSessionInvalid
	}
	now := time.Now().Unix()
	if unixTime < now-120 || unixTime > now+120 {
		return ErrDesktopSessionInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(signatureRaw)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, []byte(desktopCanonicalRequest(r, timestamp, nonce)), signature) {
		return ErrDesktopSessionInvalid
	}
	if sessionID > 0 {
		if err := s.store.ConsumeDesktopNonce(r.Context(), sessionID, nonce, now+180); err != nil {
			return err
		}
	}
	if r.Body == nil || r.Body == http.NoBody {
		empty := sha256.Sum256(nil)
		if subtle.ConstantTimeCompare(empty[:], expectedBodyDigest) != 1 {
			return ErrDesktopBodyTampered
		}
	} else {
		r.Body = &desktopDigestReadCloser{reader: r.Body, hash: sha256.New(), expected: expectedBodyDigest}
	}
	return nil
}

func desktopBearer(r *http.Request, prefix string) string {
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(authorization), "bearer ") {
		return ""
	}
	token := strings.TrimSpace(authorization[7:])
	if !strings.HasPrefix(token, prefix) {
		return ""
	}
	return token
}

func (s *Server) desktopSessionRequest(r *http.Request) (*desktopSessionAuth, error) {
	token := desktopBearer(r, "fgds_")
	if token == "" {
		return nil, ErrDesktopSessionInvalid
	}
	auth, err := s.store.DesktopSessionByAccess(r.Context(), token)
	if err != nil {
		return nil, err
	}
	if err := s.verifyDesktopRequest(r, auth.PublicKey, auth.SessionID); err != nil {
		return nil, err
	}
	if err := s.verifyDesktopMACBinding(r, auth); err != nil {
		return nil, err
	}
	s.store.TouchDesktopSession(r.Context(), auth.SessionID, s.realIP(r))
	return auth, nil
}

func desktopMACProof(r *http.Request) string {
	value := strings.TrimSpace(r.Header.Get("X-Infinite-Device-MAC-Hash"))
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return ""
	}
	return value
}

func (s *Server) verifyDesktopMACBinding(r *http.Request, auth *desktopSessionAuth) error {
	proof := desktopMACProof(r)
	if auth == nil || auth.MACHash == "" || proof == "" || subtle.ConstantTimeCompare([]byte(proof), []byte(auth.MACHash)) != 1 {
		if auth != nil && auth.DeviceID > 0 {
			_ = s.store.RequireDesktopMACReverification(r.Context(), auth.DeviceID)
		}
		return ErrDesktopSessionInvalid
	}
	return nil
}

func (s *Server) desktopAuthStart(w http.ResponseWriter, r *http.Request) {
	if platformPortalUsesPostgres(s) {
		s.platformDesktopAuthStart(w, r)
		return
	}
	ip := s.realIP(r)
	if !s.allowAttempt("desktop-start:"+ip, 20, 10*time.Minute) {
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
	if _, err := parseDesktopPublicKey(body.PublicKey); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_device_key", "设备公钥无效")
		return
	}
	body.DeviceName = strings.TrimSpace(body.DeviceName)
	body.Platform = strings.TrimSpace(body.Platform)
	if body.DeviceName == "" || len(body.DeviceName) > 120 || len(body.Platform) > 80 {
		writeError(w, http.StatusBadRequest, "invalid_device", "设备名称或平台信息无效")
		return
	}
	body.MAC = normalizeDesktopMAC(body.MAC)
	if body.MAC == "" {
		writeError(w, http.StatusBadRequest, "mac_required", "必须读取并提交有效的网卡 MAC 地址")
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
			err = errors.New("generate user code")
			break
		}
		userCode = left + "-" + right
		err = s.store.CreateDesktopAuthFlow(r.Context(), deviceCode, userCode, body.PublicKey, body.DeviceName, body.Platform, body.MAC, ip, s.cfg.DesktopFlowTTL)
		if err == nil {
			break
		}
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "auth_start_failed", "无法创建登录请求")
		return
	}
	verificationURL := s.cfg.PublicPortalURL + "/?code=" + userCode
	s.store.Audit(r.Context(), "desktop", "desktop.auth.started", body.DeviceName, ip, map[string]string{"platform": body.Platform})
	writeJSON(w, http.StatusCreated, map[string]any{
		"device_code": deviceCode, "user_code": userCode, "verification_uri": s.cfg.PublicPortalURL,
		"verification_uri_complete": verificationURL, "expires_at": time.Now().Add(s.cfg.DesktopFlowTTL).Unix(), "interval": 2,
	})
}

func (s *Server) desktopAuthPoll(w http.ResponseWriter, r *http.Request) {
	if platformPortalUsesPostgres(s) {
		s.platformDesktopAuthPoll(w, r)
		return
	}
	var body struct {
		DeviceCode string `json:"device_code"`
	}
	rawBody, ok := decodeDesktopSignedJSON(w, r, 8<<10, &body)
	if !ok {
		return
	}
	flow, err := s.store.DesktopAuthFlowByDeviceCode(r.Context(), body.DeviceCode)
	if err != nil {
		writeError(w, http.StatusGone, "authorization_expired", "网页登录请求已失效")
		return
	}
	if err := verifyDesktopBodyBytes(r, rawBody); err != nil {
		s.rejectUnauthorized(w, r, s.realIP(r), "desktop_body_tampered", "desktop request body digest mismatch", http.StatusUnauthorized)
		return
	}
	if err := s.verifyDesktopRequest(r, flow.PublicKey, 0); err != nil {
		s.rejectUnauthorized(w, r, s.realIP(r), "desktop_signature_invalid", "invalid desktop device signature", http.StatusUnauthorized)
		return
	}
	if proof := desktopMACProof(r); proof == "" || subtle.ConstantTimeCompare([]byte(proof), []byte(flow.MACHash)) != 1 {
		writeError(w, http.StatusUnauthorized, "desktop_mac_changed", "网卡信息已变化，请重新发起设备授权")
		return
	}
	access, refresh, auth, err := s.store.ConsumeApprovedDesktopFlow(r.Context(), body.DeviceCode, s.cfg.DesktopAccessTTL, s.cfg.DesktopRefreshTTL)
	if errors.Is(err, ErrDesktopFlowPending) {
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "authorization_pending"})
		return
	}
	if err != nil {
		writeError(w, http.StatusGone, "authorization_expired", "网页登录请求已失效或已完成")
		return
	}
	s.store.Audit(r.Context(), "desktop", "desktop.auth.completed", strconv.FormatInt(auth.DeviceID, 10), s.realIP(r), map[string]int64{"user_id": auth.UserID})
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "authorized", "access_token": access, "refresh_token": refresh,
		"access_expires_at": auth.AccessExpires, "refresh_expires_at": auth.RefreshExpires,
	})
}

func decodeDesktopSignedJSON(w http.ResponseWriter, r *http.Request, max int64, target any) ([]byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, max)
	value, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "请求内容格式不正确")
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "请求内容格式不正确")
		return nil, false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_json", "请求只能包含一个 JSON 对象")
		return nil, false
	}
	return value, true
}

func (s *Server) desktopAuthRefresh(w http.ResponseWriter, r *http.Request) {
	if platformPortalUsesPostgres(s) {
		s.platformDesktopAuthRefresh(w, r)
		return
	}
	refresh := desktopBearer(r, "fgdr_")
	if refresh == "" {
		writeError(w, http.StatusUnauthorized, "refresh_invalid", "桌面登录已失效")
		return
	}
	auth, err := s.store.DesktopSessionByRefresh(r.Context(), refresh)
	if err != nil || s.verifyDesktopRequest(r, auth.PublicKey, auth.SessionID) != nil || s.verifyDesktopMACBinding(r, auth) != nil {
		writeError(w, http.StatusUnauthorized, "refresh_invalid", "桌面登录已失效")
		return
	}
	access, nextRefresh, accessExpires, refreshExpires, err := s.store.RotateDesktopSession(r.Context(), auth.SessionID, refresh, s.cfg.DesktopAccessTTL, s.cfg.DesktopRefreshTTL)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "refresh_invalid", "桌面登录已失效")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": access, "refresh_token": nextRefresh, "access_expires_at": accessExpires, "refresh_expires_at": refreshExpires})
}

func (s *Server) desktopSessionStatus(w http.ResponseWriter, r *http.Request) {
	if platformPortalUsesPostgres(s) {
		s.platformDesktopSessionStatus(w, r)
		return
	}
	auth, err := s.desktopSessionRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "desktop_session_invalid", "桌面登录已失效")
		return
	}
	provisioned := auth.APIKeyID > 0
	if provisioned {
		_, err = s.store.DesktopAPIKey(r.Context(), auth.APIKeyID)
		provisioned = err == nil
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true, "session_id": auth.SessionID, "email": auth.UserEmail,
		"display_name": auth.DisplayName, "device_name": auth.DeviceName, "provisioned": provisioned,
	})
}

func (s *Server) desktopSessionWatch(w http.ResponseWriter, r *http.Request) {
	if platformPortalUsesPostgres(s) {
		s.platformDesktopSessionWatch(w, r)
		return
	}
	auth, err := s.desktopSessionRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "desktop_session_invalid", "桌面登录已失效")
		return
	}
	deadline := time.NewTimer(25 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-deadline.C:
			writeJSON(w, http.StatusOK, map[string]string{"status": "active"})
			return
		case <-ticker.C:
			current, currentErr := s.store.DesktopSessionByAccess(r.Context(), desktopBearer(r, "fgds_"))
			provisioned := currentErr == nil && current.APIKeyID > 0
			if provisioned {
				_, currentErr = s.store.DesktopAPIKey(r.Context(), current.APIKeyID)
				provisioned = currentErr == nil
			}
			if currentErr != nil || current.SessionID != auth.SessionID || !provisioned {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"status": "revoked"})
				return
			}
		}
	}
}

func (s *Server) desktopSessionLogout(w http.ResponseWriter, r *http.Request) {
	if platformPortalUsesPostgres(s) {
		s.platformDesktopSessionLogout(w, r)
		return
	}
	auth, err := s.desktopSessionRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "desktop_session_invalid", "桌面登录已失效")
		return
	}
	cancelled, err := s.revokeDesktopSession(r.Context(), auth.SessionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "logout_failed", "退出登录失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cancelled_requests": cancelled})
}

func (s *Server) desktopPolicyGet(w http.ResponseWriter, r *http.Request) {
	if platformPortalUsesPostgres(s) {
		s.platformDesktopPolicyGet(w, r)
		return
	}
	auth, err := s.desktopSessionRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "desktop_session_invalid", "桌面登录已失效")
		return
	}
	policy := s.currentDesktopPolicy()
	policy.RegistrationEnabled = false
	if auth.APIKeyID == 0 {
		writeError(w, http.StatusForbidden, "desktop_not_provisioned", "管理员尚未给该用户分配使用权限")
		return
	}
	if _, err := s.store.DesktopAPIKey(r.Context(), auth.APIKeyID); err != nil {
		writeError(w, http.StatusForbidden, "desktop_not_provisioned", "管理员分配的密钥不可用")
		return
	}
	if len(policy.AllowedModels) == 0 {
		models, modelErr := s.store.DesktopModelsForKey(r.Context(), auth.APIKeyID)
		if modelErr != nil {
			writeError(w, http.StatusInternalServerError, "desktop_models_failed", "读取账号模型列表失败")
			return
		}
		policy.AllowedModels = models
	}
	writeJSON(w, http.StatusOK, policy)
}

func (s *Server) portalHandler() http.Handler {
	root := http.NewServeMux()
	root.HandleFunc("GET /api/portal/config", s.portalConfig)
	root.HandleFunc("POST /api/portal/register", s.portalRegister)
	root.HandleFunc("POST /api/portal/login", s.portalLogin)
	root.HandleFunc("GET /api/portal/me", s.portalMe)
	protected := http.NewServeMux()
	protected.HandleFunc("POST /api/portal/logout", s.portalLogout)
	protected.HandleFunc("GET /api/portal/models", s.portalModels)
	protected.HandleFunc("POST /api/portal/chat/responses", s.portalChatResponses)
	protected.HandleFunc("GET /api/portal/chat/conversations", s.portalChatConversations)
	protected.HandleFunc("POST /api/portal/chat/conversations", s.portalChatConversations)
	protected.HandleFunc("GET /api/portal/chat/conversations/{id}", s.portalChatConversation)
	protected.HandleFunc("PATCH /api/portal/chat/conversations/{id}", s.portalChatConversation)
	protected.HandleFunc("DELETE /api/portal/chat/conversations/{id}", s.portalChatConversation)
	protected.HandleFunc("POST /api/portal/chat/conversations/{id}/responses", s.portalChatResponses)
	protected.HandleFunc("GET /api/portal/device-flow", s.portalDeviceFlow)
	protected.HandleFunc("POST /api/portal/device-flow/approve", s.portalApproveDeviceFlow)
	protected.HandleFunc("GET /api/portal/devices", s.portalDevices)
	protected.HandleFunc("DELETE /api/portal/devices/{id}", s.portalRevokeDevice)
	protected.HandleFunc("GET /api/portal/agent/projects", s.portalAgentProjects)
	protected.HandleFunc("POST /api/portal/agent/projects", s.portalAgentProjects)
	protected.HandleFunc("PATCH /api/portal/agent/projects/{id}", s.portalAgentProject)
	protected.HandleFunc("DELETE /api/portal/agent/projects/{id}", s.portalAgentProject)
	root.Handle("/api/portal/", s.portalOnly(protected))
	root.Handle("/", s.staticHandler("portal.html"))
	return root
}

func (s *Server) portalOnly(next http.Handler) http.Handler {
	if platformPortalUsesPostgres(s) {
		return s.platformPortalOnly(next)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(userCookieName)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "user_auth_required", "请先登录")
			return
		}
		_, csrf, err := s.store.UserSession(r.Context(), cookie.Value, s.realIP(r))
		if err != nil {
			http.SetCookie(w, expiredCookie(userCookieName, s.cfg.SecureCookies))
			writeError(w, http.StatusUnauthorized, "user_session_expired", "网页登录已失效")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !sameOrigin(r) || r.Header.Get("X-CSRF-Token") == "" || subtleCompare(r.Header.Get("X-CSRF-Token"), csrf) != 1 {
				writeError(w, http.StatusForbidden, "csrf_failed", "安全校验失败")
				return
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) portalConfig(w http.ResponseWriter, r *http.Request) {
	if platformPortalUsesPostgres(s) {
		s.platformPortalConfig(w, r)
		return
	}
	policy := s.store.DesktopPolicy(r.Context(), s.cfg.PublicAPIURL)
	writeJSON(w, http.StatusOK, map[string]any{"registration_enabled": policy.RegistrationEnabled, "brand": "Infinite AI"})
}

func validDesktopRegistration(email, displayName, password string) error {
	address, err := mail.ParseAddress(strings.TrimSpace(email))
	if err != nil || normalizeDesktopEmail(address.Address) != normalizeDesktopEmail(email) || len(email) > 254 {
		return errors.New("邮箱地址无效")
	}
	if len(strings.TrimSpace(displayName)) < 1 || len(strings.TrimSpace(displayName)) > 80 {
		return errors.New("昵称必须为 1–80 个字符")
	}
	if len(password) < 12 || len(password) > 256 {
		return errors.New("密码必须为 12–256 个字符")
	}
	return nil
}

func (s *Server) portalRegister(w http.ResponseWriter, r *http.Request) {
	if platformPortalUsesPostgres(s) {
		s.platformPortalRegister(w, r)
		return
	}
	ip := s.realIP(r)
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "origin_rejected", "请求来源不受信任")
		return
	}
	if !s.allowAttempt("portal-register:"+ip, 6, time.Hour) {
		writeError(w, http.StatusTooManyRequests, "registration_throttled", "注册请求过于频繁")
		return
	}
	if !s.currentDesktopPolicy().RegistrationEnabled {
		writeError(w, http.StatusForbidden, "registration_disabled", "当前已关闭新用户注册")
		return
	}
	var body struct {
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
	}
	if !decodeJSON(w, r, 16<<10, &body) {
		return
	}
	accountAttemptKey := "portal-register-account:" + tokenHash(normalizeDesktopEmail(body.Email))
	if !s.allowAttempt(accountAttemptKey, 6, time.Hour) {
		writeError(w, http.StatusTooManyRequests, "registration_throttled", "注册请求过于频繁")
		return
	}
	if err := validDesktopRegistration(body.Email, body.DisplayName, body.Password); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_registration", err.Error())
		return
	}
	user, err := s.store.CreateDesktopUser(r.Context(), body.Email, body.DisplayName, body.Password)
	if err != nil {
		writeError(w, http.StatusConflict, "email_exists", "该邮箱已注册")
		return
	}
	token, csrf, err := s.store.NewUserSession(r.Context(), user.ID, ip, s.cfg.UserSessionTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session_failed", "无法创建网页登录")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: userCookieName, Value: token, Path: "/", HttpOnly: true, Secure: s.cfg.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: int(s.cfg.UserSessionTTL.Seconds())})
	s.store.Audit(r.Context(), "user", "user.registered", strconv.FormatInt(user.ID, 10), ip, map[string]string{"email": user.Email})
	writeJSON(w, http.StatusCreated, map[string]any{"authenticated": true, "user": user, "csrf_token": csrf})
}

func (s *Server) portalLogin(w http.ResponseWriter, r *http.Request) {
	if platformPortalUsesPostgres(s) {
		s.platformPortalLogin(w, r)
		return
	}
	ip := s.realIP(r)
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "origin_rejected", "请求来源不受信任")
		return
	}
	if !s.allowAttempt("portal-login:"+ip, 8, 10*time.Minute) {
		writeError(w, http.StatusTooManyRequests, "login_throttled", "登录失败次数过多")
		return
	}
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, 16<<10, &body) {
		return
	}
	accountAttemptKey := "portal-login-account:" + tokenHash(normalizeDesktopEmail(body.Email))
	if !s.allowAttempt(accountAttemptKey, 8, 10*time.Minute) {
		writeError(w, http.StatusTooManyRequests, "login_throttled", "登录失败次数过多")
		return
	}
	user, err := s.store.AuthenticateDesktopUser(r.Context(), body.Email, body.Password)
	if err != nil {
		s.store.Audit(r.Context(), "anonymous", "user.login.failed", normalizeDesktopEmail(body.Email), ip, nil)
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "邮箱或密码错误，或账号已停用")
		return
	}
	s.resetAttempts("portal-login:" + ip)
	s.resetAttempts(accountAttemptKey)
	token, csrf, err := s.store.NewUserSession(r.Context(), user.ID, ip, s.cfg.UserSessionTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session_failed", "无法创建网页登录")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: userCookieName, Value: token, Path: "/", HttpOnly: true, Secure: s.cfg.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: int(s.cfg.UserSessionTTL.Seconds())})
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "user": user, "csrf_token": csrf})
}

func (s *Server) portalMe(w http.ResponseWriter, r *http.Request) {
	if platformPortalUsesPostgres(s) {
		s.platformPortalMe(w, r)
		return
	}
	cookie, err := r.Cookie(userCookieName)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
		return
	}
	user, csrf, err := s.store.UserSession(r.Context(), cookie.Value, s.realIP(r))
	if err != nil {
		http.SetCookie(w, expiredCookie(userCookieName, s.cfg.SecureCookies))
		writeJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "user": user, "csrf_token": csrf})
}

func (s *Server) portalLogout(w http.ResponseWriter, r *http.Request) {
	if platformPortalUsesPostgres(s) {
		s.platformPortalLogout(w, r)
		return
	}
	if cookie, err := r.Cookie(userCookieName); err == nil {
		_ = s.store.DeleteUserSession(r.Context(), cookie.Value)
	}
	http.SetCookie(w, expiredCookie(userCookieName, s.cfg.SecureCookies))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) portalModels(w http.ResponseWriter, r *http.Request) {
	if platformPortalUsesPostgres(s) {
		s.platformPortalModels(w, r)
		return
	}
	user, err := s.portalCurrentUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "user_auth_required", "请先登录")
		return
	}
	models, err := s.store.DesktopModelsForKey(r.Context(), user.APIKeyID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "models_failed", "读取模型列表失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": models})
}

func (s *Server) portalChatResponses(w http.ResponseWriter, r *http.Request) {
	if !platformPortalUsesPostgres(s) {
		writeError(w, http.StatusNotFound, "not_found", "接口不存在")
		return
	}
	s.platformPortalChatResponses(w, r)
}

func (s *Server) portalChatConversations(w http.ResponseWriter, r *http.Request) {
	if !platformPortalUsesPostgres(s) {
		writeError(w, http.StatusNotFound, "not_found", "Chat 会话接口尚未启用")
		return
	}
	s.platformPortalChatConversations(w, r)
}

func (s *Server) portalChatConversation(w http.ResponseWriter, r *http.Request) {
	if !platformPortalUsesPostgres(s) {
		writeError(w, http.StatusNotFound, "not_found", "Chat 会话接口尚未启用")
		return
	}
	s.platformPortalChatConversation(w, r)
}

func (s *Server) portalCurrentUser(r *http.Request) (*DesktopUser, error) {
	cookie, err := r.Cookie(userCookieName)
	if err != nil {
		return nil, err
	}
	user, _, err := s.store.UserSession(r.Context(), cookie.Value, s.realIP(r))
	return user, err
}

func (s *Server) portalDeviceFlow(w http.ResponseWriter, r *http.Request) {
	if platformPortalUsesPostgres(s) {
		s.platformPortalDeviceFlow(w, r)
		return
	}
	if !s.allowAttempt("portal-device-flow:"+s.realIP(r), 60, 10*time.Minute) {
		writeError(w, http.StatusTooManyRequests, "device_flow_throttled", "设备授权查询过于频繁")
		return
	}
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	flow, err := s.store.DesktopAuthFlowForPortal(r.Context(), code)
	if err != nil {
		writeError(w, http.StatusGone, "authorization_expired", "授权码无效或已过期")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"device_name": flow.DeviceName, "platform": flow.Platform, "request_ip": flow.RequestIP, "status": flow.Status, "expires_at": flow.ExpiresAt})
}

func (s *Server) portalApproveDeviceFlow(w http.ResponseWriter, r *http.Request) {
	if platformPortalUsesPostgres(s) {
		s.platformPortalApproveDeviceFlow(w, r)
		return
	}
	if !s.allowAttempt("portal-device-approve:"+s.realIP(r), 20, 10*time.Minute) {
		writeError(w, http.StatusTooManyRequests, "device_approval_throttled", "设备授权尝试过于频繁")
		return
	}
	user, err := s.portalCurrentUser(r)
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
	flow, err := s.store.DesktopAuthFlowForPortal(r.Context(), body.UserCode)
	if err != nil {
		writeError(w, http.StatusGone, "authorization_expired", "授权码无效或已过期")
		return
	}
	if err := s.store.ApproveDesktopAuthFlow(r.Context(), body.UserCode, user.ID, s.realIP(r)); err != nil {
		writeError(w, http.StatusGone, "authorization_expired", "授权码无效或已使用")
		return
	}
	s.store.Audit(r.Context(), "user", "desktop.device.approved", flow.DeviceName, s.realIP(r), map[string]any{"user_id": user.ID, "software_ip": flow.RequestIP})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) portalDevices(w http.ResponseWriter, r *http.Request) {
	if platformPortalUsesPostgres(s) {
		s.platformPortalDevices(w, r)
		return
	}
	user, err := s.portalCurrentUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "user_auth_required", "请先登录")
		return
	}
	items, err := s.store.ListDesktopDevices(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "devices_failed", "读取设备失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) portalRevokeDevice(w http.ResponseWriter, r *http.Request) {
	if platformPortalUsesPostgres(s) {
		s.platformPortalRevokeDevice(w, r)
		return
	}
	user, err := s.portalCurrentUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "user_auth_required", "请先登录")
		return
	}
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "device_not_found", "设备不存在或已经退出")
		return
	}
	cancelled, revokeErr := s.revokeDesktopDevice(r.Context(), id, user.ID)
	if revokeErr != nil {
		writeError(w, http.StatusNotFound, "device_not_found", "设备不存在或已经退出")
		return
	}
	s.store.Audit(r.Context(), "user", "desktop.device.revoked", strconv.FormatInt(id, 10), s.realIP(r), map[string]int64{"user_id": user.ID})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cancelled_requests": cancelled})
}

// portalAgentProjects deliberately has no legacy implementation.  Project
// records carry Agent security policy and must never be split between the old
// SQLite desktop domain and the PostgreSQL product authority.
func (s *Server) portalAgentProjects(w http.ResponseWriter, r *http.Request) {
	if !platformPortalUsesPostgres(s) {
		writeError(w, http.StatusNotFound, "not_found", "Agent 项目接口尚未启用")
		return
	}
	s.platformPortalProjects(w, r)
}

func (s *Server) portalAgentProject(w http.ResponseWriter, r *http.Request) {
	if !platformPortalUsesPostgres(s) {
		writeError(w, http.StatusNotFound, "not_found", "Agent 项目接口尚未启用")
		return
	}
	s.platformPortalProject(w, r)
}

func (s *Server) desktopAgentSubKeys(w http.ResponseWriter, r *http.Request) {
	if !platformPortalUsesPostgres(s) {
		writeError(w, http.StatusNotFound, "not_found", "本地子 Key 接口尚未启用")
		return
	}
	s.platformDesktopAgentSubKeys(w, r)
}

func (s *Server) desktopAgentSubKey(w http.ResponseWriter, r *http.Request) {
	if !platformPortalUsesPostgres(s) {
		writeError(w, http.StatusNotFound, "not_found", "本地子 Key 接口尚未启用")
		return
	}
	s.platformDesktopAgentSubKey(w, r)
}

func (s *Server) adminDesktopUsers(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListDesktopUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "users_failed", "读取用户失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) adminUpdateDesktopUser(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "用户编号无效")
		return
	}
	var body struct {
		Status   string `json:"status"`
		APIKeyID int64  `json:"api_key_id"`
	}
	if !decodeJSON(w, r, 8<<10, &body) {
		return
	}
	cancelled, updateErr := s.updateDesktopUser(r.Context(), id, body.APIKeyID, body.Status)
	if updateErr != nil {
		writeError(w, http.StatusBadRequest, "user_update_failed", "用户状态或绑定密钥无效")
		return
	}
	s.store.Audit(r.Context(), "admin", "desktop.user.updated", strconv.FormatInt(id, 10), s.realIP(r), body)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cancelled_requests": cancelled})
}

func (s *Server) adminDesktopDevices(w http.ResponseWriter, r *http.Request) {
	if platformPortalUsesPostgres(s) {
		s.adminPlatformDevices(w, r)
		return
	}
	items, err := s.store.ListDesktopDevices(r.Context(), 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "devices_failed", "读取设备失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) adminRevokeDesktopDevice(w http.ResponseWriter, r *http.Request) {
	if platformPortalUsesPostgres(s) {
		s.adminRevokePlatformDevice(w, r)
		return
	}
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "device_not_found", "设备不存在或已经退出")
		return
	}
	cancelled, revokeErr := s.revokeDesktopDevice(r.Context(), id, 0)
	if revokeErr != nil {
		writeError(w, http.StatusNotFound, "device_not_found", "设备不存在或已经退出")
		return
	}
	s.store.Audit(r.Context(), "admin", "desktop.device.revoked", strconv.FormatInt(id, 10), s.realIP(r), nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cancelled_requests": cancelled})
}

func (s *Server) adminDesktopPolicy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.currentDesktopPolicy())
}

func (s *Server) adminUpdateDesktopPolicy(w http.ResponseWriter, r *http.Request) {
	var policy DesktopPolicy
	if !decodeJSON(w, r, 128<<10, &policy) {
		return
	}
	policy.ProviderName = strings.TrimSpace(policy.ProviderName)
	policy.DefaultModel = strings.TrimSpace(policy.DefaultModel)
	mode := policy.ExternalAPIMode
	if mode == "authenticated_public" && (!policy.PublicAPIEnabled || policy.OfficialDesktopOnly) {
		mode = ""
	}
	policy.ExternalAPIMode = normalizeExternalAPIMode(mode, fmt.Sprint(policy.PublicAPIEnabled), fmt.Sprint(policy.OfficialDesktopOnly))
	if policy.ProviderName == "" || len(policy.ProviderName) > 100 || policy.DefaultModel == "" || len(policy.DefaultModel) > 120 || len(policy.SystemPrompt) > 64<<10 || len(policy.AllowedModels) > 500 || (policy.ExternalAPIMode != "authenticated_public" && policy.ExternalAPIMode != "official_client_only" && policy.ExternalAPIMode != "disabled") {
		writeError(w, http.StatusBadRequest, "invalid_desktop_policy", "桌面策略内容无效")
		return
	}
	policy.GatewayBaseURL = s.cfg.PublicAPIURL
	seen := make(map[string]bool)
	models := policy.AllowedModels[:0]
	for _, model := range policy.AllowedModels {
		model = strings.TrimSpace(model)
		if model != "" && len(model) <= 120 && !seen[model] {
			seen[model] = true
			models = append(models, model)
		}
	}
	policy.AllowedModels = models
	if err := s.store.SaveDesktopPolicy(r.Context(), policy); err != nil {
		writeError(w, http.StatusInternalServerError, "policy_save_failed", "保存桌面策略失败")
		return
	}
	s.setDesktopPolicy(policy)
	s.store.Audit(r.Context(), "admin", "desktop.policy.updated", "desktop", s.realIP(r), map[string]any{"registration_enabled": policy.RegistrationEnabled, "public_api_enabled": policy.PublicAPIEnabled, "official_desktop_only": policy.OfficialDesktopOnly, "default_model": policy.DefaultModel})
	writeJSON(w, http.StatusOK, policy)
}

func (s *Server) desktopProvisionedKey(r *http.Request) (*desktopSessionAuth, *APIKey, error) {
	auth, err := s.desktopSessionRequest(r)
	if err != nil {
		return nil, nil, err
	}
	key, err := s.store.DesktopAPIKey(r.Context(), auth.APIKeyID)
	if err != nil {
		return auth, nil, err
	}
	return auth, key, nil
}

func desktopAuthError(w http.ResponseWriter, err error) {
	status, code, message := http.StatusUnauthorized, "desktop_session_invalid", "桌面登录已失效"
	if errors.Is(err, ErrUserNotProvisioned) {
		status, code, message = http.StatusForbidden, "desktop_not_provisioned", "管理员尚未分配可用密钥"
	} else if errors.Is(err, ErrReplayDetected) {
		status, code, message = http.StatusConflict, "desktop_replay_detected", "请求签名已使用"
	}
	writeError(w, status, code, message)
}

func (a desktopSessionAuth) String() string {
	return fmt.Sprintf("user=%d device=%d session=%d", a.UserID, a.DeviceID, a.SessionID)
}
