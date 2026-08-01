package app

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

type adminSetupFlow struct {
	Username     string
	PasswordHash string
	Secret       string
	IP           string
	ExpiresAt    time.Time
}

func generateTOTPSecret() (string, error) {
	buffer := make([]byte, 20)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buffer), nil
}

func totpValue(secret string, counter int64) (string, bool) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", "")))
	if err != nil || len(key) < 16 || counter < 0 {
		return "", false
	}
	message := make([]byte, 8)
	binary.BigEndian.PutUint64(message, uint64(counter))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(message)
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	value := (uint32(digest[offset])&0x7f)<<24 |
		uint32(digest[offset+1])<<16 |
		uint32(digest[offset+2])<<8 |
		uint32(digest[offset+3])
	return fmt.Sprintf("%06d", value%1_000_000), true
}

func verifyTOTP(secret, code string, now time.Time, lastCounter int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return 0, false
	}
	for _, character := range code {
		if character < '0' || character > '9' {
			return 0, false
		}
	}
	current := now.Unix() / 30
	// Microsoft Authenticator follows RFC 6238. A one-step clock tolerance is
	// accepted, but a counter already consumed by setup/login cannot be replayed.
	for _, counter := range []int64{current, current - 1, current + 1} {
		if counter <= lastCounter {
			continue
		}
		want, ok := totpValue(secret, counter)
		if ok && hmac.Equal([]byte(want), []byte(code)) {
			return counter, true
		}
	}
	return 0, false
}

func totpURI(username, secret string) string {
	issuer := "FriendGate"
	values := url.Values{}
	values.Set("secret", secret)
	values.Set("issuer", issuer)
	values.Set("algorithm", "SHA1")
	values.Set("digits", "6")
	values.Set("period", "30")
	return "otpauth://totp/" + url.PathEscape(issuer+":"+username) + "?" + values.Encode()
}

func (s *Server) adminSetupStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	required, ok := s.adminSetupState(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"setup_required": required,
		"totp_provider":  "Microsoft Authenticator",
	})
}

func (s *Server) adminSetupState(w http.ResponseWriter, r *http.Request) (required, ok bool) {
	w.Header().Set("Cache-Control", "no-store")
	required, err := s.store.AdminSetupRequired(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "setup_state_unavailable", "无法确认管理员初始化状态，创建渠道已安全关闭")
		return false, false
	}
	return required, true
}

func (s *Server) adminSetupStart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ip := s.realIP(r)
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "origin_rejected", "请求来源不受信任")
		return
	}
	required, ok := s.adminSetupState(w, r)
	if !ok {
		return
	}
	if !required {
		writeError(w, http.StatusGone, "setup_closed", "管理员创建渠道已经永久关闭")
		return
	}
	if !s.allowAttempt("admin-setup:"+ip, 5, time.Hour) {
		writeError(w, http.StatusTooManyRequests, "setup_throttled", "初始化尝试次数过多，请稍后再试")
		return
	}
	var body struct {
		InitializationPassword string `json:"initialization_password"`
		Username               string `json:"username"`
		Password               string `json:"password"`
	}
	if !decodeJSON(w, r, 16<<10, &body) {
		return
	}
	body.Username = strings.TrimSpace(body.Username)
	if len(body.Username) < 3 || len(body.Username) > 64 || strings.ContainsAny(body.Username, "\r\n\t") {
		writeError(w, http.StatusBadRequest, "invalid_username", "管理员账号长度必须为 3 到 64 位")
		return
	}
	if len(body.Password) < 12 || len(body.Password) > 256 {
		writeError(w, http.StatusBadRequest, "weak_password", "管理员密码必须为 12 到 256 位")
		return
	}
	configuredMatch := hmac.Equal([]byte(tokenHash(body.InitializationPassword)), []byte(tokenHash(s.cfg.AdminPassword)))
	legacyMatch := s.store.VerifyAdmin(r.Context(), s.store.AdminUsername(r.Context()), body.InitializationPassword)
	if !configuredMatch && !legacyMatch {
		s.store.RecordSecurityEvent(r.Context(), ip, "admin_setup_failed", r.URL.Path, "invalid initialization password")
		writeError(w, http.StatusUnauthorized, "invalid_initialization_password", "初始化口令错误")
		return
	}
	passwordHashValue, err := passwordHash(body.Password, 600_000)
	if err != nil {
		writeError(w, http.StatusBadRequest, "weak_password", "管理员密码不符合要求")
		return
	}
	secret, err := generateTOTPSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "totp_failed", "无法生成双重验证密钥")
		return
	}
	setupToken, err := randomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "setup_failed", "无法创建初始化会话")
		return
	}
	uri := totpURI(body.Username, secret)
	png, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "qrcode_failed", "无法生成二维码")
		return
	}
	s.setupMu.Lock()
	for key, flow := range s.setupFlows {
		if time.Now().After(flow.ExpiresAt) {
			delete(s.setupFlows, key)
		}
	}
	s.setupFlows[tokenHash(setupToken)] = &adminSetupFlow{Username: body.Username, PasswordHash: passwordHashValue, Secret: secret, IP: ip, ExpiresAt: time.Now().Add(10 * time.Minute)}
	s.setupMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"setup_token": setupToken,
		"expires_at":  time.Now().Add(10 * time.Minute).Unix(),
		"secret":      secret,
		"otpauth_uri": uri,
		"qr_data_url": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png),
	})
}

func (s *Server) adminSetupComplete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ip := s.realIP(r)
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "origin_rejected", "请求来源不受信任")
		return
	}
	required, ok := s.adminSetupState(w, r)
	if !ok {
		return
	}
	if !required {
		writeError(w, http.StatusGone, "setup_closed", "管理员创建渠道已经永久关闭")
		return
	}
	var body struct {
		SetupToken string `json:"setup_token"`
		Code       string `json:"code"`
	}
	if !decodeJSON(w, r, 8<<10, &body) {
		return
	}
	setupAttemptKey := "admin-setup-totp:" + ip + ":" + tokenHash(strings.TrimSpace(body.SetupToken))[:12]
	if !s.allowAttempt(setupAttemptKey, 10, 10*time.Minute) {
		writeError(w, http.StatusTooManyRequests, "setup_totp_throttled", "动态验证码尝试次数过多，请重新开始初始化")
		return
	}
	s.setupMu.Lock()
	flow := s.setupFlows[tokenHash(strings.TrimSpace(body.SetupToken))]
	if flow != nil && (flow.IP != ip || time.Now().After(flow.ExpiresAt)) {
		flow = nil
	}
	s.setupMu.Unlock()
	if flow == nil {
		writeError(w, http.StatusUnauthorized, "setup_session_invalid", "初始化会话无效或已过期")
		return
	}
	counter, ok := verifyTOTP(flow.Secret, body.Code, time.Now(), -1)
	if !ok {
		s.store.RecordSecurityEvent(r.Context(), ip, "admin_setup_totp_failed", r.URL.Path, "invalid TOTP code")
		writeError(w, http.StatusUnauthorized, "invalid_totp", "动态验证码错误")
		return
	}
	encrypted, err := s.vault.Encrypt(flow.Secret, "admin-totp")
	if err != nil {
		slog.Error("administrator setup TOTP encryption failed", "error", err)
		writeError(w, http.StatusInternalServerError, "setup_failed", "管理员初始化失败，请稍后重试")
		return
	}
	if err := s.store.CompleteAdminSetup(r.Context(), flow.Username, flow.PasswordHash, encrypted, counter); err != nil {
		if errors.Is(err, ErrAdminSetupClosed) {
			writeError(w, http.StatusConflict, "setup_closed", "管理员初始化已经完成")
			return
		}
		slog.Error("administrator setup persistence failed", "error", err)
		writeError(w, http.StatusInternalServerError, "setup_failed", "管理员初始化失败，请稍后重试")
		return
	}
	s.setupMu.Lock()
	// Setup is permanently complete. Destroy every outstanding candidate flow,
	// including hashes and TOTP seeds created by parallel/abandoned attempts.
	s.setupFlows = make(map[string]*adminSetupFlow)
	s.setupMu.Unlock()
	s.resetAttempts(setupAttemptKey)
	token, csrf, err := s.store.NewAdminSession(r.Context(), ip, s.cfg.SessionTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session_failed", "管理员已创建，请重新登录")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: adminCookieName, Value: token, Path: "/", HttpOnly: true, Secure: s.cfg.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: int(s.cfg.SessionTTL.Seconds())})
	s.store.Audit(r.Context(), "admin", "admin.setup.completed", flow.Username, ip, map[string]string{"totp": "Microsoft Authenticator"})
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "username": flow.Username, "csrf_token": csrf})
}

func (s *Server) adminChangePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
		Code            string `json:"totp_code"`
	}
	if !decodeJSON(w, r, 16<<10, &body) {
		return
	}
	if len(body.NewPassword) < 12 || len(body.NewPassword) > 256 || body.NewPassword == body.CurrentPassword {
		writeError(w, http.StatusBadRequest, "weak_password", "新密码必须为 12 到 256 位，且不能与当前密码相同")
		return
	}
	if err := s.store.ChangeAdminPassword(r.Context(), body.CurrentPassword, body.NewPassword, body.Code); err != nil {
		if errors.Is(err, ErrInvalidAdminCredentials) {
			s.store.RecordSecurityEvent(r.Context(), s.realIP(r), "admin_password_change_failed", r.URL.Path, "invalid current password or TOTP")
			writeError(w, http.StatusUnauthorized, "password_change_failed", "当前密码或动态验证码错误")
			return
		}
		slog.Error("administrator password change failed", "error", err)
		s.store.RecordSecurityEvent(r.Context(), s.realIP(r), "admin_password_change_failed", r.URL.Path, "password update transaction failed")
		writeError(w, http.StatusInternalServerError, "password_change_failed", "修改后台密码失败，请稍后重试")
		return
	}
	s.store.Audit(r.Context(), "admin", "admin.password.changed", s.store.AdminUsername(r.Context()), s.realIP(r), nil)
	http.SetCookie(w, expiredCookie(adminCookieName, s.cfg.SecureCookies))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func formatTOTPSecret(secret string) string {
	var groups []string
	for len(secret) > 4 {
		groups = append(groups, secret[:4])
		secret = secret[4:]
	}
	if secret != "" {
		groups = append(groups, secret)
	}
	return strings.Join(groups, " ")
}
