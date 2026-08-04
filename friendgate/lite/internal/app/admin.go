package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const adminCookieName = "friendgate_admin"

func (s *Server) adminHandler() http.Handler {
	root := http.NewServeMux()
	root.HandleFunc("GET /api/setup/status", s.adminSetupStatus)
	root.HandleFunc("POST /api/setup/start", s.adminSetupStart)
	root.HandleFunc("POST /api/setup/complete", s.adminSetupComplete)
	root.HandleFunc("POST /api/login", s.adminLogin)
	// Session discovery must remain public so a signed-out browser can render
	// the login screen without treating the expected state as an API error.
	// The handler only returns admin details after validating the bound session.
	root.HandleFunc("GET /api/me", s.adminMe)
	api := http.NewServeMux()
	api.HandleFunc("POST /api/logout", s.adminLogout)
	api.HandleFunc("GET /api/dashboard", s.adminDashboard)
	api.HandleFunc("GET /api/platform/overview", s.adminPlatformOverview)
	api.HandleFunc("GET /api/platform/dashboard", s.adminPlatformDashboard)
	api.HandleFunc("GET /api/platform/usage", s.adminListPlatformUsage)
	api.HandleFunc("GET /api/platform/wallets", s.adminListPlatformWallets)
	api.HandleFunc("POST /api/platform/users/{id}/wallets/{scope}/credit", s.adminCreditPlatformWallet)
	api.HandleFunc("GET /api/platform/audits", s.adminListPlatformAudits)
	api.HandleFunc("GET /api/platform/payments/providers", s.adminListPaymentProviders)
	api.HandleFunc("POST /api/platform/payments/providers", s.adminCreatePaymentProvider)
	api.HandleFunc("PATCH /api/platform/payments/providers/{id}", s.adminUpdatePaymentProvider)
	api.HandleFunc("GET /api/platform/payments/orders", s.adminListPaymentOrders)
	api.HandleFunc("POST /api/platform/legacy-import", s.adminPlatformLegacyImport)
	api.HandleFunc("GET /api/platform/models", s.adminListPlatformModels)
	api.HandleFunc("POST /api/platform/models", s.adminCreatePlatformModel)
	api.HandleFunc("PUT /api/platform/models/{id}", s.adminUpdatePlatformModel)
	api.HandleFunc("GET /api/platform/model-publications", s.adminListProductModelPublications)
	api.HandleFunc("PUT /api/platform/model-publications", s.adminUpsertProductModelPublication)
	api.HandleFunc("GET /api/platform/plans", s.adminListPlatformPlans)
	api.HandleFunc("PUT /api/platform/plans/{code}/version", s.adminReplacePlatformPlanVersion)
	api.HandleFunc("GET /api/platform/settings/registration", s.adminPlatformRegistrationMode)
	api.HandleFunc("PUT /api/platform/settings/registration", s.adminSetPlatformRegistrationMode)
	api.HandleFunc("GET /api/platform/users", s.adminListPlatformUsers)
	api.HandleFunc("PATCH /api/platform/users/{id}", s.adminUpdatePlatformUser)
	api.HandleFunc("GET /api/platform/devices", s.adminPlatformDevices)
	api.HandleFunc("DELETE /api/platform/devices/{id}", s.adminRevokePlatformDevice)
	api.HandleFunc("GET /api/platform/user-invitations", s.adminListPlatformInvitations)
	api.HandleFunc("POST /api/platform/user-invitations", s.adminCreatePlatformInvitation)
	api.HandleFunc("POST /api/platform/user-invitations/{id}/revoke", s.adminRevokePlatformInvitation)
	api.HandleFunc("DELETE /api/platform/user-invitations/{id}", s.adminDeletePlatformInvitation)
	api.HandleFunc("GET /api/platform/api-keys", s.adminListPlatformAPIKeys)
	api.HandleFunc("POST /api/platform/api-keys", s.adminCreatePlatformAPIKey)
	api.HandleFunc("POST /api/platform/api-keys/{id}/copy", s.adminCopyPlatformAPIKey)
	api.HandleFunc("PATCH /api/platform/api-keys/{id}", s.adminUpdatePlatformAPIKey)
	api.HandleFunc("DELETE /api/platform/api-keys/{id}", s.adminDeletePlatformAPIKey)
	api.HandleFunc("GET /api/platform/route-pools", s.adminListRoutePools)
	api.HandleFunc("POST /api/platform/route-pools", s.adminCreateRoutePool)
	api.HandleFunc("GET /api/platform/providers", s.adminListProviderConnections)
	api.HandleFunc("POST /api/platform/providers", s.adminCreateProviderConnection)
	api.HandleFunc("POST /api/platform/providers/{id}/health", s.adminTestProviderConnection)
	api.HandleFunc("PATCH /api/platform/providers/{id}", s.adminUpdateProviderConnection)
	api.HandleFunc("DELETE /api/platform/providers/{id}", s.adminDeleteProviderConnection)
	api.HandleFunc("GET /api/platform/upstream-accounts", s.adminListUpstreamAccounts)
	api.HandleFunc("POST /api/platform/upstream-accounts", s.adminCreateUpstreamAccount)
	api.HandleFunc("POST /api/platform/upstream-accounts/{id}/models/sync", s.adminSyncUpstreamAccountModels)
	api.HandleFunc("GET /api/platform/upstream-accounts/{id}/models", s.adminListUpstreamAccountModels)
	api.HandleFunc("PATCH /api/platform/upstream-accounts/{id}", s.adminUpdateUpstreamAccount)
	api.HandleFunc("DELETE /api/platform/upstream-accounts/{id}", s.adminDeleteUpstreamAccount)
	api.HandleFunc("POST /api/platform/route-pool-members", s.adminAddRoutePoolMember)
	api.HandleFunc("GET /api/platform/route-targets", s.adminListRouteTargets)
	api.HandleFunc("POST /api/platform/route-targets", s.adminCreateRouteTarget)
	api.HandleFunc("GET /api/accounts", s.adminListAccounts)
	api.HandleFunc("GET /api/accounts/models", s.adminAccountModels)
	api.HandleFunc("POST /api/accounts/models/refresh", s.adminRefreshAccountModels)
	api.HandleFunc("POST /api/accounts", s.adminCreateAccount)
	api.HandleFunc("POST /api/accounts/oauth/openai/start", s.adminStartOpenAIOAuth)
	api.HandleFunc("POST /api/accounts/oauth/openai/complete", s.adminCompleteOpenAIOAuth)
	api.HandleFunc("PATCH /api/accounts/{id}", s.adminUpdateAccount)
	api.HandleFunc("DELETE /api/accounts/{id}", s.adminDeleteAccount)
	api.HandleFunc("POST /api/accounts/{id}/quota/refresh", s.adminRefreshAccountQuota)
	api.HandleFunc("POST /api/accounts/{id}/quota/reset", s.adminResetAccountQuota)
	api.HandleFunc("GET /api/invitations", s.adminListInvitations)
	api.HandleFunc("POST /api/invitations", s.adminCreateInvitation)
	api.HandleFunc("DELETE /api/invitations/{id}", s.adminRevokeInvitation)
	api.HandleFunc("DELETE /api/invitations/{id}/permanent", s.adminDeleteInvitation)
	api.HandleFunc("GET /api/keys", s.adminListKeys)
	api.HandleFunc("PATCH /api/keys/{id}", s.adminUpdateKey)
	api.HandleFunc("DELETE /api/keys/{id}", s.adminDeleteKey)
	api.HandleFunc("POST /api/keys/{id}/copy", s.adminCopyKey)
	api.HandleFunc("POST /api/keys/{id}/ips", s.adminAddKeyIP)
	api.HandleFunc("DELETE /api/keys/{id}/ips/{ip_id}", s.adminDeleteKeyIP)
	api.HandleFunc("GET /api/system/logs", s.adminSystemLogs)
	api.HandleFunc("GET /api/system/usage", s.adminUsage)
	api.HandleFunc("GET /api/system/bans", s.adminBans)
	api.HandleFunc("POST /api/system/bans/{ip}/unban", s.adminUnban)
	api.HandleFunc("POST /api/system/bans", s.adminBanIP)
	api.HandleFunc("GET /api/system/security", s.adminSecurityStatus)
	api.HandleFunc("PUT /api/system/security", s.adminUpdateSecurity)
	api.HandleFunc("POST /api/system/security/nginx/baseline", s.adminNginxBaseline)
	api.HandleFunc("POST /api/system/password", s.adminChangePassword)
	api.HandleFunc("POST /api/system/backup/export", s.adminExportBackup)
	api.HandleFunc("POST /api/system/backup/import", s.adminImportBackup)
	api.HandleFunc("GET /api/desktop/users", s.adminDesktopUsers)
	api.HandleFunc("PATCH /api/desktop/users/{id}", s.adminUpdateDesktopUser)
	api.HandleFunc("GET /api/desktop/devices", s.adminDesktopDevices)
	api.HandleFunc("DELETE /api/desktop/devices/{id}", s.adminRevokeDesktopDevice)
	api.HandleFunc("GET /api/desktop/policy", s.adminDesktopPolicy)
	api.HandleFunc("PUT /api/desktop/policy", s.adminUpdateDesktopPolicy)
	root.Handle("/api/", s.adminOnly(api))
	root.Handle("/", s.staticHandler("admin.html"))
	return root
}

func (s *Server) adminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		required, ok := s.adminSetupState(w, r)
		if !ok {
			http.SetCookie(w, expiredCookie(adminCookieName, s.cfg.SecureCookies))
			return
		}
		if required {
			http.SetCookie(w, expiredCookie(adminCookieName, s.cfg.SecureCookies))
			writeError(w, http.StatusPreconditionRequired, "setup_required", "请先完成管理员创建与 Microsoft 2FA 绑定")
			return
		}
		cookie, err := r.Cookie(adminCookieName)
		ip := s.realIP(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "admin_auth_required", "请先登录")
			return
		}
		csrf, ok := s.store.AdminSession(r.Context(), cookie.Value, ip)
		if !ok {
			http.SetCookie(w, expiredCookie(adminCookieName, s.cfg.SecureCookies))
			writeError(w, http.StatusUnauthorized, "admin_session_expired", "登录已失效")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !sameOrigin(r) || r.Header.Get("X-CSRF-Token") == "" || subtleCompare(r.Header.Get("X-CSRF-Token"), csrf) != 1 {
				writeError(w, http.StatusForbidden, "csrf_failed", "安全校验失败，请刷新页面")
				return
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) adminLogin(w http.ResponseWriter, r *http.Request) {
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
	if required {
		writeError(w, http.StatusPreconditionRequired, "setup_required", "请先完成管理员创建与 Microsoft 2FA 绑定")
		return
	}
	if !s.allowAttempt("admin:"+ip, 8, 10*time.Minute) {
		s.store.Audit(r.Context(), "anonymous", "admin.login.throttled", "admin", ip, nil)
		writeError(w, http.StatusTooManyRequests, "too_many_attempts", "登录失败次数过多，请稍后再试")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTPCode string `json:"totp_code"`
	}
	if !decodeJSON(w, r, 16<<10, &body) {
		return
	}
	username := strings.TrimSpace(body.Username)
	accountAttemptKey := "admin-account:" + tokenHash(strings.ToLower(username))
	if !s.allowAttempt(accountAttemptKey, 8, 10*time.Minute) {
		s.store.Audit(r.Context(), "anonymous", "admin.login.throttled", "admin", ip, nil)
		writeError(w, http.StatusTooManyRequests, "too_many_attempts", "登录失败次数过多，请稍后再试")
		return
	}
	if !s.store.AuthenticateAdmin(r.Context(), username, body.Password, body.TOTPCode) {
		s.store.Audit(r.Context(), "anonymous", "admin.login.failed", "admin", ip, nil)
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "账号、密码或动态验证码错误")
		return
	}
	s.resetAttempts("admin:" + ip)
	s.resetAttempts(accountAttemptKey)
	token, csrf, err := s.store.NewAdminSession(r.Context(), ip, s.cfg.SessionTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session_failed", "无法创建登录会话")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: adminCookieName, Value: token, Path: "/", HttpOnly: true, Secure: s.cfg.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: int(s.cfg.SessionTTL.Seconds())})
	s.store.Audit(r.Context(), "admin", "admin.login.succeeded", "admin", ip, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "csrf_token": csrf})
}

func (s *Server) adminMe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	required, ok := s.adminSetupState(w, r)
	if !ok {
		http.SetCookie(w, expiredCookie(adminCookieName, s.cfg.SecureCookies))
		return
	}
	if required {
		http.SetCookie(w, expiredCookie(adminCookieName, s.cfg.SecureCookies))
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false, "setup_required": true})
		return
	}
	cookie, err := r.Cookie(adminCookieName)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false, "setup_required": false})
		return
	}
	csrf, ok := s.store.AdminSession(r.Context(), cookie.Value, s.realIP(r))
	if !ok {
		http.SetCookie(w, expiredCookie(adminCookieName, s.cfg.SecureCookies))
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false, "setup_required": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"username":      s.store.AdminUsername(r.Context()),
		"csrf_token":    csrf,
	})
}

func (s *Server) adminLogout(w http.ResponseWriter, r *http.Request) {
	var deleteErr error
	if cookie, err := r.Cookie(adminCookieName); err == nil {
		deleteErr = s.store.DeleteAdminSession(r.Context(), cookie.Value)
	}
	http.SetCookie(w, expiredCookie(adminCookieName, s.cfg.SecureCookies))
	if deleteErr != nil {
		slog.Error("administrator logout persistence failed", "error", deleteErr)
		writeError(w, http.StatusServiceUnavailable, "logout_failed", "客户端登录信息已清除，但服务端会话撤销失败，请立即重试")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func expiredCookie(name string, secure bool) *http.Cookie {
	return &http.Cookie{Name: name, Value: "", Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0)}
}

func (s *Server) adminDashboard(w http.ResponseWriter, r *http.Request) {
	result, err := s.store.Dashboard(r.Context())
	if err != nil {
		writeError(w, 500, "database_error", "读取概览失败")
		return
	}
	result["system"] = s.systemMetrics()
	writeJSON(w, 200, result)
}

func (s *Server) adminListAccounts(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListAccounts(r.Context())
	if err != nil {
		writeError(w, 500, "database_error", "读取账号失败")
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) adminCreateAccount(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string          `json:"name"`
		Auth json.RawMessage `json:"auth"`
	}
	if !decodeJSON(w, r, 2<<20, &body) {
		return
	}
	account, err := parseAuthJSON(body.Auth)
	if err != nil {
		writeError(w, 400, "invalid_auth", err.Error())
		return
	}
	account.Name = strings.TrimSpace(body.Name)
	if account.Name == "" || len(account.Name) > 100 {
		writeError(w, 400, "invalid_name", "账号名称为必填项，且不能超过100字")
		return
	}
	id, err := s.store.CreateAccount(r.Context(), account)
	if err != nil {
		writeError(w, 500, "create_failed", "保存账号失败")
		return
	}
	s.store.Audit(r.Context(), "admin", "account.created", strconv.FormatInt(id, 10), s.realIP(r), map[string]any{"name": account.Name, "chatgpt_account_id": account.ChatGPTAccountID})
	go s.syncNewAccountMetadata(id)
	writeJSON(w, 201, map[string]any{"id": id})
}

// adminStartOpenAIOAuth follows the official Codex copy-and-paste flow. The
// browser may be on a different machine from this server: it only needs to
// return the localhost URL shown after authorization to this admin page.
func (s *Server) adminStartOpenAIOAuth(w http.ResponseWriter, r *http.Request) {
	if !s.allowAttempt("openai-oauth:"+s.realIP(r), 20, 10*time.Minute) {
		writeError(w, http.StatusTooManyRequests, "oauth_throttled", "生成授权链接过于频繁，请稍后再试")
		return
	}
	cookie, err := r.Cookie(adminCookieName)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "admin_auth_required", "请先登录")
		return
	}
	sessionID, authURL, expiresAt, err := s.startOpenAIOAuth(tokenHash(cookie.Value), s.realIP(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "oauth_start_failed", "无法生成 OpenAI 授权链接")
		return
	}
	s.store.Audit(r.Context(), "admin", "account.oauth.started", "openai", s.realIP(r), nil)
	writeJSON(w, http.StatusOK, map[string]any{"session_id": sessionID, "auth_url": authURL, "redirect_uri": openAIOAuthRedirectURI, "expires_at": expiresAt})
}

func (s *Server) adminCompleteOpenAIOAuth(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SessionID   string `json:"session_id"`
		CallbackURL string `json:"callback_url"`
		Name        string `json:"name"`
	}
	if !decodeJSON(w, r, 32<<10, &body) {
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > 100 {
		writeError(w, http.StatusBadRequest, "invalid_name", "账号名称为必填项，且不能超过100字")
		return
	}
	code, callbackState, err := parseOpenAICallback(body.CallbackURL)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_callback", err.Error())
		return
	}
	cookie, err := r.Cookie(adminCookieName)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "admin_auth_required", "请先登录")
		return
	}
	flow, err := s.beginOpenAIOAuth(strings.TrimSpace(body.SessionID), callbackState, tokenHash(cookie.Value), s.realIP(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, "oauth_session_invalid", err.Error())
		return
	}
	account, err := s.exchangeOpenAIOAuth(r.Context(), code, flow)
	if err != nil {
		s.releaseOpenAIOAuth(flow.SessionID)
		writeError(w, http.StatusBadGateway, "oauth_exchange_failed", err.Error())
		return
	}
	account.Name = name
	id, err := s.store.CreateAccount(r.Context(), account)
	if err != nil {
		s.releaseOpenAIOAuth(flow.SessionID)
		writeError(w, http.StatusInternalServerError, "create_failed", "保存 ChatGPT 账号失败")
		return
	}
	s.consumeOpenAIOAuth(flow.SessionID)
	s.store.Audit(r.Context(), "admin", "account.oauth.created", strconv.FormatInt(id, 10), s.realIP(r), map[string]any{"name": account.Name, "chatgpt_account_id": account.ChatGPTAccountID})
	go s.syncNewAccountMetadata(id)
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "chatgpt_account_id": account.ChatGPTAccountID})
}

func (s *Server) adminRefreshAccountQuota(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, 400, "invalid_id", "账号编号无效")
		return
	}
	snapshot, err := s.syncAccountQuota(r.Context(), id)
	if err != nil {
		s.store.MarkAccountQuotaError(context.Background(), id, err.Error())
		writeError(w, 502, "quota_refresh_failed", "自动读取 ChatGPT 额度失败")
		return
	}
	s.store.Audit(r.Context(), "admin", "account.quota.refreshed", strconv.FormatInt(id, 10), s.realIP(r), nil)
	writeJSON(w, 200, snapshot)
}

func (s *Server) adminResetAccountQuota(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, 400, "invalid_id", "账号编号无效")
		return
	}
	result, err := s.resetAccountQuota(r.Context(), id)
	if err != nil {
		writeError(w, 502, "quota_reset_failed", "ChatGPT 额度重置失败或没有可用重置次数")
		return
	}
	s.store.Audit(r.Context(), "admin", "account.quota.reset", strconv.FormatInt(id, 10), s.realIP(r), result)
	writeJSON(w, 200, result)
}

func (s *Server) adminUpdateAccount(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, 400, "invalid_id", "账号编号无效")
		return
	}
	var body struct {
		Active bool `json:"active"`
	}
	if !decodeJSON(w, r, 16<<10, &body) {
		return
	}
	cancelled, err := s.updateAccountState(r.Context(), id, body.Active)
	if err != nil {
		if errors.Is(err, ErrRequestDrainTimeout) {
			writeError(w, http.StatusGatewayTimeout, "request_drain_timeout", "账号已停用，但等待旧请求退出超时")
		} else if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "账号不存在")
		} else {
			slog.Error("account state update failed", "account_id", id, "error", err)
			writeError(w, http.StatusInternalServerError, "update_failed", "更新账号状态失败")
		}
		return
	}
	s.store.Audit(r.Context(), "admin", "account.updated", strconv.FormatInt(id, 10), s.realIP(r), map[string]any{
		"active": body.Active, "cancelled_requests": cancelled,
	})
	writeJSON(w, 200, map[string]any{"ok": true, "cancelled_requests": cancelled})
	if body.Active {
		go s.syncNewAccountMetadata(id)
	}
}

func (s *Server) adminListInvitations(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListInvitations(r.Context())
	if err != nil {
		writeError(w, 500, "database_error", "读取邀请失败")
		return
	}
	for i := range items {
		if items[i].Status == "pending" && items[i].ExpiresAt <= time.Now().Unix() {
			items[i].Status = "expired"
		}
		if items[i].Token != "" && items[i].Status == "pending" {
			items[i].InviteURL = s.cfg.PublicInviteURL + "/?invite=" + items[i].Token
		}
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) adminCreateInvitation(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Role            string `json:"role"`
		RecognitionCode string `json:"recognition_code"`
		QuotaRequests   int64  `json:"quota_requests"`
		ExpiresHours    int    `json:"expires_hours"`
		BindingMode     string `json:"binding_mode"`
	}
	if !decodeJSON(w, r, 32<<10, &body) {
		return
	}
	body.Role = strings.TrimSpace(body.Role)
	if body.Role == "" || len(body.Role) > 100 {
		writeError(w, 400, "invalid_role", "角色名称为必填项，且不能超过100字")
		return
	}
	if body.QuotaRequests < 0 {
		writeError(w, 400, "invalid_quota", "额度不能小于0")
		return
	}
	if body.BindingMode == "" {
		body.BindingMode = "ip"
	}
	if body.BindingMode != "ip" && body.BindingMode != "device" && body.BindingMode != "ip_device" {
		writeError(w, http.StatusBadRequest, "invalid_binding_mode", "绑定方式必须是 IP、设备凭证或 IP + 设备凭证")
		return
	}
	code := strings.TrimSpace(body.RecognitionCode)
	if code == "" {
		var err error
		code, err = randomDigits(6)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "random_failed", "创建邀请失败")
			return
		}
	}
	if len(code) < 6 || len(code) > 32 {
		writeError(w, 400, "invalid_code", "识别码长度必须为6到32位")
		return
	}
	token, err := randomToken(24)
	if err != nil {
		writeError(w, 500, "random_failed", "创建邀请失败")
		return
	}
	ttl := s.cfg.InviteTTL
	if body.ExpiresHours > 0 && body.ExpiresHours <= 720 {
		ttl = time.Duration(body.ExpiresHours) * time.Hour
	}
	expires := time.Now().Add(ttl).Unix()
	id, err := s.store.CreateInvitationWithBinding(r.Context(), body.Role, token, code, 0, body.QuotaRequests, expires, body.BindingMode)
	if err != nil {
		slog.Error("invitation creation failed", "error", err)
		writeError(w, http.StatusInternalServerError, "create_failed", "创建邀请失败")
		return
	}
	inviteURL := s.cfg.PublicInviteURL + "/?invite=" + token
	s.store.Audit(r.Context(), "admin", "invitation.created", strconv.FormatInt(id, 10), s.realIP(r), map[string]any{"role": body.Role, "routing": "account_pool", "quota_requests": body.QuotaRequests, "binding_mode": body.BindingMode})
	writeJSON(w, 201, map[string]any{"id": id, "role": body.Role, "invite_url": inviteURL, "recognition_code": code, "binding_mode": body.BindingMode, "expires_at": expires})
}

func (s *Server) adminRevokeInvitation(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, 400, "invalid_id", "邀请编号无效")
		return
	}
	if err := s.revokeInvitation(r.Context(), id); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "邀请不存在或已使用")
		} else {
			slog.Error("invitation revoke failed", "invitation_id", id, "error", err)
			writeError(w, http.StatusInternalServerError, "revoke_failed", "撤销邀请失败")
		}
		return
	}
	s.store.Audit(r.Context(), "admin", "invitation.revoked", strconv.FormatInt(id, 10), s.realIP(r), nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) adminDeleteInvitation(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, 400, "invalid_id", "邀请编号无效")
		return
	}
	if err := s.deleteInvitation(r.Context(), id); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusConflict, "invitation_not_terminal", "邀请不存在，或尚未使用、撤销、过期")
		} else {
			slog.Error("invitation deletion failed", "invitation_id", id, "error", err)
			writeError(w, http.StatusInternalServerError, "delete_failed", "删除邀请记录失败")
		}
		return
	}
	s.store.Audit(r.Context(), "admin", "invitation.deleted", strconv.FormatInt(id, 10), s.realIP(r), nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) adminListKeys(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListAPIKeys(r.Context())
	if err != nil {
		writeError(w, 500, "database_error", "读取密钥失败")
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (s *Server) adminUpdateKey(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, 400, "invalid_id", "密钥编号无效")
		return
	}
	var body struct {
		Status        string `json:"status"`
		QuotaRequests int64  `json:"quota_requests"`
	}
	if !decodeJSON(w, r, 16<<10, &body) {
		return
	}
	if (body.Status != "active" && body.Status != "disabled") || body.QuotaRequests < 0 {
		writeError(w, http.StatusBadRequest, "update_failed", "密钥状态或额度无效")
		return
	}
	cancelled, err := s.updateAPIKeyState(r.Context(), id, body.Status, body.QuotaRequests)
	if err != nil {
		if errors.Is(err, ErrRequestDrainTimeout) {
			writeError(w, http.StatusGatewayTimeout, "request_drain_timeout", "密钥状态已更新且新请求已被拒绝，但等待旧请求退出超时")
		} else if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "密钥不存在或已经删除")
		} else {
			slog.Error("API key update failed", "key_id", id, "error", err)
			writeError(w, http.StatusInternalServerError, "update_failed", "更新密钥失败")
		}
		return
	}
	s.store.Audit(r.Context(), "admin", "key.updated", strconv.FormatInt(id, 10), s.realIP(r), map[string]any{"status": body.Status, "quota_requests": body.QuotaRequests, "cancelled_requests": cancelled})
	writeJSON(w, 200, map[string]any{"ok": true, "cancelled_requests": cancelled})
}
func (s *Server) adminCopyKey(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, 400, "invalid_id", "密钥编号无效")
		return
	}
	// Hold the same lifecycle lock through the plaintext response write. Thus a
	// concurrent delete cannot return success and then let an older copy reveal
	// the deleted secret afterwards.
	s.keyRequestMu.Lock()
	key, err := s.store.CopyAPIKey(r.Context(), id)
	if err != nil {
		s.keyRequestMu.Unlock()
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "密钥不存在")
		} else {
			slog.Error("API key copy failed", "key_id", id, "error", err)
			writeError(w, http.StatusInternalServerError, "copy_failed", "读取密钥失败")
		}
		return
	}
	func() {
		defer s.keyRequestMu.Unlock()
		writeJSON(w, 200, map[string]string{"key": key})
	}()
	s.store.Audit(r.Context(), "admin", "key.copied", strconv.FormatInt(id, 10), s.realIP(r), nil)
}

func (s *Server) adminDeleteKey(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "密钥编号无效")
		return
	}
	cancelled, err := s.deleteAPIKey(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrRequestDrainTimeout) {
			writeError(w, http.StatusGatewayTimeout, "request_drain_timeout", "密钥已删除且密文已销毁，但等待旧请求退出超时")
		} else if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "密钥不存在或已经删除")
		} else {
			slog.Error("API key deletion failed", "key_id", id, "error", err)
			writeError(w, http.StatusInternalServerError, "delete_failed", "删除密钥失败")
		}
		return
	}
	s.store.Audit(r.Context(), "admin", "key.deleted", strconv.FormatInt(id, 10), s.realIP(r), map[string]any{"effect": "secret/ip_acl/affinity_destroyed", "cancelled_requests": cancelled})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cancelled_requests": cancelled})
}
func (s *Server) adminAddKeyIP(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, 400, "invalid_id", "密钥编号无效")
		return
	}
	var body struct {
		IP         string `json:"ip"`
		DeviceNote string `json:"device_note"`
	}
	if !decodeJSON(w, r, 16<<10, &body) {
		return
	}
	parsed, err := netip.ParseAddr(strings.TrimSpace(body.IP))
	if err != nil {
		writeError(w, 400, "invalid_ip", "IP地址无效")
		return
	}
	body.IP = parsed.Unmap().String()
	body.DeviceNote = strings.TrimSpace(body.DeviceNote)
	if body.DeviceNote == "" || len(body.DeviceNote) > 100 {
		writeError(w, 400, "invalid_note", "设备备注为必填项，且不能超过100字")
		return
	}
	if err := s.store.AddKeyIP(r.Context(), id, body.IP, body.DeviceNote); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "密钥不存在或已经删除")
		} else {
			slog.Error("API key IP addition failed", "key_id", id, "error", err)
			writeError(w, http.StatusInternalServerError, "add_failed", "添加授权 IP 失败")
		}
		return
	}
	s.store.Audit(r.Context(), "admin", "key.ip.added", fmt.Sprintf("%d/%s", id, body.IP), s.realIP(r), map[string]string{"device_note": body.DeviceNote})
	writeJSON(w, 201, map[string]bool{"ok": true})
}
func (s *Server) adminDeleteKeyIP(w http.ResponseWriter, r *http.Request) {
	keyID, e1 := parseID(r.PathValue("id"))
	ipID, e2 := parseID(r.PathValue("ip_id"))
	if e1 != nil || e2 != nil {
		writeError(w, 400, "invalid_id", "编号无效")
		return
	}
	cancelled, err := s.deleteKeyIP(r.Context(), keyID, ipID)
	if err != nil {
		if errors.Is(err, ErrRequestDrainTimeout) {
			writeError(w, http.StatusGatewayTimeout, "request_drain_timeout", "IP 授权已删除且新请求已被拒绝，但等待旧请求退出超时")
		} else if errors.Is(err, ErrNotFound) {
			writeError(w, 404, "not_found", "授权IP不存在")
		} else {
			slog.Error("API key IP deletion failed", "key_id", keyID, "ip_id", ipID, "error", err)
			writeError(w, http.StatusInternalServerError, "delete_failed", "删除授权 IP 失败")
		}
		return
	}
	s.store.Audit(r.Context(), "admin", "key.ip.deleted", fmt.Sprintf("%d/%d", keyID, ipID), s.realIP(r), map[string]int{"cancelled_requests": cancelled})
	writeJSON(w, 200, map[string]any{"ok": true, "cancelled_requests": cancelled})
}

func (s *Server) adminSystemLogs(w http.ResponseWriter, r *http.Request) {
	audits, err := s.store.ListAudits(r.Context(), 300)
	if err != nil {
		writeError(w, 500, "database_error", "读取日志失败")
		return
	}
	security, err := s.store.ListSecurityEvents(r.Context(), 300)
	if err != nil {
		writeError(w, 500, "database_error", "读取日志失败")
		return
	}
	writeJSON(w, 200, map[string]any{"audit": audits, "security": security})
}
func (s *Server) adminUsage(w http.ResponseWriter, r *http.Request) {
	limit := 500
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, parseErr := strconv.Atoi(raw)
		if parseErr != nil || parsed < 1 || parsed > 500 {
			writeError(w, http.StatusBadRequest, "invalid_limit", "使用记录条数必须在 1 到 500 之间")
			return
		}
		limit = parsed
	}
	items, err := s.store.ListUsage(r.Context(), limit)
	if err != nil {
		writeError(w, 500, "database_error", "读取使用记录失败")
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (s *Server) adminBans(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListBans(r.Context())
	if err != nil {
		writeError(w, 500, "database_error", "读取封禁列表失败")
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (s *Server) adminUnban(w http.ResponseWriter, r *http.Request) {
	raw, err := base64.RawURLEncoding.DecodeString(r.PathValue("ip"))
	if err != nil {
		writeError(w, 400, "invalid_ip", "IP参数无效")
		return
	}
	ip := string(raw)
	if _, err := netip.ParseAddr(ip); err != nil {
		writeError(w, 400, "invalid_ip", "IP参数无效")
		return
	}
	s.banSyncMu.Lock()
	removedIPs, err := s.store.UnbanMembers(r.Context(), ip)
	if err != nil {
		s.banSyncMu.Unlock()
		writeError(w, 500, "unban_failed", "解除封禁失败")
		return
	}
	// Remove the exact durable group before releasing the synchronization mutex,
	// so no older full-cache snapshot can reintroduce it after this response.
	s.removeBanMembersLocked(removedIPs)
	s.banSyncMu.Unlock()
	cacheDegraded := s.refreshBanCache(r.Context()) != nil
	s.store.Audit(r.Context(), "admin", "ip.unbanned", ip, s.realIP(r), map[string]any{"cache_degraded": cacheDegraded})
	writeJSON(w, 200, map[string]any{"ok": true, "unbanned_ips": removedIPs, "cache_degraded": cacheDegraded})
}

func randomDigits(length int) (string, error) {
	const digits = "0123456789"
	result := make([]byte, length)
	for i := range result {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		result[i] = digits[n.Int64()]
	}
	return string(result), nil
}

func parseAuthJSON(raw json.RawMessage) (Account, error) {
	if len(raw) == 0 {
		return Account{}, errors.New("请粘贴 Codex auth.json 内容")
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return Account{}, errors.New("auth.json 不是有效 JSON")
	}
	access := firstString(root, "access_token", "tokens.access_token", "auth.access_token", "credentials.access_token")
	refresh := firstString(root, "refresh_token", "tokens.refresh_token", "auth.refresh_token", "credentials.refresh_token")
	idToken := firstString(root, "id_token", "tokens.id_token", "auth.id_token", "credentials.id_token")
	accountID := firstString(root, "chatgpt_account_id", "account_id", "tokens.chatgpt_account_id", "tokens.account_id", "credentials.chatgpt_account_id")
	clientID := firstString(root, "client_id", "tokens.client_id", "credentials.client_id")
	if clientID == "" {
		clientID = "app_EMoamEEZ73f0CkXaXp7hrann"
	}
	if access == "" {
		return Account{}, errors.New("auth.json 中缺少 access_token")
	}
	derived, exp := jwtAccountAndExpiry(idToken)
	if derived == "" {
		derived, exp = jwtAccountAndExpiry(access)
	}
	if accountID == "" {
		accountID = derived
	} else if derived != "" && derived != accountID {
		return Account{}, errors.New("auth.json 的 account_id 与令牌不一致")
	}
	if accountID == "" {
		return Account{}, errors.New("auth.json 中缺少 account_id，且无法从令牌解析")
	}
	return Account{AccessToken: access, RefreshToken: refresh, ChatGPTAccountID: accountID, ClientID: clientID, ExpiresAt: exp}, nil
}

func firstString(root map[string]any, paths ...string) string {
	for _, path := range paths {
		var current any = root
		for _, part := range strings.Split(path, ".") {
			object, ok := current.(map[string]any)
			if !ok {
				current = nil
				break
			}
			current = object[part]
		}
		if value, ok := current.(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func jwtAccountAndExpiry(token string) (string, int64) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", 0
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", 0
	}
	var claims map[string]any
	if json.Unmarshal(payload, &claims) != nil {
		return "", 0
	}
	accountID := firstString(claims, "chatgpt_account_id", "account_id")
	if nested, ok := claims["https://api.openai.com/auth"].(map[string]any); ok && accountID == "" {
		accountID = firstString(nested, "chatgpt_account_id", "account_id")
	}
	var exp int64
	if value, ok := claims["exp"].(float64); ok {
		exp = int64(value)
	}
	return accountID, exp
}
