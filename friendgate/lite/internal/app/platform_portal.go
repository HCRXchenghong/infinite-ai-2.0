package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// This cookie belongs solely to PostgreSQL product users. It intentionally
// differs from the legacy desktop-bridge cookie so browsers cannot replay a
// session from one authority against the other during the migration.
const platformUserCookieName = "infinite_ai_user"

const platformPortalMaxBufferedResponseBytes int64 = 64 << 20

func (s *Server) platformPortalOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		platform := s.store.Platform()
		if platform == nil {
			writeError(w, http.StatusServiceUnavailable, "platform_unavailable", "统一用户系统尚未就绪")
			return
		}
		cookie, err := r.Cookie(platformUserCookieName)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "user_auth_required", "请先登录")
			return
		}
		if _, err := platform.PlatformUserSession(r.Context(), cookie.Value, s.realIP(r), r.UserAgent()); err != nil {
			http.SetCookie(w, expiredCookie(platformUserCookieName, s.cfg.SecureCookies))
			writeError(w, http.StatusUnauthorized, "user_session_expired", "网页登录已失效")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !sameOrigin(r) || r.Header.Get("X-CSRF-Token") == "" || !platform.VerifyPlatformCSRF(r.Context(), cookie.Value, r.Header.Get("X-CSRF-Token")) {
				writeError(w, http.StatusForbidden, "csrf_failed", "安全校验失败")
				return
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) platformPortalConfig(w http.ResponseWriter, r *http.Request) {
	platform := s.store.Platform()
	if platform == nil {
		writeError(w, http.StatusServiceUnavailable, "platform_unavailable", "统一用户系统尚未就绪")
		return
	}
	mode, err := platform.RegistrationMode(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "registration_unavailable", "读取注册策略失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"registration_mode":    mode,
		"registration_enabled": mode != RegistrationClosed,
		"invitation_required":  mode == RegistrationInviteOnly,
		"brand":                "Infinite AI",
		"product_authority":    "postgresql",
	})
}

func (s *Server) platformPortalRegister(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "origin_rejected", "请求来源不受信任")
		return
	}
	ip := s.realIP(r)
	if !s.allowAttempt("platform-portal-register:"+ip, 6, time.Hour) {
		writeError(w, http.StatusTooManyRequests, "registration_throttled", "注册请求过于频繁")
		return
	}
	var input PlatformUserRegistration
	if !decodeJSON(w, r, 24<<10, &input) {
		return
	}
	accountAttemptKey := "platform-portal-register-account:" + tokenHash(normalizePlatformEmail(input.Email))
	if !s.allowAttempt(accountAttemptKey, 6, time.Hour) {
		writeError(w, http.StatusTooManyRequests, "registration_throttled", "注册请求过于频繁")
		return
	}
	platform := s.store.Platform()
	if platform == nil {
		writeError(w, http.StatusServiceUnavailable, "platform_unavailable", "统一用户系统尚未就绪")
		return
	}
	user, err := platform.RegisterUser(r.Context(), input)
	if err != nil {
		switch {
		case errors.Is(err, ErrRegistrationClosed):
			writeError(w, http.StatusForbidden, "registration_closed", "当前未开放注册")
		case errors.Is(err, ErrRegistrationInvite), errors.Is(err, ErrPlatformInviteInvalid):
			writeError(w, http.StatusForbidden, "invitation_required", "需要有效且未使用的用户邀请")
		case errors.Is(err, ErrInvalidPlatformModel):
			writeError(w, http.StatusBadRequest, "invalid_registration", "邮箱、昵称或密码不符合要求")
		default:
			// PostgreSQL's unique error is intentionally not surfaced as an
			// account-enumeration oracle. The public result is the same safe
			// conflict for an existing address and a transient duplicate attempt.
			writeError(w, http.StatusConflict, "registration_unavailable", "该邮箱无法完成注册")
		}
		return
	}
	s.resetAttempts("platform-portal-register:" + ip)
	s.resetAttempts(accountAttemptKey)
	token, csrf, err := platform.NewPlatformUserSession(r.Context(), user.ID, ip, r.UserAgent(), s.cfg.UserSessionTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session_failed", "无法创建网页登录")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: platformUserCookieName, Value: token, Path: "/", HttpOnly: true, Secure: s.cfg.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: int(s.cfg.UserSessionTTL.Seconds())})
	writeJSON(w, http.StatusCreated, map[string]any{"authenticated": true, "user": user, "csrf_token": csrf})
}

func (s *Server) platformPortalLogin(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "origin_rejected", "请求来源不受信任")
		return
	}
	ip := s.realIP(r)
	if !s.allowAttempt("platform-portal-login:"+ip, 8, 10*time.Minute) {
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
	accountAttemptKey := "platform-portal-login-account:" + tokenHash(normalizePlatformEmail(body.Email))
	if !s.allowAttempt(accountAttemptKey, 8, 10*time.Minute) {
		writeError(w, http.StatusTooManyRequests, "login_throttled", "登录失败次数过多")
		return
	}
	platform := s.store.Platform()
	if platform == nil {
		writeError(w, http.StatusServiceUnavailable, "platform_unavailable", "统一用户系统尚未就绪")
		return
	}
	user, err := platform.AuthenticateUser(r.Context(), body.Email, body.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "邮箱或密码错误，或账号已停用")
		return
	}
	s.resetAttempts("platform-portal-login:" + ip)
	s.resetAttempts(accountAttemptKey)
	token, csrf, err := platform.NewPlatformUserSession(r.Context(), user.ID, ip, r.UserAgent(), s.cfg.UserSessionTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session_failed", "无法创建网页登录")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: platformUserCookieName, Value: token, Path: "/", HttpOnly: true, Secure: s.cfg.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: int(s.cfg.UserSessionTTL.Seconds())})
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "user": user, "csrf_token": csrf})
}

func (s *Server) platformPortalMe(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(platformUserCookieName)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
		return
	}
	platform := s.store.Platform()
	if platform == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]bool{"authenticated": false})
		return
	}
	user, err := platform.PlatformUserSession(r.Context(), cookie.Value, s.realIP(r), r.UserAgent())
	if err != nil {
		http.SetCookie(w, expiredCookie(platformUserCookieName, s.cfg.SecureCookies))
		writeJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
		return
	}
	csrf, err := platform.RotatePlatformUserCSRF(r.Context(), cookie.Value, s.realIP(r), r.UserAgent())
	if err != nil {
		http.SetCookie(w, expiredCookie(platformUserCookieName, s.cfg.SecureCookies))
		writeJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "user": user, "csrf_token": csrf})
}

func (s *Server) platformPortalLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(platformUserCookieName); err == nil {
		if platform := s.store.Platform(); platform != nil {
			_ = platform.RevokePlatformUserSession(r.Context(), cookie.Value)
			if _, cancelErr := s.cancelPlatformUserSessionRequests(r.Context(), cookie.Value); cancelErr != nil {
				s.setSecurityRuntimeFailure("platform_user_logout_cancel", cancelErr)
			}
		}
	}
	http.SetCookie(w, expiredCookie(platformUserCookieName, s.cfg.SecureCookies))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) platformPortalModels(w http.ResponseWriter, r *http.Request) {
	platform := s.store.Platform()
	if platform == nil {
		writeError(w, http.StatusServiceUnavailable, "platform_unavailable", "统一用户系统尚未就绪")
		return
	}
	cookie, err := r.Cookie(platformUserCookieName)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "user_auth_required", "请先登录")
		return
	}
	user, err := platform.PlatformUserSession(r.Context(), cookie.Value, s.realIP(r), r.UserAgent())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "user_session_expired", "网页登录已失效")
		return
	}
	items, err := platform.ListPlatformProductModelsForUser(r.Context(), user.ID, ProductScopeChat, "responses")
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "models_unavailable", "模型目录暂不可用")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) platformPortalAuthenticatedUser(w http.ResponseWriter, r *http.Request) (*PlatformStore, *PlatformUser, bool) {
	platform := s.store.Platform()
	if platform == nil {
		writeError(w, http.StatusServiceUnavailable, "platform_unavailable", "统一用户系统尚未就绪")
		return nil, nil, false
	}
	cookie, err := r.Cookie(platformUserCookieName)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "user_auth_required", "请先登录")
		return nil, nil, false
	}
	user, err := platform.PlatformUserSession(r.Context(), cookie.Value, s.realIP(r), r.UserAgent())
	if err != nil {
		http.SetCookie(w, expiredCookie(platformUserCookieName, s.cfg.SecureCookies))
		writeError(w, http.StatusUnauthorized, "user_session_expired", "网页登录已失效")
		return nil, nil, false
	}
	return platform, user, true
}

func (s *Server) platformPortalChatConversations(w http.ResponseWriter, r *http.Request) {
	platform, user, ok := s.platformPortalAuthenticatedUser(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		limit := 50
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 1 || parsed > 200 {
				writeError(w, http.StatusBadRequest, "invalid_limit", "会话数量必须在 1 到 200 之间")
				return
			}
			limit = parsed
		}
		items, err := platform.ListPlatformChatConversations(r.Context(), user.ID, limit)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "chat_history_unavailable", "读取 Chat 会话失败")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		var input PlatformChatConversationInput
		if !decodeJSON(w, r, 16<<10, &input) {
			return
		}
		if strings.TrimSpace(input.SelectedModelKey) != "" {
			model, err := platform.ResolvePlatformProductModelForUser(r.Context(), user.ID, ProductScopeChat, "responses", input.SelectedModelKey)
			if err != nil {
				if errors.Is(err, ErrPlatformModelDenied) {
					writeError(w, http.StatusNotFound, "model_not_found", "该模型不在当前 Chat 套餐的可用目录中")
					return
				}
				writeError(w, http.StatusServiceUnavailable, "model_catalog_unavailable", "平台模型目录暂不可用")
				return
			}
			input.SelectedModelKey = model.ModelKey
		}
		conversation, err := platform.CreatePlatformChatConversation(r.Context(), user.ID, input)
		if err != nil {
			if errors.Is(err, ErrInvalidPlatformModel) {
				writeError(w, http.StatusBadRequest, "invalid_conversation", "会话标题或模型无效")
				return
			}
			writeError(w, http.StatusServiceUnavailable, "chat_history_unavailable", "创建 Chat 会话失败")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"conversation": conversation, "messages": []PlatformChatMessage{}})
	default:
		w.Header().Set("Allow", strings.Join([]string{http.MethodGet, http.MethodPost}, ", "))
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "请求方法不允许")
	}
}

func (s *Server) platformPortalChatConversation(w http.ResponseWriter, r *http.Request) {
	platform, user, ok := s.platformPortalAuthenticatedUser(w, r)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeError(w, http.StatusNotFound, "conversation_not_found", "会话不存在")
		return
	}
	switch r.Method {
	case http.MethodGet:
		conversation, messages, err := platform.PlatformChatConversation(r.Context(), user.ID, id)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				writeError(w, http.StatusNotFound, "conversation_not_found", "会话不存在")
				return
			}
			writeError(w, http.StatusServiceUnavailable, "chat_history_unavailable", "读取 Chat 会话失败")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"conversation": conversation, "messages": messages})
	case http.MethodPatch:
		var patch PlatformChatConversationPatch
		if !decodeJSON(w, r, 16<<10, &patch) {
			return
		}
		if patch.SelectedModelKey != nil && strings.TrimSpace(*patch.SelectedModelKey) != "" {
			model, err := platform.ResolvePlatformProductModelForUser(r.Context(), user.ID, ProductScopeChat, "responses", *patch.SelectedModelKey)
			if err != nil {
				if errors.Is(err, ErrPlatformModelDenied) {
					writeError(w, http.StatusNotFound, "model_not_found", "该模型不在当前 Chat 套餐的可用目录中")
					return
				}
				writeError(w, http.StatusServiceUnavailable, "model_catalog_unavailable", "平台模型目录暂不可用")
				return
			}
			value := model.ModelKey
			patch.SelectedModelKey = &value
		}
		conversation, err := platform.UpdatePlatformChatConversation(r.Context(), user.ID, id, patch)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				writeError(w, http.StatusNotFound, "conversation_not_found", "会话不存在")
				return
			}
			if errors.Is(err, ErrInvalidPlatformModel) {
				writeError(w, http.StatusBadRequest, "invalid_conversation", "会话更新内容无效")
				return
			}
			writeError(w, http.StatusServiceUnavailable, "chat_history_unavailable", "更新 Chat 会话失败")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"conversation": conversation})
	case http.MethodDelete:
		status := "deleted"
		conversation, err := platform.UpdatePlatformChatConversation(r.Context(), user.ID, id, PlatformChatConversationPatch{Status: &status})
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				writeError(w, http.StatusNotFound, "conversation_not_found", "会话不存在")
				return
			}
			writeError(w, http.StatusServiceUnavailable, "chat_history_unavailable", "删除 Chat 会话失败")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "conversation": conversation})
	default:
		w.Header().Set("Allow", strings.Join([]string{http.MethodGet, http.MethodPatch, http.MethodDelete}, ", "))
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "请求方法不允许")
	}
}

// platformPortalChatResponses is the first real Chat product call path. It
// authenticates the browser session rather than an external API key, uses the
// Chat wallet exclusively, and still invokes the same platform alias/routing
// rules as the public gateway. Browser Chat is therefore unable to select a
// provider, endpoint, upstream key, proxy, or hidden system policy.
func (s *Server) platformPortalChatResponses(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	platform, user, ok := s.platformPortalAuthenticatedUser(w, r)
	if !ok {
		return
	}
	cookie, err := r.Cookie(platformUserCookieName)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "user_auth_required", "请先登录")
		return
	}
	r, finish, err := s.beginPlatformUserRequest(r, user.ID, cookie.Value, s.realIP(r))
	if err != nil {
		if errors.Is(err, errIPAccessBanned) {
			writeError(w, http.StatusForbidden, "ip_banned", "来源 IP 已被安全策略封禁")
		} else {
			writeError(w, http.StatusUnauthorized, "user_session_expired", "网页登录已失效")
		}
		return
	}
	defer finish()
	if r.ContentLength > s.cfg.MaxBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "请求内容超过网关限制")
		return
	}
	request, err := readPlatformGatewayRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "请求内容超过网关限制")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_request", "请求必须是包含 model 的 JSON 对象")
		return
	}
	model, err := platform.ResolvePlatformProductModelForUser(r.Context(), user.ID, ProductScopeChat, "responses", request.RequestedModel)
	if err != nil {
		if errors.Is(err, ErrPlatformModelDenied) {
			writeError(w, http.StatusNotFound, "model_not_found", "该模型不在当前 Chat 套餐的可用目录中")
			return
		}
		writeError(w, http.StatusServiceUnavailable, "model_catalog_unavailable", "平台模型目录暂不可用")
		return
	}
	userText, title, userContent := platformChatRequestContent(request.Body)
	conversation, err := s.platformPortalConversationForChatRequest(r.Context(), platform, user.ID, r.PathValue("id"), title, model.ModelKey)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "conversation_not_found", "会话不存在")
			return
		}
		if errors.Is(err, ErrInvalidPlatformModel) {
			writeError(w, http.StatusConflict, "conversation_inactive", "该会话不能继续发送消息")
			return
		}
		writeError(w, http.StatusServiceUnavailable, "chat_history_unavailable", "读取 Chat 会话失败")
		return
	}
	requestID, err := randomToken(24)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "request_id_failed", "无法创建请求标识")
		return
	}
	userMessage, err := platform.AppendPlatformChatMessage(r.Context(), PlatformChatMessageInput{
		ConversationID: conversation.ID,
		UserID:         user.ID,
		Role:           "user",
		Text:           userText,
		Content:        userContent,
		ModelKey:       model.ModelKey,
		RequestID:      requestID,
		Status:         "sent",
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusConflict, "conversation_inactive", "该会话不能继续发送消息")
			return
		}
		writeError(w, http.StatusServiceUnavailable, "chat_history_unavailable", "保存用户消息失败")
		return
	}
	appendAssistantError := func(code, message string) {
		if _, appendErr := platform.AppendPlatformChatMessage(context.Background(), PlatformChatMessageInput{
			ConversationID: conversation.ID,
			UserID:         user.ID,
			Role:           "assistant",
			Text:           message,
			ModelKey:       model.ModelKey,
			RequestID:      requestID,
			Status:         "error",
			ErrorCode:      code,
		}); appendErr != nil {
			s.setSecurityRuntimeFailure("platform_chat_history_append_error", appendErr)
		}
	}
	w.Header().Set("X-Infinite-Conversation-ID", conversation.ID)
	w.Header().Set("X-Infinite-Request-ID", requestID)
	walletID, err := platform.EnsureProductQuota(r.Context(), user.ID, ProductScopeChat)
	if err != nil {
		appendAssistantError("wallet_unavailable", "Chat 额度账户暂不可用")
		writeError(w, http.StatusServiceUnavailable, "wallet_unavailable", "Chat 额度账户暂不可用")
		return
	}
	if _, err := platform.ReserveTokens(r.Context(), walletID, requestID, request.ReservationTokens); err != nil {
		if errors.Is(err, ErrQuotaExceeded) {
			appendAssistantError("quota_exceeded", "Chat 可用 Token 额度不足")
			writeError(w, http.StatusTooManyRequests, "quota_exceeded", "Chat 可用 Token 额度不足")
			return
		}
		appendAssistantError("quota_unavailable", "Chat 额度系统暂不可用")
		writeError(w, http.StatusServiceUnavailable, "quota_unavailable", "Chat 额度系统暂不可用")
		return
	}
	settlement := PlatformUsageSettlement{RequestID: requestID, UserID: user.ID, ModelID: model.ID, ProductScope: ProductScopeChat, Protocol: "responses", StatusCode: http.StatusBadGateway, Estimated: true, ToolSummary: request.ToolSummary}
	defer func() {
		settlement.DurationMS = time.Since(started).Milliseconds()
		if err := platform.RecordPlatformUsageAndSettle(context.Background(), walletID, requestID, settlement); err != nil {
			s.setSecurityRuntimeFailure("platform_chat_usage_settlement", err)
		}
	}()

	affinityHash := s.vault.Namespace("platform-route", user.ID, string(ProductScopeChat), "responses", request.SessionSeed)
	route, err := platform.SelectRouteTarget(r.Context(), RouteSelectionRequest{ModelID: model.ID, ProductScope: ProductScopeChat, Protocol: "responses", AffinityHash: affinityHash, StickyTTL: s.cfg.StickyTTL})
	if err != nil {
		settlement.StatusCode, settlement.ErrorCode = http.StatusServiceUnavailable, "route_unavailable"
		appendAssistantError("route_unavailable", "该模型当前没有可用上游")
		writeError(w, http.StatusServiceUnavailable, "route_unavailable", "该模型当前没有可用上游")
		return
	}
	settlement.UpstreamAccountID = route.UpstreamAccountID
	if route.ProviderKind != "openai_compatible" {
		settlement.StatusCode, settlement.ErrorCode = http.StatusUnprocessableEntity, "provider_protocol_unavailable"
		appendAssistantError("provider_protocol_unavailable", "该上游尚未实现 Chat 所需的原生协议")
		writeError(w, http.StatusUnprocessableEntity, "provider_not_ready", "该上游尚未实现 Chat 所需的原生协议")
		return
	}
	request.Body, err = replaceTopLevelJSONModel(request.Body, request.RequestedModel, route.UpstreamModelID)
	if err != nil {
		settlement.StatusCode, settlement.ErrorCode = http.StatusBadRequest, "model_rewrite_failed"
		appendAssistantError("model_rewrite_failed", "请求中的 model 字段无效")
		writeError(w, http.StatusBadRequest, "invalid_request", "请求中的 model 字段无效")
		return
	}
	target, err := platformUpstreamURL(route.BaseURL, "/responses")
	if err != nil {
		settlement.StatusCode, settlement.ErrorCode = http.StatusServiceUnavailable, "unsafe_upstream_target"
		appendAssistantError("unsafe_upstream_target", "上游地址不符合安全策略")
		writeError(w, http.StatusServiceUnavailable, "upstream_unavailable", "上游地址不符合安全策略")
		return
	}
	state := &proxyState{status: http.StatusBadGateway}
	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target.String(), bytes.NewReader(request.Body))
	if err != nil {
		settlement.StatusCode, settlement.ErrorCode = http.StatusServiceUnavailable, "upstream_request_failed"
		appendAssistantError("upstream_request_failed", "无法创建上游请求")
		writeError(w, http.StatusServiceUnavailable, "upstream_unavailable", "无法创建上游请求")
		return
	}
	upstreamReq.Header = r.Header.Clone()
	upstreamReq.ContentLength = int64(len(request.Body))
	upstreamReq.Header.Set("Content-Length", strconv.FormatInt(upstreamReq.ContentLength, 10))
	s.preparePlatformUpstreamRequest(upstreamReq, target, route.Credential)
	resp, err := s.platformClient.Do(upstreamReq)
	if err != nil {
		if errors.Is(context.Cause(r.Context()), errPlatformUserSessionRevoked) {
			state.status, state.errText, state.accessRevoked = http.StatusUnauthorized, "platform user session revoked", true
			writeError(w, http.StatusUnauthorized, "user_session_expired", "网页登录已失效")
			return
		}
		if errors.Is(context.Cause(r.Context()), errIPAccessBanned) {
			state.status, state.errText, state.accessRevoked = http.StatusForbidden, "source IP banned", true
			writeError(w, http.StatusForbidden, "ip_banned", "来源 IP 已被安全策略封禁")
			return
		}
		state.status, state.errText = http.StatusBadGateway, safeProxyError(err)
		appendAssistantError("upstream_error", "连接上游服务失败")
		writeError(w, http.StatusBadGateway, "upstream_error", "连接上游服务失败")
		return
	}
	defer resp.Body.Close()
	state.status = resp.StatusCode
	state.requestID = strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if state.requestID != "" {
		w.Header().Set("X-Infinite-Upstream-Request-ID", state.requestID)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		state.errText = "upstream status " + strconv.Itoa(resp.StatusCode)
	}
	upstreamBody, readErr := io.ReadAll(io.LimitReader(resp.Body, platformPortalMaxBufferedResponseBytes+1))
	if readErr != nil {
		if errors.Is(context.Cause(r.Context()), errPlatformUserSessionRevoked) {
			state.status, state.errText, state.accessRevoked = http.StatusUnauthorized, "platform user session revoked", true
			writeError(w, http.StatusUnauthorized, "user_session_expired", "网页登录已失效")
			return
		}
		if errors.Is(context.Cause(r.Context()), errIPAccessBanned) {
			state.status, state.errText, state.accessRevoked = http.StatusForbidden, "source IP banned", true
			writeError(w, http.StatusForbidden, "ip_banned", "来源 IP 已被安全策略封禁")
			return
		}
		state.status, state.errText = http.StatusBadGateway, safeProxyError(readErr)
		appendAssistantError("upstream_read_failed", "读取上游响应失败")
		writeError(w, http.StatusBadGateway, "upstream_error", "读取上游响应失败")
		return
	}
	if int64(len(upstreamBody)) > platformPortalMaxBufferedResponseBytes {
		state.status, state.errText = http.StatusBadGateway, "upstream response too large"
		appendAssistantError("upstream_response_too_large", "上游响应超过 Portal 可保存上限")
		writeError(w, http.StatusBadGateway, "upstream_response_too_large", "上游响应超过 Portal 可保存上限")
		return
	}
	if errors.Is(context.Cause(r.Context()), errPlatformUserSessionRevoked) {
		state.status, state.errText, state.accessRevoked = http.StatusUnauthorized, "platform user session revoked", true
	} else if errors.Is(context.Cause(r.Context()), errIPAccessBanned) {
		state.status, state.errText, state.accessRevoked = http.StatusForbidden, "source IP banned", true
	}
	settlement.StatusCode = state.status
	settlement.ErrorCode = truncate(state.errText, 120)
	responseObject, sanitizedBody, objectOK := platformChatSanitizedJSONObject(upstreamBody, route.UpstreamModelID, request.RequestedModel)
	if state.status >= 200 && state.status < 300 {
		input, output, total := parseUsage(sanitizedBody)
		settlement.InputTokens, settlement.OutputTokens = input, output
		if total > 0 {
			settlement.BilledTokens, settlement.Estimated = total, false
		} else {
			settlement.BilledTokens = estimatePlatformRequestTokens(request.Body)
			settlement.Estimated = true
		}
	}
	if state.status < 200 || state.status >= 300 || state.accessRevoked {
		settlement.BilledTokens, settlement.Estimated = 0, false
	}
	assistantText := platformChatOutputText(sanitizedBody)
	if assistantText == "" && state.errText != "" {
		assistantText = state.errText
	}
	assistantStatus, assistantErrorCode := "sent", ""
	if state.status < 200 || state.status >= 300 {
		assistantStatus, assistantErrorCode = "error", settlement.ErrorCode
	}
	assistantMessage, appendErr := platform.AppendPlatformChatMessage(r.Context(), PlatformChatMessageInput{
		ConversationID: conversation.ID,
		UserID:         user.ID,
		Role:           "assistant",
		Text:           assistantText,
		Content:        platformChatStoredResponseContent(sanitizedBody, assistantText),
		ModelKey:       model.ModelKey,
		RequestID:      requestID,
		Status:         assistantStatus,
		ErrorCode:      assistantErrorCode,
	})
	if appendErr != nil {
		s.setSecurityRuntimeFailure("platform_chat_history_append_response", appendErr)
	}
	conversation, messages := platformPortalChatSnapshot(context.Background(), platform, user.ID, conversation.ID, conversation, userMessage, assistantMessage)
	metadata := map[string]any{
		"conversation": conversation,
		"messages":     messages,
		"request_id":   requestID,
	}
	if state.requestID != "" {
		metadata["upstream_request_id"] = state.requestID
	}
	if objectOK {
		responseObject["infinite_ai"] = metadata
		if _, exists := responseObject["conversation"]; !exists {
			responseObject["conversation"] = conversation
		}
		if _, exists := responseObject["messages"]; !exists {
			responseObject["messages"] = messages
		}
		writeJSON(w, state.status, responseObject)
		return
	}
	if state.status >= 200 && state.status < 300 {
		writeJSON(w, state.status, map[string]any{"output_text": assistantText, "infinite_ai": metadata, "conversation": conversation, "messages": messages})
		return
	}
	if assistantText == "" {
		assistantText = "上游服务返回错误"
	}
	writeJSON(w, state.status, map[string]any{
		"error":        map[string]string{"code": "upstream_error", "message": assistantText},
		"infinite_ai":  metadata,
		"conversation": conversation,
		"messages":     messages,
	})
}

func (s *Server) platformPortalConversationForChatRequest(ctx context.Context, platform *PlatformStore, userID, conversationID, title, modelKey string) (*PlatformChatConversation, error) {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return platform.CreatePlatformChatConversation(ctx, userID, PlatformChatConversationInput{Title: title, SelectedModelKey: modelKey})
	}
	conversation, _, err := platform.PlatformChatConversation(ctx, userID, conversationID)
	if err != nil {
		return nil, err
	}
	if conversation.Status != "active" {
		return nil, ErrInvalidPlatformModel
	}
	return conversation, nil
}

func platformPortalChatSnapshot(ctx context.Context, platform *PlatformStore, userID, conversationID string, fallback *PlatformChatConversation, fallbackMessages ...*PlatformChatMessage) (*PlatformChatConversation, []PlatformChatMessage) {
	if platform != nil {
		conversation, messages, err := platform.PlatformChatConversation(ctx, userID, conversationID)
		if err == nil {
			return conversation, messages
		}
	}
	messages := make([]PlatformChatMessage, 0, len(fallbackMessages))
	for _, message := range fallbackMessages {
		if message != nil {
			messages = append(messages, *message)
		}
	}
	if fallback != nil {
		return fallback, messages
	}
	return &PlatformChatConversation{ID: strings.TrimSpace(conversationID), UserID: strings.TrimSpace(userID), Title: "新对话", Status: "active"}, messages
}

func platformChatRequestContent(body []byte) (string, string, json.RawMessage) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || fields == nil {
		text := truncate(string(bytes.TrimSpace(body)), 4096)
		return text, platformChatTitleFromText(text), platformChatTextContent(text)
	}
	text := platformChatReadableJSON(fields["input"])
	if text == "" {
		text = platformChatReadableJSON(fields["messages"])
	}
	if text == "" {
		text = truncate(string(bytes.TrimSpace(body)), 4096)
	}
	contentFields := make(map[string]json.RawMessage)
	for _, name := range []string{"input", "instructions", "messages"} {
		if raw := bytes.TrimSpace(fields[name]); len(raw) > 0 {
			contentFields[name] = append(json.RawMessage(nil), raw...)
		}
	}
	if len(contentFields) > 0 {
		if encoded, err := json.Marshal(contentFields); err == nil && len(encoded) <= 512<<10 && isJSONObject(encoded) {
			return text, platformChatTitleFromText(text), encoded
		}
	}
	return text, platformChatTitleFromText(text), platformChatTextContent(text)
}

func platformChatTitleFromText(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return "新对话"
	}
	firstLine := strings.TrimSpace(strings.Split(text, "\n")[0])
	firstLine = strings.Join(strings.Fields(firstLine), " ")
	if firstLine == "" {
		return "新对话"
	}
	return truncate(firstLine, 80)
}

func platformChatReadableJSON(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return ""
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return truncate(text, 8192)
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return truncate(string(raw), 4096)
	}
	var chunks []string
	platformChatCollectText(value, &chunks)
	if len(chunks) > 0 {
		return truncate(strings.Join(chunks, "\n"), 8192)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return truncate(string(raw), 4096)
	}
	return truncate(string(encoded), 4096)
}

func platformChatCollectText(value any, chunks *[]string) {
	if len(*chunks) >= 32 {
		return
	}
	switch item := value.(type) {
	case []any:
		for _, child := range item {
			platformChatCollectText(child, chunks)
			if len(*chunks) >= 32 {
				return
			}
		}
	case map[string]any:
		for _, key := range []string{"output_text", "text", "content"} {
			if text, ok := item[key].(string); ok && strings.TrimSpace(text) != "" {
				*chunks = append(*chunks, strings.TrimSpace(text))
				if len(*chunks) >= 32 {
					return
				}
			}
		}
		for _, child := range item {
			platformChatCollectText(child, chunks)
			if len(*chunks) >= 32 {
				return
			}
		}
	}
}

func platformChatOutputText(body []byte) string {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return ""
	}
	var value any
	if json.Unmarshal(body, &value) != nil {
		return truncate(string(body), 256<<10)
	}
	if object, ok := value.(map[string]any); ok {
		if text, ok := object["output_text"].(string); ok && strings.TrimSpace(text) != "" {
			return truncate(text, 256<<10)
		}
		if message := platformChatErrorText(object); message != "" {
			return truncate(message, 256<<10)
		}
		if output, ok := object["output"]; ok {
			var chunks []string
			platformChatCollectText(output, &chunks)
			if len(chunks) > 0 {
				return truncate(strings.Join(chunks, "\n"), 256<<10)
			}
		}
	}
	var chunks []string
	platformChatCollectText(value, &chunks)
	if len(chunks) > 0 {
		return truncate(strings.Join(chunks, "\n"), 256<<10)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return truncate(string(body), 256<<10)
	}
	return truncate(string(encoded), 256<<10)
}

func platformChatErrorText(object map[string]any) string {
	errorValue, ok := object["error"].(map[string]any)
	if !ok {
		return ""
	}
	if message, ok := errorValue["message"].(string); ok && strings.TrimSpace(message) != "" {
		return strings.TrimSpace(message)
	}
	return ""
}

func platformChatSanitizedJSONObject(body []byte, upstreamModelID, publicModelKey string) (map[string]any, []byte, bool) {
	var object map[string]any
	if json.Unmarshal(body, &object) != nil || object == nil {
		return nil, body, false
	}
	sanitized, ok := platformChatSanitizeValue(object, upstreamModelID, publicModelKey).(map[string]any)
	if !ok || sanitized == nil {
		return object, body, true
	}
	encoded, err := json.Marshal(sanitized)
	if err != nil {
		return sanitized, body, true
	}
	return sanitized, encoded, true
}

func platformChatSanitizeValue(value any, upstreamModelID, publicModelKey string) any {
	switch item := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(item))
		for key, child := range item {
			result[key] = platformChatSanitizeValue(child, upstreamModelID, publicModelKey)
		}
		return result
	case []any:
		result := make([]any, len(item))
		for i, child := range item {
			result[i] = platformChatSanitizeValue(child, upstreamModelID, publicModelKey)
		}
		return result
	case string:
		if upstreamModelID != "" && publicModelKey != "" && item == upstreamModelID {
			return publicModelKey
		}
		return item
	default:
		return value
	}
}

func platformChatStoredResponseContent(body []byte, fallbackText string) json.RawMessage {
	body = bytes.TrimSpace(body)
	if len(body) > 0 && len(body) <= 512<<10 && isJSONObject(body) {
		return append(json.RawMessage(nil), body...)
	}
	return platformChatTextContent(fallbackText)
}

func (s *Server) platformPortalTransitionUnavailable(w http.ResponseWriter) {
	writeError(w, http.StatusNotImplemented, "agent_device_transition_pending", "Agent 设备授权尚未切换到统一 PostgreSQL 设备身份；此入口不会回退到旧用户数据")
}

func platformPortalUsesPostgres(s *Server) bool {
	return s.cfg.PlatformGatewayEnabled && s.store.Platform() != nil
}

func platformPortalRegisterMode(value string) RegistrationMode {
	mode := RegistrationMode(strings.TrimSpace(value))
	if mode.Valid() {
		return mode
	}
	return RegistrationInviteOnly
}
