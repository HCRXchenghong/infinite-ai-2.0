package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"
)

// servePlatformAgentGateway handles the desktop's signed /v1 compatibility
// traffic. It uses the Agent wallet only; a desktop Chat request is still an
// Agent product request and cannot consume web Chat credits.
func (s *Server) servePlatformAgentGateway(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	platform := s.store.Platform()
	if platform == nil {
		writeError(w, http.StatusServiceUnavailable, "platform_unavailable", "统一数据库尚未就绪")
		return
	}
	auth, err := s.platformDesktopSessionRequest(r)
	if err != nil {
		platformDesktopAuthError(w, err)
		return
	}
	if platformGatewayModelsPath(r.URL.Path) {
		protocols := []string{"responses", "chat_completions", "messages", "generate_content"}
		if r.URL.Path == "/v1beta/models" {
			protocols = []string{"generate_content"}
		}
		models, err := platform.ListPlatformProductModelsForUserProtocols(r.Context(), auth.UserID, ProductScopeAgent, protocols)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "model_catalog_unavailable", "Agent 模型目录暂不可用")
			return
		}
		if r.URL.Path == "/v1beta/models" {
			items := make([]PlatformModel, 0, len(models))
			for _, model := range models {
				if model.Available {
					items = append(items, model.PlatformModel)
				}
			}
			writePlatformGatewayModelList(w, r.URL.Path, items)
			return
		}
		items := make([]map[string]any, 0, len(models))
		for _, model := range models {
			if model.Available {
				items = append(items, map[string]any{"id": model.ModelKey, "object": "model", "created": model.CreatedAt.Unix(), "owned_by": "infinite-ai"})
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": items})
		return
	}
	spec, ok := platformGatewayProtocolForPath(r.URL.Path)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "Agent 接口不存在")
		return
	}
	if r.ContentLength > s.cfg.MaxBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "请求内容超过网关限制")
		return
	}
	request, err := readPlatformGatewayRequestForSpec(w, r, s.cfg.MaxBodyBytes, spec)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "请求内容超过网关限制")
		} else {
			message := "请求必须是包含 model 的 JSON 对象"
			if !spec.RequiresBodyModel {
				message = "请求必须是 JSON 对象"
			}
			writeError(w, http.StatusBadRequest, "invalid_request", message)
		}
		return
	}
	model, err := platform.ResolvePlatformProductModelForUser(r.Context(), auth.UserID, ProductScopeAgent, spec.Protocol, request.RequestedModel)
	if err != nil {
		if errors.Is(err, ErrPlatformModelDenied) {
			writeError(w, http.StatusNotFound, "model_not_found", "该模型不在当前 Agent 套餐的可用目录中")
		} else {
			writeError(w, http.StatusServiceUnavailable, "model_catalog_unavailable", "Agent 模型目录暂不可用")
		}
		return
	}
	r, finish, err := s.beginPlatformAgentRequest(r, auth.UserID, auth.DeviceID, s.realIP(r))
	if err != nil {
		if errors.Is(err, errIPAccessBanned) {
			writeError(w, http.StatusForbidden, "ip_banned", "来源 IP 已被安全策略封禁")
		} else {
			platformDesktopAuthError(w, err)
		}
		return
	}
	defer finish()
	walletID, err := platform.EnsureProductQuota(r.Context(), auth.UserID, ProductScopeAgent)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "wallet_unavailable", "Agent 额度账户暂不可用")
		return
	}
	requestID, err := randomToken(24)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "request_id_failed", "无法创建请求标识")
		return
	}
	if _, err := platform.ReserveTokens(r.Context(), walletID, requestID, request.ReservationTokens); err != nil {
		if errors.Is(err, ErrQuotaExceeded) {
			writeError(w, http.StatusTooManyRequests, "quota_exceeded", "Agent 可用 Token 额度不足")
		} else {
			writeError(w, http.StatusServiceUnavailable, "quota_unavailable", "Agent 额度系统暂不可用")
		}
		return
	}
	settlement := PlatformUsageSettlement{RequestID: requestID, UserID: auth.UserID, ModelID: model.ID, ProductScope: ProductScopeAgent, Protocol: spec.Protocol, StatusCode: http.StatusBadGateway, Estimated: true, ToolSummary: request.ToolSummary, SessionScopeHash: s.vault.Namespace("platform-agent-session", auth.DeviceID, request.SessionSeed)}
	defer func() {
		settlement.DurationMS = time.Since(started).Milliseconds()
		if err := platform.RecordPlatformUsageAndSettle(context.Background(), walletID, requestID, settlement); err != nil {
			s.setSecurityRuntimeFailure("platform_agent_usage_settlement", err)
		}
	}()
	route, err := platform.SelectRouteTarget(r.Context(), RouteSelectionRequest{ModelID: model.ID, ProductScope: ProductScopeAgent, Protocol: spec.Protocol, AffinityHash: s.vault.Namespace("platform-agent-route", auth.DeviceID, spec.Protocol, request.SessionSeed), StickyTTL: s.cfg.StickyTTL})
	if err != nil {
		settlement.StatusCode, settlement.ErrorCode = http.StatusServiceUnavailable, "route_unavailable"
		writeError(w, http.StatusServiceUnavailable, "route_unavailable", "该模型当前没有可用上游")
		return
	}
	settlement.UpstreamAccountID = route.UpstreamAccountID
	if route.ProviderKind != spec.RequiredProviderKind {
		settlement.StatusCode, settlement.ErrorCode = http.StatusUnprocessableEntity, "provider_protocol_unavailable"
		writeError(w, http.StatusUnprocessableEntity, "provider_not_ready", "该上游尚未实现 Agent 所需的原生协议")
		return
	}
	request.Body, err = rewritePlatformGatewayRequestModel(request.Body, request.RequestedModel, route.UpstreamModelID, spec)
	if err != nil {
		settlement.StatusCode, settlement.ErrorCode = http.StatusBadRequest, "model_rewrite_failed"
		writeError(w, http.StatusBadRequest, "invalid_request", "请求中的 model 字段无效")
		return
	}
	target, err := platformUpstreamURLForRoute(route, spec)
	if err != nil {
		settlement.StatusCode, settlement.ErrorCode = http.StatusServiceUnavailable, "unsafe_upstream_target"
		writeError(w, http.StatusServiceUnavailable, "upstream_unavailable", "上游地址不符合安全策略")
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(request.Body))
	r.ContentLength = int64(len(request.Body))
	r.Header.Set("Content-Length", strconv.FormatInt(r.ContentLength, 10))
	state := &proxyState{status: http.StatusBadGateway}
	proxy := &httputil.ReverseProxy{Transport: s.platformClient.Transport, FlushInterval: -1, Director: func(req *http.Request) {
		s.preparePlatformUpstreamRequestForProvider(req, target, route.Credential, route.ProviderKind)
	}, ModifyResponse: func(resp *http.Response) error {
		state.status = resp.StatusCode
		state.requestID = strings.TrimSpace(resp.Header.Get("X-Request-ID"))
		if resp.StatusCode >= http.StatusBadRequest {
			state.errText = fmt.Sprintf("upstream status %d", resp.StatusCode)
		}
		resp.Header.Del("Set-Cookie")
		if resp.Body != nil {
			capture := newTailCaptureReadCloser(resp.Body, 256<<10)
			state.responseCapture = capture
			resp.Body = capture
		}
		return nil
	}, ErrorHandler: func(rw http.ResponseWriter, req *http.Request, proxyErr error) {
		if errors.Is(context.Cause(req.Context()), errPlatformUserSessionRevoked) {
			state.status, state.errText, state.accessRevoked = http.StatusUnauthorized, "platform agent session revoked", true
			writeError(rw, http.StatusUnauthorized, "desktop_session_invalid", "桌面登录已失效")
			return
		}
		if errors.Is(context.Cause(req.Context()), errIPAccessBanned) {
			state.status, state.errText, state.accessRevoked = http.StatusForbidden, "source IP banned", true
			writeError(rw, http.StatusForbidden, "ip_banned", "来源 IP 已被安全策略封禁")
			return
		}
		state.status, state.errText = http.StatusBadGateway, safeProxyError(proxyErr)
		writeError(rw, http.StatusBadGateway, "upstream_error", "连接上游服务失败")
	}}
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				if recovered == http.ErrAbortHandler && (errors.Is(context.Cause(r.Context()), errPlatformUserSessionRevoked) || errors.Is(context.Cause(r.Context()), errIPAccessBanned)) {
					if errors.Is(context.Cause(r.Context()), errIPAccessBanned) {
						state.status, state.errText = http.StatusForbidden, "source IP banned"
					} else {
						state.status, state.errText = http.StatusUnauthorized, "platform agent session revoked"
					}
					state.accessRevoked = true
					return
				}
				panic(recovered)
			}
		}()
		proxy.ServeHTTP(w, r)
	}()
	if errors.Is(context.Cause(r.Context()), errPlatformUserSessionRevoked) {
		state.status, state.errText, state.accessRevoked = http.StatusUnauthorized, "platform agent session revoked", true
	} else if errors.Is(context.Cause(r.Context()), errIPAccessBanned) {
		state.status, state.errText, state.accessRevoked = http.StatusForbidden, "source IP banned", true
	}
	settlement.StatusCode = state.status
	settlement.ErrorCode = truncate(state.errText, 120)
	if state.responseCapture != nil && state.status >= 200 && state.status < 300 {
		input, output, total := parseUsage(state.responseCapture.Bytes())
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
}
