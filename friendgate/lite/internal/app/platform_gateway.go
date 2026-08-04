package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	platformDefaultReserveTokens int64 = 32_768
	platformMaxReserveTokens     int64 = 1_000_000
)

var (
	errPlatformKeyRevoked         = errors.New("platform API key access revoked while request was in flight")
	errPlatformUserSessionRevoked = errors.New("platform user session revoked while request was in flight")
)

type platformGatewayRequest struct {
	Body              []byte
	RequestedModel    string
	ReservationTokens int64
	ToolSummary       json.RawMessage
	SessionSeed       string
}

type platformGatewayProtocolSpec struct {
	Protocol             string
	RequiredProviderKind string
	Endpoint             string
	RequiresBodyModel    bool
	GeminiAction         string
	RequestedModel       string
}

func platformGatewayOwnsPath(requestPath string) bool {
	return requestPath == "/v1" || strings.HasPrefix(requestPath, "/v1/") || requestPath == "/v1beta" || strings.HasPrefix(requestPath, "/v1beta/")
}

func platformGatewayModelsPath(requestPath string) bool {
	return requestPath == "/v1/models" || requestPath == "/v1beta/models"
}

func platformGatewaySupportedPath(requestPath string) bool {
	if platformGatewayModelsPath(requestPath) {
		return true
	}
	_, ok := platformGatewayProtocolForPath(requestPath)
	return ok
}

func platformGatewayProtocolForPath(requestPath string) (platformGatewayProtocolSpec, bool) {
	switch requestPath {
	case "/v1/responses":
		return platformGatewayProtocolSpec{Protocol: "responses", RequiredProviderKind: "openai_compatible", Endpoint: "/responses", RequiresBodyModel: true}, true
	case "/v1/chat/completions":
		return platformGatewayProtocolSpec{Protocol: "chat_completions", RequiredProviderKind: "openai_compatible", Endpoint: "/chat/completions", RequiresBodyModel: true}, true
	case "/v1/messages":
		return platformGatewayProtocolSpec{Protocol: "messages", RequiredProviderKind: "anthropic_compatible", Endpoint: "/messages", RequiresBodyModel: true}, true
	}
	for _, prefix := range []string{"/v1beta/models/", "/v1/models/"} {
		if !strings.HasPrefix(requestPath, prefix) {
			continue
		}
		rest := strings.TrimPrefix(requestPath, prefix)
		for _, action := range []string{"generateContent", "streamGenerateContent"} {
			suffix := ":" + action
			if !strings.HasSuffix(rest, suffix) {
				continue
			}
			encodedModel := strings.TrimSuffix(rest, suffix)
			if encodedModel == "" || strings.Contains(encodedModel, "/") {
				return platformGatewayProtocolSpec{}, false
			}
			model, err := url.PathUnescape(encodedModel)
			if err != nil || strings.TrimSpace(model) == "" {
				return platformGatewayProtocolSpec{}, false
			}
			return platformGatewayProtocolSpec{Protocol: "generate_content", RequiredProviderKind: "gemini_compatible", RequiresBodyModel: false, GeminiAction: action, RequestedModel: strings.TrimSpace(model)}, true
		}
	}
	return platformGatewayProtocolSpec{}, false
}

func extractPlatformGatewayKey(r *http.Request) string {
	if key := extractAPIKey(r); key != "" {
		return key
	}
	if key := strings.TrimSpace(r.Header.Get("X-Goog-Api-Key")); key != "" {
		return key
	}
	return strings.TrimSpace(r.URL.Query().Get("key"))
}

// servePlatformGatewayIfMatched owns the public /v1 surface after the
// PostgreSQL gateway switch is explicitly enabled.  Returning true means the
// request was handled (including a deliberate 404), so legacy SQLite keys can
// never accidentally authorize a new public endpoint.
func (s *Server) servePlatformGatewayIfMatched(w http.ResponseWriter, r *http.Request) bool {
	if !s.cfg.PlatformGatewayEnabled || !platformGatewayOwnsPath(r.URL.Path) {
		return false
	}
	// A signed fgds_ token is a PostgreSQL Agent device session, not a public
	// external API key. It receives the Agent model catalogue and wallet only.
	if strings.HasPrefix(extractAPIKey(r), "fgds_") {
		if !platformGatewaySupportedPath(r.URL.Path) {
			writeError(w, http.StatusNotFound, "not_found", "Agent 接口不存在")
			return true
		}
		if platformGatewayModelsPath(r.URL.Path) && r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "请求方法不允许")
			return true
		}
		if !platformGatewayModelsPath(r.URL.Path) && r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "请求方法不允许")
			return true
		}
		s.servePlatformAgentGateway(w, r)
		return true
	}
	if !platformGatewaySupportedPath(r.URL.Path) {
		ip := s.realIP(r)
		s.platformGatewayInvalidPath(w, r, ip)
		return true
	}
	if platformGatewayModelsPath(r.URL.Path) && r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "请求方法不允许")
		return true
	}
	if !platformGatewayModelsPath(r.URL.Path) && r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "请求方法不允许")
		return true
	}
	s.servePlatformGateway(w, r)
	return true
}

func (s *Server) platformGatewayInvalidPath(w http.ResponseWriter, r *http.Request, ip string) {
	// Unsupported endpoints are not authenticated because a caller may simply
	// be discovering the API. Still record repeated endpoint scanning under the
	// same bounded legacy security ledger used by the existing public gateway.
	banned, err := s.store.RecordUnauthorized(r.Context(), ip, "platform_invalid_path", r.URL.Path, "unsupported PostgreSQL gateway path", s.cfg.BanThreshold, s.cfg.BanWindow, s.cfg.BanDuration)
	if err != nil {
		s.setSecurityRuntimeFailure("platform_invalid_path", err)
	}
	if banned {
		s.activatePublicBan(r.Context(), ip, s.cfg.BanDuration)
		writeError(w, http.StatusForbidden, "ip_banned", "异常访问次数过多，该 IP 已被封禁")
		return
	}
	writeError(w, http.StatusNotFound, "not_found", "接口不存在")
}

func (s *Server) servePlatformGateway(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	ip := s.realIP(r)
	if s.isBannedCached(ip, "api") {
		writeError(w, http.StatusForbidden, "ip_banned", "来源 IP 已被安全策略封禁")
		return
	}
	platform := s.store.Platform()
	if platform == nil {
		// LoadConfig prevents this configuration in production. Retaining a
		// defensive response keeps manually constructed Server instances safe.
		writeError(w, http.StatusServiceUnavailable, "platform_unavailable", "统一数据库尚未就绪")
		return
	}
	plainKey := extractPlatformGatewayKey(r)
	if plainKey == "" {
		s.rejectUnauthorized(w, r, ip, "platform_missing_key", "missing platform API key", http.StatusUnauthorized)
		return
	}
	key, err := platform.AuthorizePlatformAPIKey(r.Context(), plainKey, ip)
	if err != nil {
		s.writePlatformGatewayAuthorizationError(w, r, ip, err)
		return
	}
	if platformGatewayModelsPath(r.URL.Path) {
		protocols := []string{"responses", "chat_completions", "messages", "generate_content"}
		if r.URL.Path == "/v1beta/models" {
			protocols = []string{"generate_content"}
		}
		models, err := platform.ListPlatformGatewayModelsForProtocols(r.Context(), key, ProductScopeExternalAPI, protocols)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "model_catalog_unavailable", "平台模型目录暂不可用")
			return
		}
		writePlatformGatewayModelList(w, r.URL.Path, models)
		return
	}
	spec, ok := platformGatewayProtocolForPath(r.URL.Path)
	if !ok {
		s.platformGatewayInvalidPath(w, r, ip)
		return
	}
	if r.ContentLength > s.cfg.MaxBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "请求内容超过网关限制")
		return
	}
	request, err := readPlatformGatewayRequestForSpec(w, r, s.cfg.MaxBodyBytes, spec)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "请求内容超过网关限制")
			return
		}
		message := "请求必须是包含 model 的 JSON 对象"
		if !spec.RequiresBodyModel {
			message = "请求必须是 JSON 对象"
		}
		writeError(w, http.StatusBadRequest, "invalid_request", message)
		return
	}
	model, err := platform.ResolvePlatformGatewayModel(r.Context(), key, request.RequestedModel, ProductScopeExternalAPI, spec.Protocol)
	if err != nil {
		if errors.Is(err, ErrPlatformModelDenied) || errors.Is(err, ErrPlatformPublicationAbsent) {
			writeError(w, http.StatusNotFound, "model_not_found", "该模型不在此密钥的可用目录中")
			return
		}
		writeError(w, http.StatusServiceUnavailable, "model_catalog_unavailable", "平台模型目录暂不可用")
		return
	}
	if spec.RequiresBodyModel {
		request.Body, err = replaceTopLevelJSONModel(request.Body, request.RequestedModel, request.RequestedModel) // validate the exact body once before upstream selection
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "请求中的 model 字段无效")
			return
		}
	}
	// The replacement above intentionally uses the same alias as a no-op
	// structural validation.  Substitute the private upstream ID only after a
	// route is selected, so no raw provider ID is ever persisted in request data.

	var finish func()
	r, finish, err = s.beginPlatformGatewayRequest(r, key, plainKey, ip)
	if err != nil {
		s.writePlatformGatewayAdmissionError(w, err)
		return
	}
	defer finish()

	walletID, err := platform.EnsureProductQuota(r.Context(), key.UserID, ProductScopeExternalAPI)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "wallet_unavailable", "额度账户暂不可用")
		return
	}
	requestID, err := randomToken(24)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "request_id_failed", "无法创建请求标识")
		return
	}
	if _, err := platform.ReserveTokens(r.Context(), walletID, requestID, request.ReservationTokens); err != nil {
		if errors.Is(err, ErrQuotaExceeded) {
			writeError(w, http.StatusTooManyRequests, "quota_exceeded", "可用 Token 额度不足")
			return
		}
		writeError(w, http.StatusServiceUnavailable, "quota_unavailable", "额度系统暂不可用")
		return
	}
	reserved := true
	settlement := PlatformUsageSettlement{
		RequestID: requestID, UserID: key.UserID, APIKeyID: key.ID, ModelID: model.ID,
		ProductScope: ProductScopeExternalAPI, Protocol: spec.Protocol, StatusCode: http.StatusBadGateway,
		Estimated: true, ToolSummary: request.ToolSummary, DurationMS: 0,
	}
	defer func() {
		if !reserved {
			return
		}
		settlement.DurationMS = time.Since(started).Milliseconds()
		if err := platform.RecordPlatformUsageAndSettle(context.Background(), walletID, requestID, settlement); err != nil {
			s.setSecurityRuntimeFailure("platform_usage_settlement", err)
		}
	}()

	affinityHash := s.platformAffinityHash(r, key.ID, spec.Protocol, request.SessionSeed)
	route, err := platform.SelectRouteTarget(r.Context(), RouteSelectionRequest{ModelID: model.ID, ProductScope: ProductScopeExternalAPI, Protocol: spec.Protocol, RoutePoolID: key.RoutePoolID, AffinityHash: affinityHash, StickyTTL: s.cfg.StickyTTL})
	if err != nil {
		if errors.Is(err, ErrNoRouteTarget) || errors.Is(err, ErrNoRouteCandidate) {
			settlement.StatusCode, settlement.ErrorCode = http.StatusServiceUnavailable, "route_unavailable"
			writeError(w, http.StatusServiceUnavailable, "route_unavailable", "该平台模型当前没有可用上游")
			return
		}
		settlement.StatusCode, settlement.ErrorCode = http.StatusServiceUnavailable, "route_selection_failed"
		writeError(w, http.StatusServiceUnavailable, "route_unavailable", "模型路由暂不可用")
		return
	}
	settlement.UpstreamAccountID = route.UpstreamAccountID
	if route.ProviderKind != spec.RequiredProviderKind {
		settlement.StatusCode, settlement.ErrorCode = http.StatusUnprocessableEntity, "provider_protocol_unavailable"
		writeError(w, http.StatusUnprocessableEntity, "provider_not_ready", "该上游尚未实现所需原生请求协议")
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
	proxy := &httputil.ReverseProxy{
		Transport:     s.platformClient.Transport,
		FlushInterval: -1,
		Director: func(req *http.Request) {
			s.preparePlatformUpstreamRequestForProvider(req, target, route.Credential, route.ProviderKind)
		},
		ModifyResponse: func(resp *http.Response) error {
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
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, proxyErr error) {
			if errors.Is(context.Cause(req.Context()), errPlatformKeyRevoked) {
				state.status, state.errText, state.accessRevoked = http.StatusUnauthorized, "platform key revoked", true
				writeError(rw, http.StatusUnauthorized, "key_inactive", "该密钥已被停用或删除")
				return
			}
			if errors.Is(context.Cause(req.Context()), errIPAccessBanned) {
				state.status, state.errText, state.accessRevoked = http.StatusForbidden, "source IP banned", true
				writeError(rw, http.StatusForbidden, "ip_banned", "来源 IP 已被安全策略封禁")
				return
			}
			state.status, state.errText = http.StatusBadGateway, safeProxyError(proxyErr)
			writeError(rw, http.StatusBadGateway, "upstream_error", "连接上游服务失败")
		},
	}
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				if recovered == http.ErrAbortHandler && (errors.Is(context.Cause(r.Context()), errPlatformKeyRevoked) || errors.Is(context.Cause(r.Context()), errIPAccessBanned)) {
					if errors.Is(context.Cause(r.Context()), errIPAccessBanned) {
						state.status, state.errText = http.StatusForbidden, "source IP banned"
					} else {
						state.status, state.errText = http.StatusUnauthorized, "platform key revoked"
					}
					state.accessRevoked = true
					return
				}
				panic(recovered)
			}
		}()
		proxy.ServeHTTP(w, r)
	}()
	if errors.Is(context.Cause(r.Context()), errPlatformKeyRevoked) {
		state.status, state.errText, state.accessRevoked = http.StatusUnauthorized, "platform key revoked", true
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
		settlement.BilledTokens = 0
		settlement.Estimated = false
	}
}

func writePlatformGatewayModelList(w http.ResponseWriter, requestPath string, models []PlatformModel) {
	if requestPath == "/v1beta/models" {
		items := make([]map[string]any, 0, len(models))
		for _, model := range models {
			methods := []string{"generateContent", "streamGenerateContent"}
			items = append(items, map[string]any{"name": "models/" + model.ModelKey, "displayName": model.DisplayName, "description": model.Description, "supportedGenerationMethods": methods})
		}
		writeJSON(w, http.StatusOK, map[string]any{"models": items})
		return
	}
	items := make([]map[string]any, 0, len(models))
	for _, model := range models {
		items = append(items, map[string]any{"id": model.ModelKey, "object": "model", "created": model.CreatedAt.Unix(), "owned_by": "infinite-ai"})
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": items})
}

func rewritePlatformGatewayRequestModel(body []byte, requested, upstream string, spec platformGatewayProtocolSpec) ([]byte, error) {
	if !spec.RequiresBodyModel {
		return body, nil
	}
	return replaceTopLevelJSONModel(body, requested, upstream)
}

func platformUpstreamURLForRoute(route *RouteSelection, spec platformGatewayProtocolSpec) (*url.URL, error) {
	if route == nil {
		return nil, ErrUnsafeProviderTarget
	}
	endpoint := spec.Endpoint
	if spec.Protocol == "generate_content" {
		resource, err := platformGeminiModelResource(route.UpstreamModelID)
		if err != nil {
			return nil, err
		}
		action := spec.GeminiAction
		if action == "" {
			action = "generateContent"
		}
		endpoint = resource + ":" + action
	}
	return platformUpstreamURL(route.BaseURL, endpoint)
}

func platformGeminiModelResource(modelID string) (string, error) {
	modelID = strings.Trim(strings.TrimSpace(modelID), "/")
	if modelID == "" || strings.ContainsAny(modelID, "\x00\r\n?#") {
		return "", ErrUnsafeProviderTarget
	}
	if !strings.HasPrefix(modelID, "models/") && !strings.HasPrefix(modelID, "tunedModels/") {
		modelID = "models/" + modelID
	}
	parts := strings.Split(modelID, "/")
	for i, part := range parts {
		if strings.TrimSpace(part) == "" {
			return "", ErrUnsafeProviderTarget
		}
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/"), nil
}

func (s *Server) preparePlatformUpstreamRequest(req *http.Request, target *url.URL, credential string) {
	s.preparePlatformUpstreamRequestForProvider(req, target, credential, "openai_compatible")
}

func (s *Server) preparePlatformUpstreamRequestForProvider(req *http.Request, target *url.URL, credential, providerKind string) {
	original := req.Header.Clone()
	req.URL.Scheme, req.URL.Host, req.URL.Path, req.URL.RawPath = target.Scheme, target.Host, target.Path, ""
	req.URL.RawQuery = target.RawQuery
	req.Host = target.Host
	req.Header = make(http.Header)
	for name, values := range original {
		switch strings.ToLower(name) {
		case "accept", "accept-language", "content-type", "user-agent", "openai-beta", "openai-organization", "openai-project", "anthropic-version", "anthropic-beta", "x-goog-api-client", "x-goog-fieldmask":
			for _, value := range values {
				req.Header.Add(name, value)
			}
		}
	}
	switch providerKind {
	case "anthropic_compatible":
		req.Header.Set("X-API-Key", credential)
		if req.Header.Get("Anthropic-Version") == "" {
			req.Header.Set("Anthropic-Version", providerAnthropicAPIVersion)
		}
	case "gemini_compatible":
		query := req.URL.Query()
		query.Set("key", credential)
		req.URL.RawQuery = query.Encode()
	default:
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "Infinite-AI-Gateway/2")
	}
}

func platformUpstreamURL(baseURL, endpoint string) (*url.URL, error) {
	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || base.Scheme == "" || base.Host == "" || base.User != nil || (base.Scheme != "https" && base.Scheme != "http") {
		return nil, ErrUnsafeProviderTarget
	}
	if err := validateProviderEndpointHost(base); err != nil {
		return nil, err
	}
	base.RawQuery, base.Fragment = "", ""
	base.Path = path.Join("/", base.Path, endpoint)
	return base, nil
}

func (s *Server) writePlatformGatewayAuthorizationError(w http.ResponseWriter, r *http.Request, ip string, err error) {
	if errors.Is(err, ErrPlatformKeyIPDenied) {
		s.rejectUnauthorized(w, r, ip, "platform_ip_denied", "platform key source IP denied", http.StatusForbidden)
		return
	}
	s.rejectUnauthorized(w, r, ip, "platform_invalid_key", "unknown or inactive platform API key", http.StatusUnauthorized)
}

func (s *Server) writePlatformGatewayAdmissionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrPlatformKeyInactive), errors.Is(err, errPlatformKeyRevoked):
		writeError(w, http.StatusUnauthorized, "key_inactive", "该密钥已被停用或删除")
	case errors.Is(err, ErrPlatformKeyIPDenied):
		writeError(w, http.StatusForbidden, "ip_not_allowed", "当前 IP 未获得此密钥授权")
	case errors.Is(err, errIPAccessBanned):
		writeError(w, http.StatusForbidden, "ip_banned", "来源 IP 已被安全策略封禁")
	default:
		writeError(w, http.StatusServiceUnavailable, "authorization_unavailable", "密钥授权检查暂不可用")
	}
}

func (s *Server) platformAffinityHash(r *http.Request, keyID, protocol, bodySeed string) string {
	seed := strings.TrimSpace(bodySeed)
	if seed == "" {
		for _, name := range []string{"X-Session-Affinity", "X-Session-ID", "Conversation_ID", "Session_ID"} {
			if value := strings.TrimSpace(r.Header.Get(name)); value != "" {
				seed = value
				break
			}
		}
	}
	if seed == "" {
		seed = "key-default"
	}
	return s.vault.Namespace("platform-route", keyID, string(ProductScopeExternalAPI), protocol, seed)
}

func (s *Server) beginPlatformGatewayRequest(r *http.Request, key *PlatformAPIKey, plainKey, ip string) (*http.Request, func(), error) {
	s.platformRequestMu.Lock()
	defer s.platformRequestMu.Unlock()
	if s.isBannedCached(ip, "api") {
		return r, func() {}, errIPAccessBanned
	}
	current, err := s.store.Platform().AuthorizePlatformAPIKey(r.Context(), plainKey, ip)
	if err != nil {
		return r, func() {}, err
	}
	if current.ID != key.ID || current.Version != key.Version || current.UserID != key.UserID {
		return r, func() {}, ErrPlatformKeyInactive
	}
	ctx, cancel := context.WithCancelCause(r.Context())
	done := make(chan struct{})
	s.platformRequestID++
	requestID := s.platformRequestID
	if s.platformRequests[key.ID] == nil {
		s.platformRequests[key.ID] = make(map[uint64]activePlatformRequest)
	}
	s.platformRequests[key.ID][requestID] = activePlatformRequest{userID: key.UserID, ip: ip, cancel: cancel, done: done}
	var once sync.Once
	finish := func() {
		once.Do(func() {
			cancel(nil)
			s.platformRequestMu.Lock()
			delete(s.platformRequests[key.ID], requestID)
			if len(s.platformRequests[key.ID]) == 0 {
				delete(s.platformRequests, key.ID)
			}
			s.platformRequestMu.Unlock()
			close(done)
		})
	}
	return r.WithContext(ctx), finish, nil
}

func (s *Server) cancelPlatformKeyRequestsLocked(keyID string) []<-chan struct{} {
	requests := s.platformRequests[keyID]
	delete(s.platformRequests, keyID)
	done := make([]<-chan struct{}, 0, len(requests))
	for _, request := range requests {
		request.cancel(errPlatformKeyRevoked)
		done = append(done, request.done)
	}
	return done
}

func (s *Server) setPlatformAPIKeyStatus(ctx context.Context, id, status string) (int, error) {
	s.platformRequestMu.Lock()
	if err := s.store.Platform().SetPlatformAPIKeyStatus(ctx, id, status); err != nil {
		s.platformRequestMu.Unlock()
		return 0, err
	}
	var waiting []<-chan struct{}
	if strings.TrimSpace(strings.ToLower(status)) != "active" {
		waiting = s.cancelPlatformKeyRequestsLocked(strings.TrimSpace(id))
	}
	s.platformRequestMu.Unlock()
	if err := waitKeyRequests(ctx, waiting); err != nil {
		return len(waiting), err
	}
	return len(waiting), nil
}

func (s *Server) deletePlatformAPIKey(ctx context.Context, id string) (int, error) {
	s.platformRequestMu.Lock()
	if err := s.store.Platform().DeletePlatformAPIKey(ctx, id); err != nil {
		s.platformRequestMu.Unlock()
		return 0, err
	}
	waiting := s.cancelPlatformKeyRequestsLocked(strings.TrimSpace(id))
	s.platformRequestMu.Unlock()
	if err := waitKeyRequests(ctx, waiting); err != nil {
		return len(waiting), err
	}
	return len(waiting), nil
}

func (s *Server) beginPlatformUserRequest(r *http.Request, userID, sessionToken, ip string) (*http.Request, func(), error) {
	userID = strings.TrimSpace(userID)
	sessionToken = strings.TrimSpace(sessionToken)
	if userID == "" || sessionToken == "" {
		return r, func() {}, ErrUserInactive
	}
	sessionID := "user-session:" + tokenHash(sessionToken)
	s.platformRequestMu.Lock()
	defer s.platformRequestMu.Unlock()
	if s.isBannedCached(ip, "api") {
		return r, func() {}, errIPAccessBanned
	}
	ctx, cancel := context.WithCancelCause(r.Context())
	done := make(chan struct{})
	s.platformRequestID++
	requestID := s.platformRequestID
	if s.platformRequests[sessionID] == nil {
		s.platformRequests[sessionID] = make(map[uint64]activePlatformRequest)
	}
	s.platformRequests[sessionID][requestID] = activePlatformRequest{userID: userID, ip: ip, cancel: cancel, done: done}
	var once sync.Once
	finish := func() {
		once.Do(func() {
			cancel(nil)
			s.platformRequestMu.Lock()
			delete(s.platformRequests[sessionID], requestID)
			if len(s.platformRequests[sessionID]) == 0 {
				delete(s.platformRequests, sessionID)
			}
			s.platformRequestMu.Unlock()
			close(done)
		})
	}
	return r.WithContext(ctx), finish, nil
}

// beginPlatformAgentRequest keeps desktop Agent streams in a separate
// revocation namespace. Revoking a device therefore interrupts only that
// device's active work and cannot accidentally cancel another browser Chat
// session belonging to the same user.
func (s *Server) beginPlatformAgentRequest(r *http.Request, userID, deviceID, ip string) (*http.Request, func(), error) {
	userID, deviceID = strings.TrimSpace(userID), strings.TrimSpace(deviceID)
	if userID == "" || deviceID == "" {
		return r, func() {}, ErrPlatformDeviceSession
	}
	requestGroup := "agent-device:" + deviceID
	s.platformRequestMu.Lock()
	defer s.platformRequestMu.Unlock()
	if s.isBannedCached(ip, "api") {
		return r, func() {}, errIPAccessBanned
	}
	ctx, cancel := context.WithCancelCause(r.Context())
	done := make(chan struct{})
	s.platformRequestID++
	requestID := s.platformRequestID
	if s.platformRequests[requestGroup] == nil {
		s.platformRequests[requestGroup] = make(map[uint64]activePlatformRequest)
	}
	s.platformRequests[requestGroup][requestID] = activePlatformRequest{userID: userID, ip: ip, cancel: cancel, done: done}
	var once sync.Once
	finish := func() {
		once.Do(func() {
			cancel(nil)
			s.platformRequestMu.Lock()
			delete(s.platformRequests[requestGroup], requestID)
			if len(s.platformRequests[requestGroup]) == 0 {
				delete(s.platformRequests, requestGroup)
			}
			s.platformRequestMu.Unlock()
			close(done)
		})
	}
	return r.WithContext(ctx), finish, nil
}

func (s *Server) cancelPlatformDeviceRequests(ctx context.Context, deviceID string) (int, error) {
	requestGroup := "agent-device:" + strings.TrimSpace(deviceID)
	s.platformRequestMu.Lock()
	requests := s.platformRequests[requestGroup]
	delete(s.platformRequests, requestGroup)
	waiting := make([]<-chan struct{}, 0, len(requests))
	for _, request := range requests {
		request.cancel(errPlatformUserSessionRevoked)
		waiting = append(waiting, request.done)
	}
	s.platformRequestMu.Unlock()
	if err := waitKeyRequests(ctx, waiting); err != nil {
		return len(waiting), err
	}
	return len(waiting), nil
}

func (s *Server) cancelPlatformUserSessionRequests(ctx context.Context, sessionToken string) (int, error) {
	sessionID := "user-session:" + tokenHash(strings.TrimSpace(sessionToken))
	s.platformRequestMu.Lock()
	requests := s.platformRequests[sessionID]
	delete(s.platformRequests, sessionID)
	waiting := make([]<-chan struct{}, 0, len(requests))
	for _, request := range requests {
		request.cancel(errPlatformUserSessionRevoked)
		waiting = append(waiting, request.done)
	}
	s.platformRequestMu.Unlock()
	if err := waitKeyRequests(ctx, waiting); err != nil {
		return len(waiting), err
	}
	return len(waiting), nil
}

func (s *Server) setPlatformUserStatus(ctx context.Context, userID, status string) (int, error) {
	s.platformRequestMu.Lock()
	if err := s.store.Platform().SetPlatformUserStatus(ctx, userID, status); err != nil {
		s.platformRequestMu.Unlock()
		return 0, err
	}
	waiting := make([]<-chan struct{}, 0)
	if strings.TrimSpace(strings.ToLower(status)) != "active" {
		for keyID, requests := range s.platformRequests {
			for requestID, request := range requests {
				if request.userID != strings.TrimSpace(userID) {
					continue
				}
				request.cancel(errPlatformUserSessionRevoked)
				waiting = append(waiting, request.done)
				delete(requests, requestID)
			}
			if len(requests) == 0 {
				delete(s.platformRequests, keyID)
			}
		}
	}
	s.platformRequestMu.Unlock()
	if err := waitKeyRequests(ctx, waiting); err != nil {
		return len(waiting), err
	}
	return len(waiting), nil
}

func readPlatformGatewayRequest(w http.ResponseWriter, r *http.Request, limit int64) (platformGatewayRequest, error) {
	return readPlatformGatewayRequestForSpec(w, r, limit, platformGatewayProtocolSpec{RequiresBodyModel: true})
}

func readPlatformGatewayRequestForSpec(w http.ResponseWriter, r *http.Request, limit int64, spec platformGatewayProtocolSpec) (platformGatewayRequest, error) {
	var result platformGatewayRequest
	reader := http.MaxBytesReader(w, r.Body, limit)
	body, err := io.ReadAll(reader)
	if closeErr := reader.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return result, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
		return result, errors.New("request is not an object")
	}
	model := strings.TrimSpace(spec.RequestedModel)
	if spec.RequiresBodyModel {
		var start, end int
		model, start, end, err = topLevelJSONModelRange(body)
		if err != nil {
			return result, err
		}
		if start < 0 || end <= start || strings.TrimSpace(model) == "" || len(model) > 128 {
			return result, errors.New("model is missing")
		}
	} else if model == "" || len(model) > 128 {
		return result, errors.New("model is missing")
	}
	result.Body, result.RequestedModel = body, strings.TrimSpace(model)
	result.ReservationTokens = estimatePlatformReservationTokens(body, fields)
	result.ToolSummary = summarizePlatformTools(fields["tools"])
	for _, name := range []string{"prompt_cache_key", "conversation", "previous_response_id", "cachedContent", "cached_content"} {
		var value string
		if json.Unmarshal(fields[name], &value) == nil && strings.TrimSpace(value) != "" {
			result.SessionSeed = truncate(strings.TrimSpace(value), 512)
			break
		}
	}
	return result, nil
}

func estimatePlatformReservationTokens(body []byte, fields map[string]json.RawMessage) int64 {
	reserve := platformDefaultReserveTokens
	for _, name := range []string{"max_output_tokens", "max_tokens", "max_completion_tokens"} {
		var value int64
		if json.Unmarshal(fields[name], &value) == nil && value > 0 {
			reserve = value + estimatePlatformRequestTokens(body)
			break
		}
	}
	if reserve == platformDefaultReserveTokens {
		var generationConfig map[string]json.RawMessage
		if json.Unmarshal(fields["generationConfig"], &generationConfig) == nil {
			var value int64
			if json.Unmarshal(generationConfig["maxOutputTokens"], &value) == nil && value > 0 {
				reserve = value + estimatePlatformRequestTokens(body)
			}
		}
	}
	if reserve < 1 {
		reserve = 1
	}
	if reserve > platformMaxReserveTokens {
		reserve = platformMaxReserveTokens
	}
	return reserve
}

func estimatePlatformRequestTokens(body []byte) int64 {
	// A deliberately conservative byte heuristic is only used if the upstream
	// omits a trusted usage envelope.  The usage record exposes estimated=true
	// so it is never mistaken for provider-reported token accounting.
	value := int64((len(body) + 3) / 4)
	if value < 1 {
		return 1
	}
	return value
}

func summarizePlatformTools(raw json.RawMessage) json.RawMessage {
	summary := map[string]any{"count": 0}
	var tools []map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &tools) != nil {
		encoded, _ := json.Marshal(summary)
		return encoded
	}
	types := make(map[string]int)
	for _, tool := range tools {
		var kind string
		if json.Unmarshal(tool["type"], &kind) == nil && kind != "" {
			types[truncate(kind, 64)]++
		}
	}
	summary["count"], summary["types"] = len(tools), types
	encoded, _ := json.Marshal(summary)
	return encoded
}

// replaceTopLevelJSONModel changes exactly the bytes belonging to the
// top-level model string. Nested tool JSON, input payloads, whitespace and all
// other bytes remain byte-for-byte untouched.
func replaceTopLevelJSONModel(body []byte, expected, replacement string) ([]byte, error) {
	model, start, end, err := topLevelJSONModelRange(body)
	if err != nil || strings.TrimSpace(model) != strings.TrimSpace(expected) {
		return nil, errors.New("top-level model mismatch")
	}
	encoded, err := json.Marshal(replacement)
	if err != nil {
		return nil, err
	}
	result := make([]byte, 0, len(body)-end+start+len(encoded))
	result = append(result, body[:start]...)
	result = append(result, encoded...)
	result = append(result, body[end:]...)
	return result, nil
}

// topLevelJSONModelRange performs a strict object walk sufficient to locate
// the string value of the top-level model property. json.Valid handles the
// complete grammar; this walker preserves the original value byte offsets.
func topLevelJSONModelRange(body []byte) (string, int, int, error) {
	if !json.Valid(body) {
		return "", 0, 0, errors.New("invalid JSON")
	}
	i := skipJSONWhitespace(body, 0)
	if i >= len(body) || body[i] != '{' {
		return "", 0, 0, errors.New("top-level request is not an object")
	}
	i++
	seen := false
	model, start, end := "", -1, -1
	for {
		i = skipJSONWhitespace(body, i)
		if i >= len(body) {
			return "", 0, 0, errors.New("truncated JSON object")
		}
		if body[i] == '}' {
			break
		}
		key, next, err := readJSONStringAt(body, i)
		if err != nil {
			return "", 0, 0, err
		}
		i = skipJSONWhitespace(body, next)
		if i >= len(body) || body[i] != ':' {
			return "", 0, 0, errors.New("missing JSON colon")
		}
		i = skipJSONWhitespace(body, i+1)
		valueStart := i
		valueEnd, err := skipJSONValue(body, i)
		if err != nil {
			return "", 0, 0, err
		}
		if key == "model" {
			if seen || valueStart >= len(body) || body[valueStart] != '"' {
				return "", 0, 0, errors.New("duplicate or non-string model")
			}
			decoded, _, err := readJSONStringAt(body, valueStart)
			if err != nil {
				return "", 0, 0, err
			}
			seen, model, start, end = true, decoded, valueStart, valueEnd
		}
		i = skipJSONWhitespace(body, valueEnd)
		if i >= len(body) {
			return "", 0, 0, errors.New("truncated JSON object")
		}
		if body[i] == '}' {
			break
		}
		if body[i] != ',' {
			return "", 0, 0, errors.New("missing JSON comma")
		}
		i++
	}
	if !seen {
		return "", -1, -1, errors.New("model is missing")
	}
	return model, start, end, nil
}

func skipJSONWhitespace(body []byte, i int) int {
	for i < len(body) && (body[i] == ' ' || body[i] == '\t' || body[i] == '\r' || body[i] == '\n') {
		i++
	}
	return i
}

func readJSONStringAt(body []byte, start int) (string, int, error) {
	if start >= len(body) || body[start] != '"' {
		return "", start, errors.New("expected JSON string")
	}
	i, escaped := start+1, false
	for i < len(body) {
		if escaped {
			escaped = false
		} else if body[i] == '\\' {
			escaped = true
		} else if body[i] == '"' {
			var value string
			if err := json.Unmarshal(body[start:i+1], &value); err != nil {
				return "", start, err
			}
			return value, i + 1, nil
		}
		i++
	}
	return "", start, errors.New("unterminated JSON string")
}

func skipJSONValue(body []byte, start int) (int, error) {
	if start >= len(body) {
		return 0, errors.New("missing JSON value")
	}
	if body[start] == '"' {
		_, end, err := readJSONStringAt(body, start)
		return end, err
	}
	if body[start] != '{' && body[start] != '[' {
		i := start
		for i < len(body) && !strings.ContainsRune(",}] \t\r\n", rune(body[i])) {
			i++
		}
		if i == start {
			return 0, errors.New("invalid JSON scalar")
		}
		return i, nil
	}
	depth, inString, escaped := 0, false, false
	for i := start; i < len(body); i++ {
		value := body[i]
		if inString {
			if escaped {
				escaped = false
			} else if value == '\\' {
				escaped = true
			} else if value == '"' {
				inString = false
			}
			continue
		}
		switch value {
		case '"':
			inString = true
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				return i + 1, nil
			}
			if depth < 0 {
				return 0, errors.New("invalid JSON nesting")
			}
		}
	}
	return 0, errors.New("unterminated JSON value")
}
