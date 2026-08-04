package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
)

const (
	responsesWSFirstMessageTimeout = 20 * time.Second
	responsesWSWriteTimeout        = 30 * time.Second
)

var errResponsesWSModelChanged = errors.New("Responses WebSocket model is not available on the selected account")

type responsesWSClientEvent struct {
	Type           string `json:"type"`
	Model          string `json:"model"`
	PromptCacheKey string `json:"prompt_cache_key"`
	Session        struct {
		Model string `json:"model"`
	} `json:"session"`
}

type responsesWSRelayResult struct {
	model        string
	inputTokens  int64
	outputTokens int64
	totalTokens  int64
	requestID    string
	err          error
}

func isResponsesWebSocket(r *http.Request, suffix string) bool {
	if r == nil || r.Method != http.MethodGet || suffix != "/responses" {
		return false
	}
	return headerHasToken(r.Header, "Connection", "upgrade") && headerHasToken(r.Header, "Upgrade", "websocket")
}

func headerHasToken(header http.Header, name, want string) bool {
	for _, value := range header.Values(name) {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), want) {
				return true
			}
		}
	}
	return false
}

func (s *Server) serveResponsesWebSocket(w http.ResponseWriter, r *http.Request, key *APIKey, ip, suffix string, startedAt time.Time) {
	requestedProtocols := validWebSocketSubprotocols(r.Header.Values("Sec-WebSocket-Protocol"))
	clientConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: requestedProtocols,
		// Compression is deliberately disabled on both sides. JSON message bytes
		// remain identical while each peer still gets independent ping/pong handling.
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		slog.Warn("Responses WebSocket client handshake failed", "ip", ip, "error", safeProxyError(err))
		return
	}
	clientConn.SetReadLimit(s.cfg.MaxBodyBytes)
	defer clientConn.CloseNow()

	firstCtx, cancelFirst := context.WithTimeout(r.Context(), responsesWSFirstMessageTimeout)
	firstType, firstPayload, err := clientConn.Read(firstCtx)
	cancelFirst()
	if err != nil {
		writeResponsesWSError(clientConn, "first_message_required", "首个 response.create 消息读取失败")
		return
	}
	desktop, _ := r.Context().Value(desktopProxyContextKey{}).(bool)
	managedInstructions := ""
	if desktop {
		managedInstructions = strings.TrimSpace(s.currentDesktopPolicy().SystemPrompt)
		if managedInstructions != "" {
			firstPayload, err = injectManagedWSInstructions(firstPayload, managedInstructions, s.cfg.MaxBodyBytes)
			if err != nil {
				writeResponsesWSError(clientConn, "invalid_first_message", "首个 WebSocket 消息无法应用后台系统提示词")
				return
			}
		}
	}
	firstEvent, err := parseResponsesWSClientEvent(firstPayload)
	if err != nil || (firstType != websocket.MessageText && firstType != websocket.MessageBinary) {
		writeResponsesWSError(clientConn, "invalid_first_message", "首个 WebSocket 消息必须是合法 JSON")
		return
	}
	requestedModel := strings.TrimSpace(firstEvent.Model)
	if requestedModel == "" {
		requestedModel = strings.TrimSpace(firstEvent.Session.Model)
	}
	if requestedModel == "" {
		writeResponsesWSError(clientConn, "model_required", "首个 response.create 消息必须包含模型")
		return
	}
	promptCacheKey := truncate(strings.TrimSpace(firstEvent.PromptCacheKey), 256)
	compactSeed, _ := randomToken(18)
	affinityHash := accountAffinityHash(r, key.ID, suffix, promptCacheKey, compactSeed)
	account, err := s.store.SelectAccountForModel(r.Context(), key.ID, affinityHash, requestedModel, s.cfg.StickyTTL)
	if err != nil {
		writeResponsesWSRoutingError(clientConn, err)
		return
	}
	account, err = s.refreshAccountIfNeeded(r.Context(), account)
	if err != nil {
		s.store.MarkAccountCooldown(context.Background(), account.ID, time.Now().Add(s.cfg.AccountCooldown).Unix(), safeProxyError(err))
		writeResponsesWSError(clientConn, "token_refresh_failed", "ChatGPT 授权已过期且刷新失败")
		return
	}

	var admitted *http.Request
	var finishRequest func()
	if desktop {
		admitted, finishRequest, err = s.beginDesktopKeyRequest(r, key.ID, account.ID, ip)
	} else {
		admitted, finishRequest, err = s.beginKeyRequestWithDevice(r, key.ID, account.ID, ip, extractDeviceToken(r))
	}
	if err != nil {
		writeResponsesWSRoutingError(clientConn, err)
		return
	}
	var upstreamConn *websocket.Conn
	defer func() {
		if upstreamConn != nil {
			_ = upstreamConn.CloseNow()
		}
		_ = clientConn.CloseNow()
		finishRequest()
	}()
	if !desktop {
		s.store.TouchKeyIP(admitted.Context(), key.ID, ip)
		s.store.TouchKeyDevice(admitted.Context(), key.ID, extractDeviceToken(r))
	}

	upstreamURL, upstreamHeader, err := s.responsesWSUpstreamRequest(admitted, key, account, suffix, promptCacheKey, compactSeed)
	if err != nil {
		writeResponsesWSError(clientConn, "upstream_invalid", "ChatGPT WebSocket 上游地址无效")
		s.logResponsesWSUsage(startedAt, key.ID, account.ID, ip, r.URL.Path, requestedModel, http.StatusInternalServerError, 0, 0, 0, "", safeProxyError(err))
		return
	}

	dialCtx, cancelDial := context.WithTimeout(admitted.Context(), 30*time.Second)
	upstreamConn, response, err := websocket.Dial(dialCtx, upstreamURL, &websocket.DialOptions{
		HTTPClient:      s.client,
		HTTPHeader:      upstreamHeader,
		Subprotocols:    requestedProtocols,
		CompressionMode: websocket.CompressionDisabled,
	})
	cancelDial()
	if err != nil {
		if status, code, message, detail, cancelled := responsesWSLifecycleFailure(admitted.Context()); cancelled {
			writeResponsesWSError(clientConn, code, message)
			s.logResponsesWSUsage(startedAt, key.ID, account.ID, ip, r.URL.Path, requestedModel, status, 0, 0, 0, "", detail)
			return
		}
		status := http.StatusBadGateway
		if response != nil && response.StatusCode > 0 {
			status = response.StatusCode
		}
		detail := safeProxyError(err)
		writeResponsesWSError(clientConn, "upstream_websocket_failed", "连接 ChatGPT WebSocket 上游失败")
		s.logResponsesWSUsage(startedAt, key.ID, account.ID, ip, r.URL.Path, requestedModel, status, 0, 0, 0, "", detail)
		s.recordResponsesWSAccountResult(account.ID, status, response, detail)
		return
	}
	upstreamConn.SetReadLimit(s.cfg.MaxBodyBytes)
	if clientConn.Subprotocol() != upstreamConn.Subprotocol() {
		writeResponsesWSError(clientConn, "subprotocol_mismatch", "ChatGPT WebSocket 子协议不兼容")
		s.logResponsesWSUsage(startedAt, key.ID, account.ID, ip, r.URL.Path, requestedModel, http.StatusBadGateway, 0, 0, 0, "", "upstream WebSocket subprotocol mismatch")
		return
	}

	writeCtx, cancelWrite := context.WithTimeout(admitted.Context(), responsesWSWriteTimeout)
	err = upstreamConn.Write(writeCtx, firstType, firstPayload)
	cancelWrite()
	if err != nil {
		if status, code, message, detail, cancelled := responsesWSLifecycleFailure(admitted.Context()); cancelled {
			writeResponsesWSError(clientConn, code, message)
			s.logResponsesWSUsage(startedAt, key.ID, account.ID, ip, r.URL.Path, requestedModel, status, 0, 0, 0, "", detail)
			return
		}
		detail := safeProxyError(err)
		writeResponsesWSError(clientConn, "upstream_write_failed", "ChatGPT WebSocket 首帧发送失败")
		s.logResponsesWSUsage(startedAt, key.ID, account.ID, ip, r.URL.Path, requestedModel, http.StatusBadGateway, 0, 0, 0, "", detail)
		s.store.MarkAccountResult(context.Background(), account.ID, detail)
		return
	}

	relay := s.relayResponsesWebSocket(admitted.Context(), clientConn, upstreamConn, account.ID, requestedModel, managedInstructions)
	status, detail := responsesWSRelayStatus(admitted.Context(), relay.err)
	s.logResponsesWSUsage(startedAt, key.ID, account.ID, ip, r.URL.Path, relay.model, status, relay.inputTokens, relay.outputTokens, relay.totalTokens, relay.requestID, detail)
	_, _, _, _, lifecycleCancelled := responsesWSLifecycleFailure(admitted.Context())
	if status >= http.StatusBadRequest && !lifecycleCancelled {
		s.store.MarkAccountResult(context.Background(), account.ID, detail)
	} else if status < http.StatusBadRequest {
		s.store.MarkAccountResult(context.Background(), account.ID, "")
	}
}

func parseResponsesWSClientEvent(payload []byte) (responsesWSClientEvent, error) {
	var event responsesWSClientEvent
	if len(payload) == 0 || json.Unmarshal(payload, &event) != nil {
		return responsesWSClientEvent{}, errors.New("invalid Responses WebSocket JSON")
	}
	event.Type = strings.TrimSpace(event.Type)
	event.Model = strings.TrimSpace(event.Model)
	event.Session.Model = strings.TrimSpace(event.Session.Model)
	return event, nil
}

func injectManagedWSInstructions(payload []byte, managedInstructions string, limit int64) ([]byte, error) {
	managedInstructions = strings.TrimSpace(managedInstructions)
	if managedInstructions == "" {
		return payload, nil
	}
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return nil, errors.New("Responses WebSocket event must be a JSON object")
	}
	encoded, err := json.Marshal(managedInstructions)
	if err != nil {
		return nil, err
	}
	closingOffset := bytes.LastIndexByte(payload, '}')
	separator := []byte(",")
	if len(bytes.TrimSpace(trimmed[1:len(trimmed)-1])) == 0 {
		separator = nil
	}
	result := make([]byte, 0, closingOffset+len(separator)+len(encoded)+18)
	result = append(result, payload[:closingOffset]...)
	result = append(result, separator...)
	result = append(result, `"instructions":`...)
	result = append(result, encoded...)
	result = append(result, '}')
	if int64(len(result)) > limit {
		return nil, errors.New("managed Responses WebSocket event exceeds request limit")
	}
	return result, nil
}

func (s *Server) responsesWSUpstreamRequest(r *http.Request, key *APIKey, account *Account, suffix, promptCacheKey, compactSeed string) (string, http.Header, error) {
	target, err := url.Parse(s.cfg.UpstreamBaseURL + suffix)
	if err != nil || target.Scheme == "" || target.Host == "" || target.Fragment != "" {
		return "", nil, errors.New("invalid Responses WebSocket upstream URL")
	}
	target.RawQuery = r.URL.RawQuery
	request := r.Clone(r.Context())
	request.URL = &url.URL{Scheme: target.Scheme, Host: target.Host, Path: target.Path, RawQuery: target.RawQuery}
	request.Header = r.Header.Clone()
	s.prepareUpstreamRequest(request, target, key, account, suffix, promptCacheKey, compactSeed)
	for _, name := range []string{
		"Connection", "Upgrade", "Sec-WebSocket-Key", "Sec-WebSocket-Version",
		"Sec-WebSocket-Extensions", "Sec-WebSocket-Protocol", "Content-Length",
	} {
		request.Header.Del(name)
	}
	return target.String(), request.Header, nil
}

func (s *Server) relayResponsesWebSocket(ctx context.Context, clientConn, upstreamConn *websocket.Conn, accountID int64, initialModel, managedInstructions string) responsesWSRelayResult {
	relayCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type directionResult struct {
		direction string
		result    responsesWSRelayResult
	}
	results := make(chan directionResult, 2)
	go func() {
		model := initialModel
		for {
			messageType, payload, err := clientConn.Read(relayCtx)
			if err != nil {
				results <- directionResult{direction: "client", result: responsesWSRelayResult{model: model, err: err}}
				return
			}
			event, parseErr := parseResponsesWSClientEvent(payload)
			if parseErr == nil {
				candidate := ""
				switch event.Type {
				case "response.create":
					candidate = event.Model
				case "session.update":
					candidate = event.Session.Model
				}
				if candidate != "" {
					if err := s.requireAccountModel(relayCtx, accountID, candidate); err != nil {
						writeResponsesWSError(clientConn, "model_not_available", "当前 WebSocket 绑定账号不支持切换后的模型")
						results <- directionResult{direction: "client", result: responsesWSRelayResult{model: model, err: fmt.Errorf("%w: %v", errResponsesWSModelChanged, err)}}
						return
					}
					model = candidate
				}
				if event.Type == "response.create" && managedInstructions != "" {
					payload, err = injectManagedWSInstructions(payload, managedInstructions, s.cfg.MaxBodyBytes)
					if err != nil {
						writeResponsesWSError(clientConn, "managed_instructions_failed", "后台系统提示词无法应用到当前请求")
						results <- directionResult{direction: "client", result: responsesWSRelayResult{model: model, err: err}}
						return
					}
				}
			}
			writeCtx, cancelWrite := context.WithTimeout(relayCtx, responsesWSWriteTimeout)
			err = upstreamConn.Write(writeCtx, messageType, payload)
			cancelWrite()
			if err != nil {
				results <- directionResult{direction: "client", result: responsesWSRelayResult{model: model, err: err}}
				return
			}
		}
	}()
	go func() {
		result := responsesWSRelayResult{model: initialModel}
		for {
			messageType, payload, err := upstreamConn.Read(relayCtx)
			if err != nil {
				result.err = err
				results <- directionResult{direction: "upstream", result: result}
				return
			}
			input, output, total := parseUsage(payload)
			if input != 0 || output != 0 || total != 0 {
				result.inputTokens += input
				result.outputTokens += output
				result.totalTokens += total
			}
			if result.requestID == "" {
				result.requestID = responsesWSRequestID(payload)
			}
			writeCtx, cancelWrite := context.WithTimeout(relayCtx, responsesWSWriteTimeout)
			err = clientConn.Write(writeCtx, messageType, payload)
			cancelWrite()
			if err != nil {
				result.err = err
				results <- directionResult{direction: "upstream", result: result}
				return
			}
		}
	}()

	first := <-results
	cancel()
	propagateResponsesWSClose(first.result.err, clientConn, upstreamConn, first.direction)
	_ = clientConn.CloseNow()
	_ = upstreamConn.CloseNow()
	second := <-results
	combined := first.result
	if first.direction == "client" {
		combined.inputTokens = second.result.inputTokens
		combined.outputTokens = second.result.outputTokens
		combined.totalTokens = second.result.totalTokens
		combined.requestID = second.result.requestID
	} else {
		combined.model = second.result.model
	}
	return combined
}

func (s *Server) requireAccountModel(ctx context.Context, accountID int64, model string) error {
	model = strings.TrimSpace(model)
	if model == "" || len(model) > maxModelIDBytes || strings.ContainsAny(model, "\x00\r\n") {
		return ErrModelNotAvailable
	}
	var count int
	err := s.store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM account_models model
		JOIN account_model_snapshots snapshot ON snapshot.account_id=model.account_id AND snapshot.updated_at>0 AND snapshot.manifest_json<>''
		JOIN accounts account ON account.id=model.account_id AND account.active=1 AND account.access_token_enc<>''
		WHERE model.account_id=? AND model.model_id=?`, accountID, model).Scan(&count)
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrModelNotAvailable
	}
	return nil
}

func responsesWSRequestID(payload []byte) string {
	var event struct {
		RequestID string `json:"request_id"`
		Response  struct {
			ID string `json:"id"`
		} `json:"response"`
	}
	if json.Unmarshal(payload, &event) != nil {
		return ""
	}
	if value := strings.TrimSpace(event.RequestID); value != "" {
		return truncate(value, 200)
	}
	return truncate(strings.TrimSpace(event.Response.ID), 200)
}

func writeResponsesWSRoutingError(conn *websocket.Conn, err error) {
	switch {
	case errors.Is(err, ErrModelCatalogUnavailable):
		writeResponsesWSError(conn, "model_catalog_unavailable", "模型目录尚未完成真实同步")
	case errors.Is(err, ErrModelNotAvailable):
		writeResponsesWSError(conn, "model_not_available", "当前账号池不支持请求的模型")
	case errors.Is(err, ErrKeyInactive):
		writeResponsesWSError(conn, "key_inactive", "该密钥已被停用或删除")
	case errors.Is(err, ErrIPNotAllowed):
		writeResponsesWSError(conn, "ip_not_allowed", "当前 IP 授权已被删除")
	case errors.Is(err, ErrDeviceNotAllowed):
		writeResponsesWSError(conn, "device_not_allowed", "设备凭证缺失、无效或已被撤销")
	case errors.Is(err, errIPAccessBanned):
		writeResponsesWSError(conn, "ip_banned", "来源 IP 已被安全策略封禁")
	case errors.Is(err, errAccountAccessRevoked):
		writeResponsesWSError(conn, "account_unavailable", "ChatGPT 账号已被管理员停用或删除")
	case errors.Is(err, errDesktopSessionRevoked):
		writeResponsesWSError(conn, "desktop_session_invalid", "Infinite AI 登录或设备授权已被撤销")
	case errors.Is(err, ErrNoAccount):
		writeResponsesWSError(conn, "account_pool_unavailable", "ChatGPT 账号池当前没有可用账号")
	case errors.Is(err, ErrQuotaExceeded):
		writeResponsesWSError(conn, "quota_exceeded", "该密钥的可用额度已用完")
	default:
		writeResponsesWSError(conn, "gateway_unavailable", "Codex 网关当前不可用")
	}
}

func writeResponsesWSError(conn *websocket.Conn, code, message string) {
	if conn == nil {
		return
	}
	payload, _ := json.Marshal(map[string]any{
		"type": "error",
		"error": map[string]string{
			"type": "invalid_request_error", "code": code, "message": message,
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_ = conn.Write(ctx, websocket.MessageText, payload)
	cancel()
}

func validWebSocketSubprotocols(values []string) []string {
	protocols := make([]string, 0, 4)
	seen := make(map[string]bool)
	for _, value := range values {
		for _, candidate := range strings.Split(value, ",") {
			candidate = strings.TrimSpace(candidate)
			if candidate == "" || len(candidate) > 128 || !validWebSocketToken(candidate) || seen[candidate] {
				continue
			}
			seen[candidate] = true
			protocols = append(protocols, candidate)
			if len(protocols) == 8 {
				return protocols
			}
		}
	}
	return protocols
}

func validWebSocketToken(value string) bool {
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' {
			continue
		}
		if !strings.ContainsRune("!#$%&'*+-.^_`|~", character) {
			return false
		}
	}
	return value != ""
}

func propagateResponsesWSClose(err error, clientConn, upstreamConn *websocket.Conn, direction string) {
	status := websocket.CloseStatus(err)
	if status < 0 {
		return
	}
	reason := "peer closed"
	var closeErr websocket.CloseError
	if errors.As(err, &closeErr) && strings.TrimSpace(closeErr.Reason) != "" {
		reason = truncate(closeErr.Reason, 100)
	}
	if direction == "client" {
		_ = upstreamConn.Close(status, reason)
	} else {
		_ = clientConn.Close(status, reason)
	}
}

func responsesWSRelayStatus(ctx context.Context, err error) (int, string) {
	if status, _, _, detail, cancelled := responsesWSLifecycleFailure(ctx); cancelled {
		return status, detail
	}
	if errors.Is(err, errResponsesWSModelChanged) {
		return http.StatusBadRequest, "WebSocket model is not available on the bound account"
	}
	status := websocket.CloseStatus(err)
	if status == websocket.StatusNormalClosure || status == websocket.StatusGoingAway || err == nil {
		return http.StatusOK, ""
	}
	if errors.Is(err, context.Canceled) && context.Cause(ctx) == nil {
		return http.StatusOK, ""
	}
	return http.StatusBadGateway, safeProxyError(err)
}

// responsesWSLifecycleFailure keeps administrative cancellation truthful even
// when it races the upstream WebSocket dial or first write. In particular,
// disabling an account must never be reported to the client or usage log as an
// invalid API key or as an upstream transport failure.
func responsesWSLifecycleFailure(ctx context.Context) (status int, code, message, detail string, ok bool) {
	switch cause := context.Cause(ctx); {
	case errors.Is(cause, errKeyAccessRevoked):
		return http.StatusUnauthorized, "key_inactive", "该密钥已被停用或删除", "key access revoked by administrator", true
	case errors.Is(cause, errAccountAccessRevoked):
		return http.StatusServiceUnavailable, "account_unavailable", "ChatGPT 账号已被管理员停用或删除", "ChatGPT account access revoked by administrator", true
	case errors.Is(cause, errDesktopSessionRevoked):
		return http.StatusUnauthorized, "desktop_session_invalid", "Infinite AI 登录或设备授权已被撤销", "Infinite AI desktop session revoked", true
	case errors.Is(cause, errIPAccessBanned):
		return http.StatusForbidden, "ip_banned", "来源 IP 已被安全策略封禁", "source IP banned by administrator or security policy", true
	default:
		return 0, "", "", "", false
	}
}

func (s *Server) logResponsesWSUsage(startedAt time.Time, keyID, accountID int64, ip, path, model string, status int, input, output, total int64, requestID, detail string) {
	item := UsageLog{
		IP: ip, Method: http.MethodGet, Path: path, Model: model, Status: status,
		DurationMS: time.Since(startedAt).Milliseconds(), InputTokens: input,
		OutputTokens: output, TotalTokens: total, RequestID: requestID, Error: detail,
	}
	if err := s.store.LogUsage(context.Background(), keyID, accountID, item); err != nil {
		slog.Error("Responses WebSocket usage log persistence failed", "key_id", keyID, "account_id", accountID, "error", err)
	}
}

func (s *Server) recordResponsesWSAccountResult(accountID int64, status int, response *http.Response, detail string) {
	if status == http.StatusTooManyRequests {
		retry := s.cfg.AccountCooldown
		if response != nil {
			retry = retryAfterDuration(response.Header.Get("Retry-After"), retry)
		}
		s.store.MarkAccountCooldown(context.Background(), accountID, time.Now().Add(retry).Unix(), detail)
		return
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden || status >= http.StatusInternalServerError {
		s.store.MarkAccountResult(context.Background(), accountID, detail)
	}
}
