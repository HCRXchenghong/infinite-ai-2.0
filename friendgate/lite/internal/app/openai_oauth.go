package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	openAIOAuthClientID    = "app_EMoamEEZ73f0CkXaXp7hrann"
	openAIOAuthRedirectURI = "http://localhost:1455/auth/callback"
	openAIOAuthAuthorize   = "https://auth.openai.com/oauth/authorize"
	openAIOAuthToken       = "https://auth.openai.com/oauth/token"
	openAIOAuthTTL         = 30 * time.Minute
)

// openAIOAuthFlow contains the temporary PKCE verifier required to redeem one
// callback. It is stored encrypted for only openAIOAuthTTL so a browser refresh
// or service restart does not strand an otherwise valid callback.
type openAIOAuthFlow struct {
	SessionID    string
	State        string
	CodeVerifier string
	OwnerHash    string
	IP           string
	CreatedAt    time.Time
	Redeeming    bool
}

type openAITokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

func (s *Server) startOpenAIOAuth(ownerHash, ip string) (sessionID, authURL string, expiresAt int64, err error) {
	// Match the official Codex OAuth implementation byte-for-byte: state uses
	// 32 random bytes as hex, the PKCE verifier uses 64 random bytes as hex,
	// and the transient session id uses 16 random bytes as hex.
	state, err := randomHex(32)
	if err != nil {
		return "", "", 0, err
	}
	verifier, err := randomHex(64)
	if err != nil {
		return "", "", 0, err
	}
	sessionID, err = randomHex(16)
	if err != nil {
		return "", "", 0, err
	}
	now := time.Now()
	s.oauthMu.Lock()
	for id, flow := range s.oauthFlows {
		if now.Sub(flow.CreatedAt) > openAIOAuthTTL {
			delete(s.oauthFlows, id)
		}
	}
	flow := &openAIOAuthFlow{
		SessionID: sessionID, State: state, CodeVerifier: verifier, OwnerHash: ownerHash, IP: ip, CreatedAt: now,
	}
	s.oauthFlows[sessionID] = flow
	s.oauthMu.Unlock()
	if err := s.store.SaveOpenAIOAuthFlow(context.Background(), flow); err != nil {
		s.oauthMu.Lock()
		delete(s.oauthFlows, sessionID)
		s.oauthMu.Unlock()
		return "", "", 0, err
	}
	_ = s.store.CleanupOpenAIOAuthFlows(context.Background(), now.Add(-openAIOAuthTTL))

	challengeSum := sha256.Sum256([]byte(verifier))
	params := url.Values{
		"response_type":              {"code"},
		"client_id":                  {openAIOAuthClientID},
		"redirect_uri":               {openAIOAuthRedirectURI},
		"scope":                      {"openid profile email offline_access"},
		"state":                      {state},
		"code_challenge":             {base64.RawURLEncoding.EncodeToString(challengeSum[:])},
		"code_challenge_method":      {"S256"},
		"id_token_add_organizations": {"true"},
		"codex_cli_simplified_flow":  {"true"},
	}
	return sessionID, openAIOAuthAuthorize + "?" + params.Encode(), now.Add(openAIOAuthTTL).Unix(), nil
}

func randomHex(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

// beginOpenAIOAuth marks a flow as in use. Its owner and source IP bindings
// prevent a session ID copied from an admin page from being redeemed elsewhere.
func (s *Server) beginOpenAIOAuth(sessionID, state, ownerHash, ip string) (*openAIOAuthFlow, error) {
	if state == "" {
		return nil, errors.New("OAuth state 缺失，请重新生成授权链接")
	}
	s.oauthMu.Lock()
	defer s.oauthMu.Unlock()
	flow := s.oauthFlows[sessionID]
	if flow == nil {
		stored, err := s.store.OpenAIOAuthFlow(context.Background(), state)
		if err != nil {
			return nil, errors.New("OAuth 会话读取失败，请重新生成授权链接")
		}
		if stored != nil {
			if sessionID != "" && subtle.ConstantTimeCompare([]byte(stored.SessionID), []byte(sessionID)) != 1 {
				return nil, errors.New("OAuth 会话与回跳链接不匹配，请粘贴同一次授权返回的完整 localhost 链接")
			}
			flow = stored
			s.oauthFlows[flow.SessionID] = flow
		}
	}
	if flow == nil || time.Since(flow.CreatedAt) > openAIOAuthTTL {
		delete(s.oauthFlows, sessionID)
		_ = s.store.DeleteOpenAIOAuthFlow(context.Background(), state)
		return nil, errors.New("OAuth 会话已失效，请重新生成授权链接")
	}
	if subtle.ConstantTimeCompare([]byte(flow.OwnerHash), []byte(ownerHash)) != 1 ||
		subtle.ConstantTimeCompare([]byte(flow.IP), []byte(ip)) != 1 {
		return nil, errors.New("OAuth 会话不属于当前管理员登录")
	}
	if subtle.ConstantTimeCompare([]byte(flow.State), []byte(state)) != 1 {
		return nil, errors.New("OAuth state 校验失败，请粘贴同一次授权返回的完整 localhost 链接")
	}
	if flow.Redeeming {
		return nil, errors.New("OAuth 授权正在处理，请稍候")
	}
	flow.Redeeming = true
	copy := *flow
	return &copy, nil
}

func (s *Server) releaseOpenAIOAuth(sessionID string) {
	s.oauthMu.Lock()
	defer s.oauthMu.Unlock()
	if flow := s.oauthFlows[sessionID]; flow != nil {
		flow.Redeeming = false
	}
}

func (s *Server) consumeOpenAIOAuth(sessionID string) {
	s.oauthMu.Lock()
	flow := s.oauthFlows[sessionID]
	if flow != nil {
		_ = s.store.DeleteOpenAIOAuthFlow(context.Background(), flow.State)
	}
	delete(s.oauthFlows, sessionID)
	s.oauthMu.Unlock()
}

func parseOpenAICallback(raw string) (code, state string, err error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", "", errors.New("请粘贴 OpenAI 登录后跳转回来的完整 localhost 链接")
	}
	callback, err := url.ParseRequestURI(value)
	if err != nil {
		return "", "", errors.New("回跳链接格式不正确")
	}
	if callback.Scheme != "http" || !strings.EqualFold(callback.Hostname(), "localhost") || callback.Port() != "1455" || callback.Path != "/auth/callback" || callback.User != nil {
		return "", "", errors.New("回跳链接必须是 http://localhost:1455/auth/callback 开头的完整链接")
	}
	query := callback.Query()
	if upstreamError := strings.TrimSpace(query.Get("error")); upstreamError != "" {
		return "", "", fmt.Errorf("OpenAI 授权未完成：%s", upstreamError)
	}
	code, state = strings.TrimSpace(query.Get("code")), strings.TrimSpace(query.Get("state"))
	if code == "" || state == "" {
		return "", "", errors.New("回跳链接缺少 code 或 state，请复制完整链接")
	}
	return code, state, nil
}

func (s *Server) exchangeOpenAIOAuth(ctx context.Context, code string, flow *openAIOAuthFlow) (Account, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {openAIOAuthClientID},
		"code":          {code},
		"redirect_uri":  {openAIOAuthRedirectURI},
		"code_verifier": {flow.CodeVerifier},
	}
	exchangeCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(exchangeCtx, http.MethodPost, openAIOAuthToken, strings.NewReader(form.Encode()))
	if err != nil {
		return Account{}, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("User-Agent", "codex-cli/0.144.1")
	response, err := s.client.Do(request)
	if err != nil {
		return Account{}, fmt.Errorf("联系 OpenAI 兑换授权码失败：%w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return Account{}, errors.New("读取 OpenAI 授权响应失败")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		detail := strings.TrimSpace(string(body))
		if len(detail) > 300 {
			detail = detail[:300] + "..."
		}
		if detail == "" {
			detail = "请重新生成链接后再试"
		}
		return Account{}, fmt.Errorf("OpenAI 拒绝兑换授权码（状态 %d）：%s", response.StatusCode, detail)
	}
	var token openAITokenResponse
	if err := json.Unmarshal(body, &token); err != nil || strings.TrimSpace(token.AccessToken) == "" {
		return Account{}, errors.New("OpenAI 返回的授权数据无效")
	}
	accountID, expiresAt := jwtAccountAndExpiry(token.IDToken)
	if accountID == "" {
		accountID, expiresAt = jwtAccountAndExpiry(token.AccessToken)
	}
	if accountID == "" {
		return Account{}, errors.New("无法从 OpenAI 令牌确认 ChatGPT 账号，请重新登录授权")
	}
	if expiresAt == 0 && token.ExpiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second).Unix()
	}
	return Account{
		AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, ChatGPTAccountID: accountID,
		ClientID: openAIOAuthClientID, ExpiresAt: expiresAt,
	}, nil
}
