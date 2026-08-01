package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func oauthTestJWT(t *testing.T, accountID string, expiresAt int64) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"exp": float64(expiresAt),
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": accountID,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func TestOpenAIOAuthUsesPKCEAndValidatesLocalhostCallback(t *testing.T) {
	server, _ := testApp(t)
	ownerHash, ip := "admin-session-hash", "203.0.113.56"
	sessionID, authorizationURL, expiresAt, err := server.startOpenAIOAuth(ownerHash, ip)
	if err != nil {
		t.Fatal(err)
	}
	if sessionID == "" || expiresAt <= time.Now().Unix() {
		t.Fatalf("invalid OAuth session result: id=%q expires=%d", sessionID, expiresAt)
	}
	if len(sessionID) != 32 {
		t.Fatalf("session id does not match official Codex hex format: %q", sessionID)
	}
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if parsed.Scheme != "https" || parsed.Host != "auth.openai.com" || parsed.Path != "/oauth/authorize" ||
		query.Get("client_id") != openAIOAuthClientID || query.Get("redirect_uri") != openAIOAuthRedirectURI ||
		query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" || query.Get("state") == "" {
		t.Fatalf("unexpected authorization URL: %s", authorizationURL)
	}

	code, state, err := parseOpenAICallback(openAIOAuthRedirectURI + "?code=returned-code&state=" + url.QueryEscape(query.Get("state")))
	if err != nil || code != "returned-code" || state != query.Get("state") {
		t.Fatalf("callback parse code=%q state=%q err=%v", code, state, err)
	}
	flow, err := server.beginOpenAIOAuth(sessionID, state, ownerHash, ip)
	if err != nil || flow.CodeVerifier == "" {
		t.Fatalf("begin OAuth flow=%+v err=%v", flow, err)
	}
	if len(flow.CodeVerifier) != 128 || len(state) != 64 {
		t.Fatalf("OAuth randomness does not match official Codex format: verifier=%d state=%d", len(flow.CodeVerifier), len(state))
	}
	server.releaseOpenAIOAuth(sessionID)
	if _, _, err := parseOpenAICallback("http://127.0.0.1:1455/auth/callback?code=x&state=y"); err == nil {
		t.Fatal("non-localhost callback must be rejected")
	}
	if _, err := server.beginOpenAIOAuth(sessionID, "wrong-state", ownerHash, ip); err == nil {
		t.Fatal("mismatched OAuth state must be rejected")
	}
	if _, err := server.beginOpenAIOAuth(sessionID, state, ownerHash, "203.0.113.57"); err == nil {
		t.Fatal("OAuth flow must be bound to the starting admin IP")
	}
}

func TestOpenAIOAuthCanResumeAfterBrowserOrServerStateLoss(t *testing.T) {
	server, _ := testApp(t)
	ownerHash, ip := "admin-session-hash", "203.0.113.59"
	sessionID, authorizationURL, _, err := server.startOpenAIOAuth(ownerHash, ip)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	server.oauthMu.Lock()
	delete(server.oauthFlows, sessionID)
	server.oauthMu.Unlock()
	flow, err := server.beginOpenAIOAuth("", state, ownerHash, ip)
	if err != nil {
		t.Fatal(err)
	}
	if flow.SessionID != sessionID || flow.State != state || flow.CodeVerifier == "" {
		t.Fatalf("OAuth flow was not restored: %+v", flow)
	}
	server.releaseOpenAIOAuth(flow.SessionID)
	server.consumeOpenAIOAuth(flow.SessionID)
	if _, err := server.beginOpenAIOAuth("", state, ownerHash, ip); err == nil {
		t.Fatal("consumed OAuth flow must not be reusable")
	}
}

func TestOpenAIOAuthExchangesTheReturnedCode(t *testing.T) {
	server, _ := testApp(t)
	sessionID, authorizationURL, _, err := server.startOpenAIOAuth("owner", "203.0.113.58")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := server.beginOpenAIOAuth(sessionID, parsed.Query().Get("state"), "owner", "203.0.113.58")
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().Add(time.Hour).Unix()
	accessToken := oauthTestJWT(t, "acct-oauth", expiresAt)
	server.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.String() != openAIOAuthToken {
			t.Fatalf("unexpected token request %s %s", request.Method, request.URL)
		}
		if request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || request.Header.Get("User-Agent") != "codex-cli/0.144.1" {
			t.Fatalf("unexpected token headers: %#v", request.Header)
		}
		body, _ := io.ReadAll(request.Body)
		form, err := url.ParseQuery(string(body))
		if err != nil || form.Get("grant_type") != "authorization_code" || form.Get("client_id") != openAIOAuthClientID ||
			form.Get("redirect_uri") != openAIOAuthRedirectURI || form.Get("code") != "returned-code" || form.Get("code_verifier") != flow.CodeVerifier {
			t.Fatalf("unexpected token form %q err=%v", string(body), err)
		}
		response := `{"access_token":"` + accessToken + `","refresh_token":"fresh-refresh","expires_in":3600}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(response)), Header: make(http.Header), Request: request}, nil
	})}
	account, err := server.exchangeOpenAIOAuth(context.Background(), "returned-code", flow)
	if err != nil {
		t.Fatal(err)
	}
	if account.ChatGPTAccountID != "acct-oauth" || account.AccessToken != accessToken || account.RefreshToken != "fresh-refresh" || account.ExpiresAt != expiresAt || account.ClientID != openAIOAuthClientID {
		t.Fatalf("unexpected OAuth account: %+v", account)
	}
}
