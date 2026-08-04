package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPlatformPortalPostgresIntegration(t *testing.T) {
	dsn := os.Getenv("INFINITE_AI_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("INFINITE_AI_TEST_POSTGRES_URL is not set")
	}
	ctx := context.Background()
	var chatUpstreamBody []byte
	blockedChatStarted := make(chan struct{})
	chatUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" || r.Header.Get("Authorization") != "Bearer portal-chat-upstream-secret" {
			http.Error(w, "unexpected upstream request", http.StatusUnauthorized)
			return
		}
		chatUpstreamBody, _ = io.ReadAll(r.Body)
		if bytes.Contains(chatUpstreamBody, []byte(`"input":"block-chat-until-logout"`)) {
			close(blockedChatStarted)
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"private-portal-chat-model","output_text":"hello **browser**","usage":{"input_tokens":4,"output_tokens":6,"total_tokens":10}}`))
	}))
	defer chatUpstream.Close()
	masterKey := bytes.Repeat([]byte{0x74}, 32)
	vault, err := NewVault(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		DatabasePath: filepath.Join(t.TempDir(), "legacy.db"), PlatformDatabaseURL: dsn, PlatformGatewayEnabled: true,
		PlatformDBMaxOpen: 4, PlatformDBMaxIdle: 2, PlatformDBMaxLife: time.Minute,
		AdminUsername: "admin", AdminPassword: "portal-integration-admin-password", MasterKey: masterKey,
		BanThreshold: 20, BanWindow: time.Minute, BanDuration: time.Hour, MaxBodyBytes: 4 << 20,
		StickyTTL: time.Hour, AccountCooldown: time.Minute, UserSessionTTL: time.Hour,
		DesktopFlowTTL: time.Minute, DesktopAccessTTL: time.Minute, DesktopRefreshTTL: time.Hour,
	}
	store, err := OpenStore(cfg, vault)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	platform := store.Platform()
	previousMode, err := platform.RegistrationMode(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := platform.SetRegistrationMode(ctx, RegistrationInviteOnly, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = platform.SetRegistrationMode(context.Background(), previousMode, "") })

	invite, err := platform.CreatePlatformInvitation(ctx, PlatformInvitationInput{RoleLabel: "Portal integration", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(cfg, store, vault)
	unique := strings.ReplaceAll(newPlatformID(), "-", "")
	payload, _ := json.Marshal(PlatformUserRegistration{Email: unique + "@portal.integration.invalid", DisplayName: "Portal user", Password: "portal-integration-password", InvitationToken: invite.Token, InvitationCode: invite.Code})
	registerReq := httptest.NewRequest(http.MethodPost, "http://portal.integration.invalid/api/portal/register", bytes.NewReader(payload))
	registerReq.Header.Set("Content-Type", "application/json")
	registerReq.Header.Set("User-Agent", "portal-integration-browser")
	registerRec := httptest.NewRecorder()
	server.portalHandler().ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", registerRec.Code, registerRec.Body.String())
	}
	var registered struct {
		Authenticated bool         `json:"authenticated"`
		CSRF          string       `json:"csrf_token"`
		User          PlatformUser `json:"user"`
	}
	if err := json.Unmarshal(registerRec.Body.Bytes(), &registered); err != nil || !registered.Authenticated || registered.CSRF == "" || registered.User.Email == "" {
		t.Fatalf("register payload=%s err=%v", registerRec.Body.String(), err)
	}
	var chatWallets, agentWallets int
	if err := platform.db.QueryRowContext(ctx, `SELECT COUNT(*) FILTER (WHERE product_scope='chat'),COUNT(*) FILTER (WHERE product_scope='agent') FROM wallet_accounts WHERE user_id=$1`, registered.User.ID).Scan(&chatWallets, &agentWallets); err != nil || chatWallets != 1 || agentWallets != 1 {
		t.Fatalf("Free plan did not create separate Chat/Agent wallets: chat=%d agent=%d err=%v", chatWallets, agentWallets, err)
	}
	cookies := registerRec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != platformUserCookieName || cookies[0].Value == "" {
		t.Fatalf("platform cookie=%+v", cookies)
	}
	model, err := platform.CreatePlatformModel(ctx, PlatformModelInput{ModelKey: "portal-model-" + unique, DisplayName: "Portal model", Category: "chat", Capabilities: json.RawMessage(`{}`), Billing: json.RawMessage(`{}`), Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := platform.UpsertProductModelPublication(ctx, ProductModelPublicationInput{ModelID: model.ID, ProductScope: ProductScopeChat, Protocol: "responses", Enabled: true, PlanRules: json.RawMessage(`{"allowed_plans":["free"]}`)}); err != nil {
		t.Fatal(err)
	}
	pool, err := platform.CreateRoutePool(ctx, DefaultPlatformTenantID(), "portal-chat-pool-"+unique, "quota_aware")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := platform.CreateProviderConnection(ctx, ProviderConnectionInput{ProviderKind: "openai_compatible", ProviderName: "portal-chat-provider-" + unique, BaseURL: chatUpstream.URL + "/v1", Credential: "portal-chat-upstream-secret", Settings: json.RawMessage(`{}`), Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	account, err := platform.CreateUpstreamAccount(ctx, UpstreamAccountInput{ConnectionID: provider.ID, Label: "portal chat account", ExternalReference: "portal-chat-account-" + unique, ModelCatalog: json.RawMessage(`[{"id":"private-portal-chat-model"}]`), QuotaState: json.RawMessage(`{}`), Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if err := platform.AddRoutePoolMember(ctx, RoutePoolMemberInput{RoutePoolID: pool.ID, UpstreamAccountID: account.ID, Priority: 1, Weight: 1, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := platform.CreateRouteTarget(ctx, ModelRouteTargetInput{ModelID: model.ID, ProductScope: ProductScopeChat, Protocol: "responses", RoutePoolID: pool.ID, UpstreamModelID: "private-portal-chat-model", Priority: 1, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	modelsReq := httptest.NewRequest(http.MethodGet, "http://portal.integration.invalid/api/portal/models", nil)
	modelsReq.Header.Set("User-Agent", "portal-integration-browser")
	modelsReq.AddCookie(cookies[0])
	modelsRec := httptest.NewRecorder()
	server.portalHandler().ServeHTTP(modelsRec, modelsReq)
	if modelsRec.Code != http.StatusOK || !strings.Contains(modelsRec.Body.String(), model.ModelKey) || !strings.Contains(modelsRec.Body.String(), `"available":true`) || strings.Contains(modelsRec.Body.String(), "private-portal-chat-model") {
		t.Fatalf("portal model catalogue=%d %s", modelsRec.Code, modelsRec.Body.String())
	}
	chatReq := httptest.NewRequest(http.MethodPost, "http://portal.integration.invalid/api/portal/chat/responses", strings.NewReader(`{"model":"`+model.ModelKey+`","input":"hello from browser","max_output_tokens":64}`))
	chatReq.Header.Set("Content-Type", "application/json")
	chatReq.Header.Set("User-Agent", "portal-integration-browser")
	chatReq.Header.Set("X-CSRF-Token", registered.CSRF)
	chatReq.AddCookie(cookies[0])
	chatRec := httptest.NewRecorder()
	server.portalHandler().ServeHTTP(chatRec, chatReq)
	if chatRec.Code != http.StatusOK || !strings.Contains(chatRec.Body.String(), `"total_tokens":10`) || strings.Contains(string(chatUpstreamBody), model.ModelKey) || !strings.Contains(string(chatUpstreamBody), `"model":"private-portal-chat-model"`) {
		t.Fatalf("portal chat status=%d response=%s upstream=%s", chatRec.Code, chatRec.Body.String(), chatUpstreamBody)
	}
	if strings.Contains(chatRec.Body.String(), "private-portal-chat-model") || !strings.Contains(chatRec.Body.String(), `"model":"`+model.ModelKey+`"`) {
		t.Fatalf("portal response leaked upstream model id or lost public model alias: %s", chatRec.Body.String())
	}
	var chatPayload struct {
		Model      string `json:"model"`
		OutputText string `json:"output_text"`
		Meta       struct {
			Conversation PlatformChatConversation `json:"conversation"`
			Messages     []PlatformChatMessage    `json:"messages"`
		} `json:"infinite_ai"`
	}
	if err := json.Unmarshal(chatRec.Body.Bytes(), &chatPayload); err != nil {
		t.Fatalf("portal chat payload JSON: %v body=%s", err, chatRec.Body.String())
	}
	if chatPayload.Model != model.ModelKey || chatPayload.OutputText != "hello **browser**" || chatPayload.Meta.Conversation.ID == "" || len(chatPayload.Meta.Messages) != 2 {
		t.Fatalf("portal chat metadata missing or incorrect: %+v", chatPayload)
	}
	conversationID := chatPayload.Meta.Conversation.ID
	var storedUserMessages, storedAssistantMessages int
	if err := platform.db.QueryRowContext(ctx, `SELECT COUNT(*) FILTER (WHERE role='user' AND model_key=$3),COUNT(*) FILTER (WHERE role='assistant' AND model_key=$3 AND status='sent') FROM chat_messages WHERE conversation_id=$1 AND user_id=$2`, conversationID, registered.User.ID, model.ModelKey).Scan(&storedUserMessages, &storedAssistantMessages); err != nil || storedUserMessages != 1 || storedAssistantMessages != 1 {
		t.Fatalf("Chat messages were not persisted: user=%d assistant=%d err=%v", storedUserMessages, storedAssistantMessages, err)
	}
	listChatReq := httptest.NewRequest(http.MethodGet, "http://portal.integration.invalid/api/portal/chat/conversations", nil)
	listChatReq.Header.Set("User-Agent", "portal-integration-browser")
	listChatReq.AddCookie(cookies[0])
	listChatRec := httptest.NewRecorder()
	server.portalHandler().ServeHTTP(listChatRec, listChatReq)
	if listChatRec.Code != http.StatusOK || !strings.Contains(listChatRec.Body.String(), conversationID) || strings.Contains(listChatRec.Body.String(), "private-portal-chat-model") {
		t.Fatalf("conversation list status=%d body=%s", listChatRec.Code, listChatRec.Body.String())
	}
	getChatReq := httptest.NewRequest(http.MethodGet, "http://portal.integration.invalid/api/portal/chat/conversations/"+conversationID, nil)
	getChatReq.Header.Set("User-Agent", "portal-integration-browser")
	getChatReq.AddCookie(cookies[0])
	getChatRec := httptest.NewRecorder()
	server.portalHandler().ServeHTTP(getChatRec, getChatReq)
	if getChatRec.Code != http.StatusOK || !strings.Contains(getChatRec.Body.String(), "hello **browser**") || strings.Contains(getChatRec.Body.String(), "private-portal-chat-model") {
		t.Fatalf("conversation detail status=%d body=%s", getChatRec.Code, getChatRec.Body.String())
	}
	deleteChatReq := httptest.NewRequest(http.MethodDelete, "http://portal.integration.invalid/api/portal/chat/conversations/"+conversationID, nil)
	deleteChatReq.Header.Set("User-Agent", "portal-integration-browser")
	deleteChatReq.Header.Set("X-CSRF-Token", registered.CSRF)
	deleteChatReq.AddCookie(cookies[0])
	deleteChatRec := httptest.NewRecorder()
	server.portalHandler().ServeHTTP(deleteChatRec, deleteChatReq)
	if deleteChatRec.Code != http.StatusOK {
		t.Fatalf("delete conversation status=%d body=%s", deleteChatRec.Code, deleteChatRec.Body.String())
	}
	deletedChatReq := httptest.NewRequest(http.MethodPost, "http://portal.integration.invalid/api/portal/chat/conversations/"+conversationID+"/responses", strings.NewReader(`{"model":"`+model.ModelKey+`","input":"should not send"}`))
	deletedChatReq.Header.Set("Content-Type", "application/json")
	deletedChatReq.Header.Set("User-Agent", "portal-integration-browser")
	deletedChatReq.Header.Set("X-CSRF-Token", registered.CSRF)
	deletedChatReq.AddCookie(cookies[0])
	deletedChatRec := httptest.NewRecorder()
	server.portalHandler().ServeHTTP(deletedChatRec, deletedChatReq)
	if deletedChatRec.Code == http.StatusOK {
		t.Fatalf("deleted conversation accepted new message: %s", deletedChatRec.Body.String())
	}
	var chatUsage int
	if err := platform.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM usage_records WHERE user_id=$1 AND product_scope='chat' AND api_key_id IS NULL AND billed_tokens=10`, registered.User.ID).Scan(&chatUsage); err != nil || chatUsage != 1 {
		t.Fatalf("Chat usage was not separately recorded: rows=%d err=%v", chatUsage, err)
	}
	// A web logout must terminate a Chat request that is already waiting on an
	// upstream stream, not merely prevent the next browser request.
	streamToken, streamCSRF, err := platform.NewPlatformUserSession(ctx, registered.User.ID, "127.0.0.1", "portal-stream-browser", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	portalHTTP := httptest.NewServer(server.portalHandler())
	defer portalHTTP.Close()
	streamResult := make(chan int, 1)
	go func() {
		request, _ := http.NewRequest(http.MethodPost, portalHTTP.URL+"/api/portal/chat/responses", strings.NewReader(`{"model":"`+model.ModelKey+`","input":"block-chat-until-logout","max_output_tokens":64}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("User-Agent", "portal-stream-browser")
		request.Header.Set("X-CSRF-Token", streamCSRF)
		request.AddCookie(&http.Cookie{Name: platformUserCookieName, Value: streamToken})
		response, requestErr := http.DefaultClient.Do(request)
		if requestErr != nil {
			streamResult <- 0
			return
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		streamResult <- response.StatusCode
	}()
	select {
	case <-blockedChatStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("Chat stream did not reach upstream")
	}
	logoutStreamReq, _ := http.NewRequest(http.MethodPost, portalHTTP.URL+"/api/portal/logout", nil)
	logoutStreamReq.Header.Set("User-Agent", "portal-stream-browser")
	logoutStreamReq.Header.Set("X-CSRF-Token", streamCSRF)
	logoutStreamReq.AddCookie(&http.Cookie{Name: platformUserCookieName, Value: streamToken})
	logoutStreamResponse, err := http.DefaultClient.Do(logoutStreamReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = logoutStreamResponse.Body.Close()
	if logoutStreamResponse.StatusCode != http.StatusOK {
		t.Fatalf("stream logout status=%d", logoutStreamResponse.StatusCode)
	}
	select {
	case status := <-streamResult:
		if status != http.StatusUnauthorized {
			t.Fatalf("logout did not terminate in-flight Chat: status=%d", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight Chat remained open after logout")
	}
	meReq := httptest.NewRequest(http.MethodGet, "http://portal.integration.invalid/api/portal/me", nil)
	meReq.Header.Set("User-Agent", "portal-integration-browser")
	meReq.AddCookie(cookies[0])
	meRec := httptest.NewRecorder()
	server.portalHandler().ServeHTTP(meRec, meReq)
	var me struct {
		Authenticated bool   `json:"authenticated"`
		CSRF          string `json:"csrf_token"`
	}
	if meRec.Code != http.StatusOK || json.Unmarshal(meRec.Body.Bytes(), &me) != nil || !me.Authenticated || me.CSRF == "" || me.CSRF == registered.CSRF {
		t.Fatalf("resumed session=%d %s", meRec.Code, meRec.Body.String())
	}
	logoutReq := httptest.NewRequest(http.MethodPost, "http://portal.integration.invalid/api/portal/logout", nil)
	logoutReq.Header.Set("User-Agent", "portal-integration-browser")
	logoutReq.Header.Set("X-CSRF-Token", me.CSRF)
	logoutReq.AddCookie(cookies[0])
	logoutRec := httptest.NewRecorder()
	server.portalHandler().ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("logout status=%d body=%s", logoutRec.Code, logoutRec.Body.String())
	}
	afterLogout := httptest.NewRequest(http.MethodGet, "http://portal.integration.invalid/api/portal/me", nil)
	afterLogout.Header.Set("User-Agent", "portal-integration-browser")
	afterLogout.AddCookie(cookies[0])
	afterLogoutRec := httptest.NewRecorder()
	server.portalHandler().ServeHTTP(afterLogoutRec, afterLogout)
	if afterLogoutRec.Code != http.StatusOK || !strings.Contains(afterLogoutRec.Body.String(), `"authenticated":false`) {
		t.Fatalf("revoked portal session remained active: status=%d body=%s", afterLogoutRec.Code, afterLogoutRec.Body.String())
	}
}
