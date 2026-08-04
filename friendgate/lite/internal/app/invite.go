package app

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const claimCookieName = "friendgate_claim"

func (s *Server) inviteHandler() http.Handler {
	root := http.NewServeMux()
	static := s.staticHandler("invite.html")
	root.HandleFunc("GET /api/invitations/{token}", s.inviteInfo)
	root.HandleFunc("POST /api/invitations/{token}/verify", s.inviteVerify)
	root.HandleFunc("OPTIONS /api/invitations/{token}/probe", s.inviteProbeOptions)
	root.HandleFunc("POST /api/invitations/{token}/probe", s.inviteProbe)
	root.HandleFunc("POST /api/invitations/{token}/device", s.inviteDevice)
	root.HandleFunc("POST /api/invitations/{token}/generate", s.inviteGenerate)
	root.HandleFunc("GET /api/invitations/{token}/key", s.inviteRevealKey)
	root.HandleFunc("POST /api/invitations/{token}/close", s.inviteClose)
	root.Handle("GET /invite.js", static)
	root.Handle("GET /favicon.ico", static)
	root.Handle("GET /favicon.svg", static)
	root.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { s.invitePage(static, w, r) })
	// The embedded source file must never be an alternate, unchecked entry point.
	// Valid invitations are served exclusively from /?invite=...
	root.HandleFunc("GET /invite.html", func(w http.ResponseWriter, r *http.Request) {
		s.rejectInvalidInvitation(w, r, r.URL.Query().Get("invite"), "invalid_invitation_entry", "unvalidated invitation HTML entry point")
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/invitations/") {
			setInvitationNoStore(w)
		}
		root.ServeHTTP(w, r)
	})
}

func (s *Server) invitePage(static http.Handler, w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("invite")
	item, err := s.store.PublicInvitation(r.Context(), token)
	if errors.Is(err, ErrInvalidInvite) {
		s.rejectInvalidInvitation(w, r, token, "invalid_invitation_token", "invitation page token is invalid or terminal")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database_error", "无法检查邀请状态")
		return
	}
	if item.Status == "claimed" || item.ClaimSessionHash != "" {
		claim, ok := claimToken(r)
		if !ok || !s.store.InvitationClaimValid(r.Context(), token, claim, s.realIP(r)) {
			s.rejectInvalidInvitation(w, r, token, "invalid_invitation_claim", "invitation page claim is missing or invalid")
			return
		}
	}
	static.ServeHTTP(w, r)
}

func (s *Server) inviteInfo(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if len(token) < 20 {
		s.rejectInvalidInvitation(w, r, token, "invalid_invitation_token", "invitation API token is malformed")
		return
	}
	item, err := s.store.PublicInvitation(r.Context(), token)
	if errors.Is(err, ErrInvalidInvite) {
		s.rejectInvalidInvitation(w, r, token, "invalid_invitation_token", "invitation API token is invalid or terminal")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database_error", "无法检查邀请状态")
		return
	}
	response := map[string]any{"role": item.Role, "status": item.Status, "expires_at": item.ExpiresAt, "binding_mode": item.BindingMode}
	claimRequired := item.Status == "claimed" || item.ClaimSessionHash != ""
	if cookie, cookieErr := r.Cookie(claimCookieName); cookieErr == nil && s.store.InvitationClaimValid(r.Context(), token, cookie.Value, s.realIP(r)) {
		response["verified"] = true
		response["ips"] = item.ObservedIPs
		response["device_note"] = item.DeviceNote
		response["reveal_until"] = item.RevealUntil
	} else if claimRequired {
		s.rejectInvalidInvitation(w, r, token, "invalid_invitation_claim", "invitation API claim is missing or invalid")
		return
	}
	writeJSON(w, 200, response)
}

func (s *Server) inviteVerify(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	ip := s.realIP(r)
	if !s.requireActiveInvitation(w, r, token) {
		return
	}
	if !sameOrigin(r) {
		writeError(w, 403, "origin_rejected", "请求来源不受信任")
		return
	}
	invitationHash := tokenHash(token)
	if !s.allowAttempt("invite:"+invitationHash+":"+ip, 10, 10*time.Minute) ||
		!s.allowAttempt("invite-token:"+invitationHash, 50, 10*time.Minute) {
		s.recordInvitationUnauthorized(r, "invalid_invitation_code", "recognition-code attempts exceeded the in-memory limit for "+invitationFingerprint(token))
		writeError(w, 429, "too_many_attempts", "识别码尝试次数过多，请稍后再试")
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, 8<<10, &body) {
		return
	}
	claim, err := randomToken(32)
	if err != nil {
		writeError(w, 500, "random_failed", "验证失败")
		return
	}
	probeToken, err := randomToken(32)
	if err != nil {
		writeError(w, 500, "random_failed", "验证失败")
		return
	}
	item, err := s.store.VerifyInvitation(r.Context(), token, strings.TrimSpace(body.Code), ip, claim, probeToken)
	if err != nil {
		s.store.Audit(r.Context(), "invitee", "invitation.verify.failed", tokenHash(token)[:12], ip, nil)
		switch {
		case errors.Is(err, ErrInvalidCode):
			s.recordInvitationUnauthorized(r, "invalid_invitation_code", "recognition code rejected for "+invitationFingerprint(token))
			writeError(w, http.StatusUnauthorized, "invalid_code", "识别码错误")
		case errors.Is(err, ErrInvalidInvite), errors.Is(err, ErrInviteConsumed):
			s.rejectInvalidInvitation(w, r, token, "invalid_invitation_token", "invitation became invalid during recognition-code verification")
		default:
			writeError(w, http.StatusInternalServerError, "verification_failed", "验证失败")
		}
		return
	}
	http.SetCookie(w, &http.Cookie{Name: claimCookieName, Value: claim, Path: "/", HttpOnly: true, Secure: s.cfg.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: int(s.cfg.InviteTTL.Seconds())})
	s.store.Audit(r.Context(), "invitee", "invitation.verified", item.Role, ip, nil)
	writeJSON(w, 200, map[string]any{"role": item.Role, "ips": item.ObservedIPs, "probe_token": probeToken, "probe_urls": s.probeURLs(), "binding_mode": item.BindingMode, "verified": true})
}

func (s *Server) inviteProbeOptions(w http.ResponseWriter, r *http.Request) {
	if !s.setProbeCORS(w, r) {
		writeError(w, 403, "origin_rejected", "请求来源不受信任")
		return
	}
	if !s.requireActiveInvitation(w, r, r.PathValue("token")) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) inviteProbe(w http.ResponseWriter, r *http.Request) {
	if !s.requireActiveInvitation(w, r, r.PathValue("token")) {
		return
	}
	if !s.setProbeCORS(w, r) {
		writeError(w, 403, "origin_rejected", "请求来源不受信任")
		return
	}
	var body struct {
		ProbeToken string `json:"probe_token"`
	}
	if !decodeJSON(w, r, 8<<10, &body) {
		return
	}
	ips, err := s.store.RecordInvitationProbe(r.Context(), r.PathValue("token"), strings.TrimSpace(body.ProbeToken), s.realIP(r))
	if errors.Is(err, ErrInvalidInvite) {
		s.rejectInvalidInvitation(w, r, r.PathValue("token"), "invalid_invitation_probe", "invitation probe token or invitation is invalid")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "probe_failed", "IP 检测失败")
		return
	}
	writeJSON(w, 200, map[string]any{"ips": ips})
}

func (s *Server) setProbeCORS(w http.ResponseWriter, r *http.Request) bool {
	origin := strings.TrimRight(strings.TrimSpace(r.Header.Get("Origin")), "/")
	allowed := publicOrigin(s.cfg.PublicInviteURL)
	if origin == "" || allowed == "" || origin != allowed {
		return false
	}
	w.Header().Set("Access-Control-Allow-Origin", allowed)
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Max-Age", "600")
	w.Header().Set("Vary", "Origin")
	return true
}

func publicOrigin(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

func (s *Server) probeURLs() []string {
	result := make([]string, 0, 2)
	for _, candidate := range []string{s.cfg.PublicIPv4ProbeURL, s.cfg.PublicIPv6ProbeURL} {
		if candidate != "" && !containsString(result, candidate) {
			result = append(result, candidate)
		}
	}
	return result
}

func (s *Server) inviteDevice(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if !s.requireActiveInvitation(w, r, token) {
		return
	}
	if !sameOrigin(r) {
		writeError(w, 403, "origin_rejected", "请求来源不受信任")
		return
	}
	ip := s.realIP(r)
	claim, ok := claimToken(r)
	if !ok {
		s.rejectInvalidInvitation(w, r, token, "invalid_invitation_claim", "device registration claim is missing")
		return
	}
	item, err := s.store.PublicInvitation(r.Context(), token)
	if errors.Is(err, ErrInvalidInvite) {
		s.rejectInvalidInvitation(w, r, token, "invalid_invitation_claim", "device registration claim or invitation is invalid")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database_error", "无法检查邀请状态")
		return
	}
	var body struct {
		DeviceNote string `json:"device_note"`
	}
	if !decodeJSON(w, r, 8<<10, &body) {
		return
	}
	body.DeviceNote = strings.TrimSpace(body.DeviceNote)
	if body.DeviceNote == "" || len(body.DeviceNote) > 100 {
		writeError(w, 400, "invalid_note", "设备备注为必填项，且不能超过100字")
		return
	}
	deviceToken := ""
	if item.BindingMode == "device" || item.BindingMode == "ip_device" {
		deviceToken, err = randomToken(32)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "random_failed", "设备凭证生成失败")
			return
		}
	}
	if err := s.store.SaveInviteDeviceWithCredential(r.Context(), token, claim, ip, body.DeviceNote, deviceToken); errors.Is(err, ErrInvalidInvite) {
		s.rejectInvalidInvitation(w, r, token, "invalid_invitation_claim", "device registration claim or invitation is invalid")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "device_failed", "保存设备信息失败")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "binding_mode": item.BindingMode, "device_token": deviceToken})
}

func (s *Server) inviteGenerate(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if !s.requireActiveInvitation(w, r, token) {
		return
	}
	if !sameOrigin(r) {
		writeError(w, 403, "origin_rejected", "请求来源不受信任")
		return
	}
	ip := s.realIP(r)
	claim, ok := claimToken(r)
	if !ok {
		s.rejectInvalidInvitation(w, r, token, "invalid_invitation_claim", "key generation claim is missing")
		return
	}
	random, err := randomToken(32)
	if err != nil {
		writeError(w, 500, "random_failed", "生成密钥失败")
		return
	}
	plainKey := "sk-fg_" + random
	s.keyRequestMu.Lock()
	key, revealUntil, err := s.store.GenerateInvitedKey(r.Context(), token, claim, ip, plainKey, s.cfg.RevealTTL)
	if err != nil {
		s.keyRequestMu.Unlock()
		switch {
		case errors.Is(err, ErrInvalidInvite), errors.Is(err, ErrInviteConsumed):
			s.rejectInvalidInvitation(w, r, token, "invalid_invitation_claim", "key generation claim or invitation is invalid")
		case errors.Is(err, ErrNoAccount):
			writeError(w, http.StatusServiceUnavailable, "account_pool_unavailable", "当前没有可用的 ChatGPT 账号")
		default:
			writeError(w, http.StatusInternalServerError, "generate_failed", "生成密钥失败")
		}
		return
	}
	func() {
		defer s.keyRequestMu.Unlock()
		writeJSON(w, 201, map[string]any{"role": key.Role, "key": plainKey, "guide_token": s.guideTokenForKey(plainKey), "reveal_until": revealUntil, "base_url": s.cfg.PublicAPIURL, "guide_url": s.cfg.PublicGuideURL})
	}()
	s.store.Audit(r.Context(), "invitee", "key.generated", key.Role, ip, map[string]any{"key_id": key.ID, "routing": "account_pool"})
}

func (s *Server) inviteRevealKey(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if !s.requireActiveInvitation(w, r, token) {
		return
	}
	ip := s.realIP(r)
	claim, ok := claimToken(r)
	if !ok {
		s.rejectInvalidInvitation(w, r, token, "invalid_invitation_claim", "key reveal claim is missing")
		return
	}
	s.keyRequestMu.Lock()
	key, until, err := s.store.RevealInvitedKey(r.Context(), token, claim, ip)
	if errors.Is(err, ErrInvalidInvite) {
		s.keyRequestMu.Unlock()
		s.rejectInvalidInvitation(w, r, token, "invalid_invitation_claim", "key reveal claim or invitation is invalid")
		return
	}
	if err != nil {
		s.keyRequestMu.Unlock()
		writeError(w, http.StatusInternalServerError, "reveal_failed", "读取密钥失败")
		return
	}
	func() {
		defer s.keyRequestMu.Unlock()
		writeJSON(w, 200, map[string]any{"key": key, "guide_token": s.guideTokenForKey(key), "reveal_until": until, "base_url": s.cfg.PublicAPIURL, "guide_url": s.cfg.PublicGuideURL})
	}()
}

func (s *Server) inviteClose(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "origin_rejected", "请求来源不受信任")
		return
	}
	http.SetCookie(w, expiredCookie(claimCookieName, s.cfg.SecureCookies))
	w.WriteHeader(http.StatusNoContent)
}

func claimToken(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(claimCookieName)
	return func() (string, bool) {
		if err != nil || cookie.Value == "" {
			return "", false
		}
		return cookie.Value, true
	}()
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func setInvitationNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Pragma", "no-cache")
}

func (s *Server) writeInvitationGone(w http.ResponseWriter) {
	setInvitationNoStore(w)
	http.SetCookie(w, expiredCookie(claimCookieName, s.cfg.SecureCookies))
	writeError(w, http.StatusGone, "invite_expired", "邀请链接无效或已失效")
}

// recordInvitationUnauthorized feeds invitation abuse into the same durable
// counter and public-surface ban used by the API gateway. Responses retain
// their existing 410/401/429 semantics for the triggering request; once the
// threshold is reached, the refreshed cache rejects subsequent public traffic.
func (s *Server) recordInvitationUnauthorized(r *http.Request, kind, detail string) {
	ip := s.realIP(r)
	banned, err := s.store.RecordUnauthorized(r.Context(), ip, kind, r.URL.Path, detail, s.cfg.BanThreshold, s.cfg.BanWindow, s.cfg.BanDuration)
	if err != nil {
		s.setSecurityRuntimeFailure("unauthorized_ban", err)
		return
	}
	s.setSecurityRuntimeFailure("unauthorized_ban", nil)
	if banned {
		s.activatePublicBan(r.Context(), ip, s.cfg.BanDuration)
	}
}

func (s *Server) rejectInvalidInvitation(w http.ResponseWriter, r *http.Request, token, kind, detail string) {
	s.recordInvitationUnauthorized(r, kind, detail+" ("+invitationFingerprint(token)+")")
	s.writeInvitationGone(w)
}

func invitationFingerprint(token string) string {
	return "token_hash=" + tokenHash(token)[:12]
}

func (s *Server) requireActiveInvitation(w http.ResponseWriter, r *http.Request, token string) bool {
	_, err := s.store.PublicInvitation(r.Context(), token)
	if errors.Is(err, ErrInvalidInvite) {
		s.rejectInvalidInvitation(w, r, token, "invalid_invitation_token", "invitation token is invalid or terminal")
		return false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database_error", "无法检查邀请状态")
		return false
	}
	return true
}
