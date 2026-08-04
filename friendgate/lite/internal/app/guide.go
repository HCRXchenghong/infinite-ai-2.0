package app

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"image"
	"image/png"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"time"
)

const (
	guideCookieName = "friendgate_guide"
	guideSessionTTL = 24 * time.Hour
	guideMarkerMax  = 8192
)

type guideSession struct {
	KeyHash   string
	Role      string
	ExpiresAt time.Time
}

type guideMarker struct {
	Version    int    `json:"v"`
	GuideToken string `json:"t"`
	Key        string `json:"k"`
	Device     string `json:"d"`
}

type guideAuthResponse struct {
	Authenticated bool   `json:"authenticated"`
	Role          string `json:"role"`
	Key           string `json:"key"`
	DeviceToken   string `json:"device_token,omitempty"`
	BaseURL       string `json:"base_url"`
	GuideURL      string `json:"guide_url"`
}

func (s *Server) guideHandler() http.Handler {
	root := http.NewServeMux()
	root.HandleFunc("GET /api/guide/session", s.guideSession)
	root.HandleFunc("GET /api/guide/content", s.guideContent)
	root.HandleFunc("GET /api/guide/models", s.guideModels)
	root.HandleFunc("POST /api/guide/auth/key", s.guideAuthKey)
	root.HandleFunc("POST /api/guide/auth/image", s.guideAuthImage)
	root.HandleFunc("POST /api/guide/logout", s.guideLogout)
	root.Handle("GET /guide.js", s.guideStatic("guide.js"))
	root.Handle("GET /guide.css", s.guideStatic("guide.css"))
	root.Handle("GET /favicon.svg", s.guideStatic("favicon.svg"))
	root.HandleFunc("GET /robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store, private")
		_, _ = io.WriteString(w, "User-agent: *\nDisallow: /\n")
	})
	root.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		s.guideStatic("index.html").ServeHTTP(w, r)
	})
	return root
}

func (s *Server) guideStatic(name string) http.Handler {
	sub, err := fs.Sub(webFiles, "web/guide")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if name == "index.html" {
			r.URL.Path = "/"
		} else {
			r.URL.Path = "/" + name
		}
		w.Header().Set("Cache-Control", "no-store, private")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet, noimageindex")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; img-src 'self' data: blob:; base-uri 'none'; form-action 'self'")
		files.ServeHTTP(w, r)
	})
}

func (s *Server) guideSession(w http.ResponseWriter, r *http.Request) {
	session, key, ok := s.currentGuideSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"authenticated": false})
		return
	}
	writeJSON(w, http.StatusOK, guideAuthResponse{Authenticated: true, Role: session.Role, BaseURL: s.cfg.PublicAPIURL, GuideURL: s.cfg.PublicGuideURL, Key: key.MaskedKey})
}

func (s *Server) guideContent(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := s.currentGuideSession(r); !ok {
		writeError(w, http.StatusUnauthorized, "guide_auth_required", "请先验证 Key 或上传凭证海报")
		return
	}
	content, err := fs.ReadFile(webFiles, "web/guide/content.html")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "guide_content_unavailable", "配置指南暂时不可用")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"html": string(content)})
}

// guideModels exposes only deduplicated model IDs from persisted official
// snapshots. Account names and per-account routing details remain private.
func (s *Server) guideModels(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := s.currentGuideSession(r); !ok {
		writeError(w, http.StatusUnauthorized, "guide_auth_required", "请先验证 Key 或上传凭证海报")
		return
	}
	catalog, err := s.store.ListModelCatalog(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "guide_models_unavailable", "模型列表暂时不可用")
		return
	}
	models := make([]ModelDescriptor, len(catalog.Models))
	copy(models, catalog.Models)
	w.Header().Set("Cache-Control", "no-store, private")
	writeJSON(w, http.StatusOK, map[string]any{
		"models":      models,
		"model_count": len(models),
		"updated_at":  catalog.UpdatedAt,
	})
}

func (s *Server) guideAuthKey(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "origin_rejected", "请求来源不受信任")
		return
	}
	var body struct {
		Key string `json:"key"`
	}
	if !decodeJSON(w, r, 8<<10, &body) {
		return
	}
	key := strings.TrimSpace(body.Key)
	if len(key) < 20 || len(key) > 512 {
		s.guideAuthFailure(w, r, "invalid_key_format")
		return
	}
	item, err := s.store.AuthorizeGuideKey(r.Context(), key)
	if err != nil {
		s.guideAuthFailure(w, r, "unknown_or_disabled_key")
		return
	}
	s.issueGuideSession(w, r, item, key, "")
}

func (s *Server) guideAuthImage(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "origin_rejected", "请求来源不受信任")
		return
	}
	if r.ContentLength > 8<<20 {
		s.guideAuthFailure(w, r, "image_too_large")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		s.guideAuthFailure(w, r, "invalid_image_upload")
		return
	}
	file, _, err := r.FormFile("poster")
	if err != nil {
		s.guideAuthFailure(w, r, "poster_missing")
		return
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 8<<20))
	if err != nil {
		s.guideAuthFailure(w, r, "poster_read_failed")
		return
	}
	marker, err := decodeGuideMarker(data)
	if err != nil || marker.Version != 1 || marker.GuideToken == "" || marker.Key == "" {
		s.guideAuthFailure(w, r, "poster_marker_invalid")
		return
	}
	if !s.validGuideToken(marker.GuideToken, marker.Key) {
		s.guideAuthFailure(w, r, "poster_marker_untrusted")
		return
	}
	item, err := s.store.AuthorizeGuideKey(r.Context(), marker.Key)
	if err != nil {
		s.guideAuthFailure(w, r, "poster_key_disabled")
		return
	}
	s.issueGuideSession(w, r, item, marker.Key, marker.Device)
}

func (s *Server) issueGuideSession(w http.ResponseWriter, r *http.Request, item *APIKey, key, device string) {
	token, err := randomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session_failed", "无法创建指南会话")
		return
	}
	now := time.Now()
	s.guideMu.Lock()
	for candidate, session := range s.guideSessions {
		if !now.Before(session.ExpiresAt) {
			delete(s.guideSessions, candidate)
		}
	}
	s.guideSessions[token] = guideSession{KeyHash: tokenHash(key), Role: item.Role, ExpiresAt: now.Add(guideSessionTTL)}
	s.guideMu.Unlock()
	// Keep this as a browser-session cookie. The page also sends a best-effort
	// logout beacon on pagehide, while a session cookie provides the safe
	// fallback when the browser closes before the beacon can be delivered.
	http.SetCookie(w, &http.Cookie{Name: guideCookieName, Value: token, Path: "/", HttpOnly: true, Secure: s.cfg.SecureCookies, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, guideAuthResponse{Authenticated: true, Role: item.Role, Key: key, DeviceToken: strings.TrimSpace(device), BaseURL: s.cfg.PublicAPIURL, GuideURL: s.cfg.PublicGuideURL})
	_ = r
}

func (s *Server) currentGuideSession(r *http.Request) (guideSession, *APIKey, bool) {
	cookie, err := r.Cookie(guideCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return guideSession{}, nil, false
	}
	now := time.Now()
	s.guideMu.RLock()
	session, ok := s.guideSessions[cookie.Value]
	s.guideMu.RUnlock()
	if !ok || !now.Before(session.ExpiresAt) {
		return guideSession{}, nil, false
	}
	item, err := s.store.AuthorizeGuideHash(r.Context(), session.KeyHash)
	if err != nil {
		return guideSession{}, nil, false
	}
	return session, item, true
}

func (s *Server) guideLogout(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "origin_rejected", "请求来源不受信任")
		return
	}
	// Clear-Site-Data is intentionally limited to cache/storage here. Cookies
	// are not port-scoped, so a host-wide "cookies" directive on the guide
	// listener could also remove the separate administrator cookie. The named
	// guide cookie is expired explicitly below.
	w.Header().Set("Clear-Site-Data", `"cache", "storage"`)
	w.Header().Set("Cache-Control", "no-store, private")
	if cookie, err := r.Cookie(guideCookieName); err == nil {
		s.guideMu.Lock()
		delete(s.guideSessions, cookie.Value)
		s.guideMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: guideCookieName, Value: "", Path: "/", HttpOnly: true, Secure: s.cfg.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) guideAuthFailure(w http.ResponseWriter, r *http.Request, detail string) {
	temporary, permanent, err := s.store.RecordGuideFailure(r.Context(), s.realIP(r), r.URL.Path, detail)
	if err != nil {
		s.setSecurityRuntimeFailure("guide_auth_ban", err)
		writeError(w, http.StatusInternalServerError, "security_unavailable", "安全策略暂时不可用，请稍后重试")
		return
	}
	if temporary || permanent {
		duration := 24 * time.Hour
		if permanent {
			duration = 100 * 365 * 24 * time.Hour
		}
		s.activateScopedBan(r.Context(), s.realIP(r), duration, "guide")
		if permanent {
			writeError(w, http.StatusForbidden, "guide_ip_permanently_banned", "该 IP 已永久禁止访问配置指南，请联系管理员解封")
		} else {
			writeError(w, http.StatusForbidden, "guide_ip_banned", "错误次数过多，24 小时内禁止访问配置指南")
		}
		return
	}
	writeError(w, http.StatusUnauthorized, "guide_auth_failed", "请输入有效 Key 或上传由系统生成的凭证海报")
}

func (s *Server) guideTokenForKey(plainKey string) string {
	hash := tokenHash(plainKey)
	return "fg1." + hash + "." + s.vault.Namespace("guide-v1", hash)
}

func (s *Server) validGuideToken(token, plainKey string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "fg1" || parts[1] != tokenHash(plainKey) {
		return false
	}
	expected := s.vault.Namespace("guide-v1", parts[1])
	return subtle.ConstantTimeCompare([]byte(expected), []byte(parts[2])) == 1
}

// decodeGuideMarker reads the RGB least-significant bits of the final PNG row.
// The poster remains visually unchanged while the marker survives lossless PNG
// downloads and lets the server verify that the image came from FriendGate.
func decodeGuideMarker(data []byte) (guideMarker, error) {
	if len(data) == 0 || len(data) > 8<<20 {
		return guideMarker{}, errors.New("invalid poster size")
	}
	// DecodeConfig inspects only the PNG header. Bound dimensions before the
	// full decode so a tiny decompressed-image bomb cannot allocate unbounded
	// memory on the public guide listener.
	config, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil || config.Width < 32 || config.Height < 1 || config.Width > 8192 || config.Height > 8192 || int64(config.Width)*int64(config.Height) > 16_000_000 {
		return guideMarker{}, errors.New("poster dimensions are invalid")
	}
	img, format, err := image.Decode(bytes.NewReader(data))
	if err != nil || format != "png" {
		return guideMarker{}, errors.New("poster must be a PNG")
	}
	bounds := img.Bounds()
	if bounds.Dx() < 32 || bounds.Dy() < 1 {
		return guideMarker{}, errors.New("poster dimensions are invalid")
	}
	readBits := func(count int) ([]byte, error) {
		if count <= 0 || count > guideMarkerMax {
			return nil, errors.New("marker length is invalid")
		}
		bits := make([]byte, 0, count*8)
		y := bounds.Max.Y - 1
		for x := bounds.Min.X; len(bits) < count*8; x++ {
			if x >= bounds.Max.X {
				return nil, errors.New("marker is truncated")
			}
			r, g, b, _ := img.At(x, y).RGBA()
			// Mask before narrowing: only the least-significant marker bit is
			// retained, so no high colour bits can be truncated into the result.
			bits = append(bits, byte((r>>8)&1), byte((g>>8)&1), byte((b>>8)&1))
		}
		result := make([]byte, count)
		for i := range result {
			for bit := 0; bit < 8; bit++ {
				result[i] |= bits[i*8+bit] << (7 - bit)
			}
		}
		return result, nil
	}
	header, err := readBits(6)
	if err != nil || string(header[:4]) != "FGP1" {
		return guideMarker{}, errors.New("poster marker is missing")
	}
	length := int(header[4])<<8 | int(header[5])
	if length < 2 || length > guideMarkerMax {
		return guideMarker{}, errors.New("poster marker length is invalid")
	}
	payload, err := readBits(6 + length)
	if err != nil {
		return guideMarker{}, err
	}
	var marker guideMarker
	if err := json.Unmarshal(payload[6:], &marker); err != nil {
		return guideMarker{}, err
	}
	return marker, nil
}
