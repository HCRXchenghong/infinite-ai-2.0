package app

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed web/*
var webFiles embed.FS

type Server struct {
	cfg                Config
	store              *Store
	vault              *Vault
	client             *http.Client
	refreshLocks       sync.Map
	metricsMu          sync.Mutex
	lastCPU            cpuTimes
	oauthMu            sync.Mutex
	oauthFlows         map[string]*openAIOAuthFlow
	setupMu            sync.Mutex
	setupFlows         map[string]*adminSetupFlow
	guideMu            sync.RWMutex
	guideSessions      map[string]guideSession
	limitMu            sync.Mutex
	limits             map[string]*attemptWindow
	lastLimitSweep     time.Time
	securityMu         sync.RWMutex
	security           SecurityConfig
	securityRuntimeMu  sync.RWMutex
	securityRuntime    map[string]securityRuntimeFailure
	banSyncMu          sync.Mutex
	banMu              sync.RWMutex
	activeBans         map[string]activeBan
	banCacheFailClosed bool
	nginxMu            sync.Mutex
	// restoreGate covers each externally-triggered operation and scheduled
	// writer. A portable restore takes the write side only after closing request
	// admission, so stale work from the previous database generation cannot
	// commit after restored rows become visible.
	restoreGate  sync.RWMutex
	keyRequestMu sync.Mutex
	keyRequestID uint64
	keyRequests  map[int64]map[uint64]activeKeyRequest
	// restoreInProgress is protected by keyRequestMu. It closes admission while
	// a portable restore drains the old request generation and replaces data.
	restoreInProgress bool
}

type activeKeyRequest struct {
	accountID int64
	ip        string
	cancel    context.CancelCauseFunc
	done      <-chan struct{}
}

type activeBan struct {
	ExpiresAt int64
	Scope     string
}

type attemptWindow struct {
	ExpiresAt time.Time
	Count     int
}

type securityRuntimeFailure struct {
	Key       string `json:"key"`
	Detail    string `json:"detail"`
	UpdatedAt int64  `json:"updated_at"`
}

const maxAttemptWindows = 10_000

func NewServer(cfg Config, store *Store, vault *Vault) *Server {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 64
	transport.MaxIdleConnsPerHost = 32
	transport.IdleConnTimeout = 90 * time.Second
	transport.ResponseHeaderTimeout = 90 * time.Second
	transport.ForceAttemptHTTP2 = true
	server := &Server{
		cfg: cfg, store: store, vault: vault,
		client:          &http.Client{Transport: transport},
		oauthFlows:      make(map[string]*openAIOAuthFlow),
		setupFlows:      make(map[string]*adminSetupFlow),
		guideSessions:   make(map[string]guideSession),
		limits:          make(map[string]*attemptWindow),
		activeBans:      make(map[string]activeBan),
		securityRuntime: make(map[string]securityRuntimeFailure),
		keyRequests:     make(map[int64]map[uint64]activeKeyRequest),
	}
	// Store-side logging is used from proxy and invite goroutines which do not
	// otherwise have a Server reference. Register the reporter before any
	// runtime work so a failed usage/audit/security write is visible in the
	// administrator health page instead of being confined to stderr.
	store.SetRuntimeFailureReporter(server.setSecurityRuntimeFailure)
	server.security = store.SecurityConfig(context.Background())
	server.refreshBanCache(context.Background())
	server.lastCPU, _ = readCPUTimes()
	return server
}

func RunMain() error {
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	vault, err := NewVault(cfg.MasterKey)
	if err != nil {
		return err
	}
	store, err := OpenStore(cfg, vault)
	if err != nil {
		return err
	}
	defer store.Close()
	server := NewServer(cfg, store, vault)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return server.Run(ctx)
}

func (s *Server) Run(ctx context.Context) error {
	servers := []*http.Server{
		newHTTPServer(s.cfg.APIAddr, s.commonHeaders("api", s.proxyHandler())),
		newHTTPServer(s.cfg.AdminAddr, s.commonHeaders("admin", s.adminHandler())),
		newHTTPServer(s.cfg.InviteAddr, s.commonHeaders("invite", s.inviteHandler())),
		newHTTPServer(s.cfg.GuideAddr, s.commonHeaders("guide", s.guideHandler())),
	}
	labels := []string{"api", "admin", "invite", "guide"}
	errCh := make(chan error, len(servers))
	for i, server := range servers {
		go func(label string, srv *http.Server) {
			slog.Info("listener started", "name", label, "addr", srv.Addr)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("%s listener: %w", label, err)
			}
		}(labels[i], server)
	}
	go s.maintenance(ctx)
	go s.quotaSyncLoop(ctx)
	go s.modelSyncLoop(ctx)
	go s.securityMonitorLoop(ctx)
	select {
	case <-ctx.Done():
	case err := <-errCh:
		return err
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
	defer cancel()
	for _, server := range servers {
		_ = server.Shutdown(shutdownCtx)
	}
	return nil
}

func (s *Server) maintenance(ctx context.Context) {
	run := func() {
		if !s.beginRuntimeOperation() {
			return
		}
		defer s.restoreGate.RUnlock()
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.store.Cleanup(cleanupCtx); err != nil {
			slog.Warn("maintenance cleanup failed", "error", err)
		}
	}
	run()
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr: addr, Handler: handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute, WriteTimeout: 0,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 64 << 10,
	}
}

func (s *Server) commonHeaders(surface string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := s.realIP(r)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		if surface == "guide" {
			w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet, noimageindex")
			w.Header().Set("Cache-Control", "no-store, private")
		}
		if s.cfg.SecureCookies {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		if s.isBannedCached(ip, surface) {
			writeError(w, http.StatusForbidden, "ip_banned", "该 IP 已被安全策略封禁")
			return
		}
		// The restore endpoint owns the exclusive side of this gate itself. Every
		// other surface is either admitted into the current database generation or
		// receives an explicit retryable response while restoration is active.
		isRestoreUpload := surface == "admin" && r.Method == http.MethodPost && r.URL.Path == "/api/system/backup/import"
		if !isRestoreUpload {
			if !s.beginRuntimeOperation() {
				w.Header().Set("Retry-After", "2")
				writeError(w, http.StatusServiceUnavailable, "restore_in_progress", "系统正在恢复备份，请稍后重试")
				return
			}
			defer s.restoreGate.RUnlock()
		}
		tracked := &statusResponseWriter{ResponseWriter: w}
		defer func() {
			if recovered := recover(); recovered != nil {
				// ReverseProxy uses this sentinel after response headers have
				// already been written (for example when an SSE client goes
				// away). Appending a JSON 500 here would corrupt the stream.
				if recovered == http.ErrAbortHandler {
					panic(recovered)
				}
				slog.Error("request panic", "error", recovered, "path", r.URL.Path)
				writeError(tracked, http.StatusInternalServerError, "internal_error", "服务内部错误")
			}
			s.observeHTTPStatus(ip, surface, r.URL.Path, tracked.Status())
		}()
		next.ServeHTTP(tracked, r)
	})
}

// beginRuntimeOperation atomically joins the current database generation. The
// key lifecycle mutex prevents a reader from slipping between the restore flag
// check and the RW lock acquisition.
func (s *Server) beginRuntimeOperation() bool {
	s.keyRequestMu.Lock()
	defer s.keyRequestMu.Unlock()
	if s.restoreInProgress {
		return false
	}
	s.restoreGate.RLock()
	return true
}

func (s *Server) staticHandler(name string) http.Handler {
	sub, err := fs.Sub(webFiles, "web")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			r.URL.Path = "/" + name
		} else if r.URL.Path == "/favicon.ico" {
			// Keep older tabs and browsers from logging a harmless 404 while the
			// HTML advertises the SVG favicon.
			r.URL.Path = "/favicon.svg"
		}
		if strings.Contains(r.URL.Path, "..") {
			http.NotFound(w, r)
			return
		}
		if strings.HasSuffix(r.URL.Path, ".html") || r.URL.Path == "/"+name {
			w.Header().Set("Cache-Control", "no-store")
			connectSources := []string{"'self'"}
			if name == "invite.html" {
				for _, raw := range []string{s.cfg.PublicIPv4ProbeURL, s.cfg.PublicIPv6ProbeURL} {
					if origin := publicOrigin(raw); origin != "" && !containsString(connectSources, origin) {
						connectSources = append(connectSources, origin)
					}
				}
			}
			// Vue's browser build compiles this embedded admin template at runtime.
			// It therefore needs unsafe-eval even though every script is served from
			// this binary under script-src 'self'; no third-party script is allowed.
			w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-eval'; connect-src "+strings.Join(connectSources, " ")+"; img-src 'self' data:; base-uri 'none'; form-action 'self'")
		} else {
			w.Header().Set("Cache-Control", "public,max-age=3600")
		}
		files.ServeHTTP(w, r)
	})
}

func (s *Server) realIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return "unknown"
	}
	if s.isTrustedProxy(peer) {
		forwarded := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		// Walk from the trusted proxy backwards. This ignores client-supplied
		// spoofed values on the left when nginx/Caddy appends the real peer.
		var leftmost netip.Addr
		for i := len(forwarded) - 1; i >= 0; i-- {
			parsed, parseErr := netip.ParseAddr(strings.TrimSpace(forwarded[i]))
			if parseErr != nil {
				continue
			}
			parsed = parsed.Unmap()
			leftmost = parsed
			if !s.isTrustedProxy(parsed) {
				return parsed.String()
			}
		}
		if leftmost.IsValid() {
			return leftmost.String()
		}
		if parsed, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); err == nil {
			return parsed.Unmap().String()
		}
	}
	return peer.Unmap().String()
}

func (s *Server) isTrustedProxy(address netip.Addr) bool {
	for _, prefix := range s.cfg.TrustedProxies {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (s *Server) allowAttempt(key string, max int, window time.Duration) bool {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	now := time.Now()
	item := s.limits[key]
	if item != nil && now.Before(item.ExpiresAt) {
		item.Count++
		return item.Count <= max
	}
	if item != nil {
		delete(s.limits, key)
	}
	// Sweep periodically or under capacity pressure, not on every request.
	// This keeps cleanup O(n) amortized and avoids a 10k-entry CPU amplifier.
	if len(s.limits) >= maxAttemptWindows || now.Sub(s.lastLimitSweep) >= time.Minute {
		for candidate, candidateWindow := range s.limits {
			if !now.Before(candidateWindow.ExpiresAt) {
				delete(s.limits, candidate)
			}
		}
		s.lastLimitSweep = now
	}
	if item == nil || !now.Before(item.ExpiresAt) {
		// Bound attacker-controlled invitation/IP keys on a 1H2G server. When
		// every slot is still live, deny a new attempt instead of growing memory.
		if len(s.limits) >= maxAttemptWindows {
			return false
		}
		s.limits[key] = &attemptWindow{ExpiresAt: now.Add(window), Count: 1}
		return true
	}
	return false
}

func (s *Server) resetAttempts(key string) {
	s.limitMu.Lock()
	delete(s.limits, key)
	s.limitMu.Unlock()
}

func requireMethod(method string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "请求方法不允许")
			return
		}
		next(w, r)
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, max int64, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, max)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "请求内容格式不正确")
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_json", "请求只能包含一个 JSON 对象")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func sameOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(origin, prefix) {
			return strings.EqualFold(strings.TrimPrefix(origin, prefix), r.Host)
		}
	}
	return false
}
