package app

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	nginxFingerprintVersion = "2"
	nginxMaxFiles           = 5000
	nginxMaxFileBytes       = int64(8 << 20)
	nginxMaxTotalBytes      = int64(64 << 20)
)

type statusResponseWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *statusResponseWriter) Status() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}
func (w *statusResponseWriter) WriteHeader(status int) {
	if w.wrote {
		return
	}
	w.status, w.wrote = status, true
	w.ResponseWriter.WriteHeader(status)
}
func (w *statusResponseWriter) Write(value []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(value)
}
func (w *statusResponseWriter) Flush() {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}
func (w *statusResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}
func (w *statusResponseWriter) Push(target string, options *http.PushOptions) error {
	if pusher, ok := w.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, options)
	}
	return http.ErrNotSupported
}
func (w *statusResponseWriter) ReadFrom(reader io.Reader) (int64, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if from, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		return from.ReadFrom(reader)
	}
	return io.Copy(writerOnly{Writer: w.ResponseWriter}, reader)
}

type writerOnly struct{ io.Writer }

func (s *Server) currentSecurityConfig() SecurityConfig {
	s.securityMu.RLock()
	defer s.securityMu.RUnlock()
	return s.security
}

func (s *Server) setSecurityConfig(config SecurityConfig) {
	s.securityMu.Lock()
	s.security = config
	s.securityMu.Unlock()
}

func (s *Server) setSecurityRuntimeFailure(key string, err error) {
	s.securityRuntimeMu.Lock()
	defer s.securityRuntimeMu.Unlock()
	if err == nil {
		delete(s.securityRuntime, key)
		return
	}
	s.securityRuntime[key] = securityRuntimeFailure{Key: key, Detail: truncate(err.Error(), 300), UpdatedAt: time.Now().Unix()}
	slog.Error("security enforcement degraded", "component", key, "error", err)
}

func (s *Server) securityRuntimeFailures() []securityRuntimeFailure {
	s.securityRuntimeMu.RLock()
	defer s.securityRuntimeMu.RUnlock()
	result := make([]securityRuntimeFailure, 0, len(s.securityRuntime))
	for _, issue := range s.securityRuntime {
		result = append(result, issue)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].UpdatedAt > result[j].UpdatedAt })
	return result
}

func (s *Server) hasSecurityRuntimeFailure(keys ...string) bool {
	s.securityRuntimeMu.RLock()
	defer s.securityRuntimeMu.RUnlock()
	for _, key := range keys {
		if _, exists := s.securityRuntime[key]; exists {
			return true
		}
	}
	return false
}

func (s *Server) refreshBanCache(ctx context.Context) error {
	// Serialize the database snapshot with targeted cache mutations. Otherwise
	// a slow refresh that started before a manual ban/unban committed could
	// overwrite the newer in-memory decision after the administrator received a
	// success response.
	s.banSyncMu.Lock()
	defer s.banSyncMu.Unlock()
	items, err := s.store.ListBans(ctx)
	if err != nil {
		s.banMu.Lock()
		s.banCacheFailClosed = true
		s.banMu.Unlock()
		s.setSecurityRuntimeFailure("ban_cache", err)
		return err
	}
	next := make(map[string]activeBan, len(items))
	for _, item := range items {
		next[item.IP] = activeBan{ExpiresAt: item.ExpiresAt, Scope: item.Scope}
	}
	s.banMu.Lock()
	s.activeBans = next
	s.banCacheFailClosed = false
	s.banMu.Unlock()
	s.setSecurityRuntimeFailure("ban_cache", nil)
	return nil
}

func (s *Server) cacheBanMembersLocked(ips []string, ban activeBan) {
	s.banMu.Lock()
	for _, ip := range ips {
		if ip != "" && ip != "unknown" {
			s.activeBans[ip] = ban
		}
	}
	s.banMu.Unlock()
}

func (s *Server) removeBanMembersLocked(ips []string) {
	s.banMu.Lock()
	for _, ip := range ips {
		delete(s.activeBans, ip)
	}
	s.banMu.Unlock()
}

// activatePublicBan makes the just-committed automatic ban effective before a
// full cache refresh is attempted. The direct source IP is always installed as
// a fail-safe; when the durable ban group is readable, its paired IPv4/IPv6
// members are installed and their in-flight proxy requests are cancelled too.
func (s *Server) activatePublicBan(ctx context.Context, ip string, duration time.Duration) {
	s.activateScopedBan(ctx, ip, duration, "public")
}

func (s *Server) activateScopedBan(ctx context.Context, ip string, duration time.Duration, scope string) {
	activationCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	members := []string{ip}
	var membersErr error
	s.banSyncMu.Lock()
	if durableMembers, err := s.store.BanMembers(activationCtx, ip); err == nil && len(durableMembers) > 0 {
		members = durableMembers
	} else if err != nil {
		membersErr = err
	}
	s.cacheBanMembersLocked(members, activeBan{ExpiresAt: time.Now().Add(duration).Unix(), Scope: scope})
	s.banSyncMu.Unlock()

	refreshErr := s.refreshBanCache(activationCtx)
	if membersErr != nil && refreshErr == nil {
		// A successful snapshot means storage recovered. Retry membership so the
		// cancellation boundary covers both sides of a dual-stack device.
		if durableMembers, err := s.store.BanMembers(activationCtx, ip); err == nil && len(durableMembers) > 0 {
			members = durableMembers
			membersErr = nil
		} else if err != nil {
			membersErr = err
		}
	}
	cancelled, cancelErr := s.cancelIPRequests(members, false)
	_ = cancelled
	if cancelErr != nil {
		s.setSecurityRuntimeFailure("ban_request_cancel", cancelErr)
	} else if membersErr != nil {
		s.setSecurityRuntimeFailure("ban_request_cancel", fmt.Errorf("resolve dual-stack ban members: %w", membersErr))
	} else {
		s.setSecurityRuntimeFailure("ban_request_cancel", nil)
	}
}

func (s *Server) isBannedCached(ip string, surfaces ...string) bool {
	if ip == "" || ip == "unknown" {
		return false
	}
	surface := "api"
	if len(surfaces) > 0 {
		surface = surfaces[0]
	}
	now := time.Now().Unix()
	s.banMu.RLock()
	ban, found := s.activeBans[ip]
	failClosed := s.banCacheFailClosed
	s.banMu.RUnlock()
	// An unreadable durable ban set must never silently open the public API or
	// invitation surface. Administration remains reachable for diagnosis and
	// recovery, protected by its independent login/CSRF/2FA controls.
	if failClosed && surface != "admin" {
		return true
	}
	if !found {
		return false
	}
	if ban.Scope == "public" && surface == "admin" {
		return false
	}
	if ban.Scope == "guide" && surface != "guide" {
		return false
	}
	if ban.ExpiresAt == 0 || ban.ExpiresAt > now {
		return true
	}
	s.banMu.Lock()
	delete(s.activeBans, ip)
	s.banMu.Unlock()
	return false
}

func (s *Server) observeHTTPStatus(ip, surface, path string, status int) {
	// Authenticated administration has its own session, CSRF and login-rate
	// protections. Counting its ordinary 404/502 responses could lock the only
	// administrator out because of a stale asset or a failed quota refresh.
	if surface == "admin" {
		return
	}
	if status != http.StatusNotFound && status != http.StatusBadGateway {
		return
	}
	config := s.currentSecurityConfig()
	if !config.ProtectionEnabled {
		return
	}
	threshold := config.Threshold404
	if status == http.StatusBadGateway {
		threshold = config.Threshold502
	}
	window := time.Duration(config.WindowMinutes) * time.Minute
	duration := time.Duration(config.BanHours) * time.Hour
	banned, err := s.store.RecordStatusFailure(context.Background(), ip, status, threshold, window, duration, surface+":"+path)
	runtimeKey := fmt.Sprintf("http_%d_ban", status)
	if err != nil {
		s.setSecurityRuntimeFailure(runtimeKey, err)
		return
	}
	s.setSecurityRuntimeFailure(runtimeKey, nil)
	if banned {
		s.activatePublicBan(context.Background(), ip, duration)
	}
}

func (s *Server) adminBanIP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP        string `json:"ip"`
		Reason    string `json:"reason"`
		Hours     int    `json:"hours"`
		Permanent bool   `json:"permanent"`
	}
	if !decodeJSON(w, r, 16<<10, &body) {
		return
	}
	parsed, err := netip.ParseAddr(strings.TrimSpace(body.IP))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_ip", "IP 地址无效")
		return
	}
	body.IP = parsed.Unmap().String()
	if body.IP == s.realIP(r) {
		writeError(w, http.StatusConflict, "self_ban_rejected", "不能封禁当前管理员的来源 IP")
		return
	}
	body.Reason = strings.TrimSpace(body.Reason)
	if body.Reason == "" {
		body.Reason = "管理员手动封禁"
	}
	if len(body.Reason) > 200 || (!body.Permanent && (body.Hours < 1 || body.Hours > 8760)) {
		writeError(w, http.StatusBadRequest, "invalid_ban", "封禁原因或有效期无效")
		return
	}
	adminIP := s.realIP(r)
	// Keep the device relation stable while resolving and writing the dual-stack
	// ban. The same lifecycle mutex protects Key IP additions/removals.
	s.keyRequestMu.Lock()
	relatedIPs, relatedErr := s.store.relatedDeviceIPs(r.Context(), body.IP)
	if relatedErr != nil {
		s.keyRequestMu.Unlock()
		writeError(w, http.StatusInternalServerError, "ban_members_failed", "无法读取关联的 IPv4 / IPv6，未执行封禁")
		return
	}
	s.banSyncMu.Lock()
	banErr := s.store.BanIP(r.Context(), body.IP, body.Reason, time.Duration(body.Hours)*time.Hour, body.Permanent, adminIP)
	if banErr == nil {
		expiresAt := int64(0)
		if !body.Permanent {
			// This is intentionally calculated after the commit: if the following
			// full refresh fails, the targeted cache may over-enforce by less than a
			// second but can never unblock before the durable database expiry.
			expiresAt = time.Now().Add(time.Duration(body.Hours) * time.Hour).Unix()
		}
		s.cacheBanMembersLocked(relatedIPs, activeBan{ExpiresAt: expiresAt, Scope: "all"})
	}
	s.banSyncMu.Unlock()
	s.keyRequestMu.Unlock()
	if banErr != nil {
		if errors.Is(banErr, ErrProtectedIP) {
			writeError(w, http.StatusConflict, "self_ban_rejected", "不能封禁当前管理员或其同设备关联的 IPv4 / IPv6")
			return
		}
		writeError(w, http.StatusInternalServerError, "ban_failed", "封禁 IP 失败")
		return
	}
	// The targeted entries above already make this operation immediate. A full
	// refresh reconciles exact database expiry and unrelated entries; its failure
	// is reported as degraded health without turning a successful ban into a
	// misleading failure response.
	cacheDegraded := s.refreshBanCache(r.Context()) != nil
	cancelled, cancelErr := s.cancelBannedIPRequests(body.IP, true)
	if cancelErr != nil {
		writeError(w, http.StatusGatewayTimeout, "ban_drain_timeout", "IP 已封禁且新请求已被拒绝，但等待在途请求退出超时")
		return
	}
	s.store.Audit(r.Context(), "admin", "ip.banned", body.IP, s.realIP(r), map[string]any{"reason": body.Reason, "hours": body.Hours, "permanent": body.Permanent, "cancelled_requests": cancelled, "cache_degraded": cacheDegraded})
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "cancelled_requests": cancelled, "banned_ips": relatedIPs, "cache_degraded": cacheDegraded})
}

func (s *Server) adminUpdateSecurity(w http.ResponseWriter, r *http.Request) {
	var config SecurityConfig
	if !decodeJSON(w, r, 16<<10, &config) {
		return
	}
	if config.Threshold404 < 3 || config.Threshold404 > 10000 || config.Threshold502 < 3 || config.Threshold502 > 10000 ||
		config.WindowMinutes < 1 || config.WindowMinutes > 1440 || config.BanHours < 1 || config.BanHours > 8760 {
		writeError(w, http.StatusBadRequest, "invalid_security_config", "阈值、统计窗口或封禁时长超出允许范围")
		return
	}
	if config.ProtectionEnabled && config.NginxProtection {
		s.nginxMu.Lock()
		fingerprint := s.nginxFingerprint()
		if !fingerprint.Available {
			s.nginxMu.Unlock()
			writeError(w, http.StatusConflict, "nginx_unavailable", "未找到完整且可读的 Nginx 配置，不能开启完整性监控")
			return
		}
		baseline, err := s.store.SettingValue(r.Context(), "security_nginx_baseline")
		if err != nil {
			s.setSecurityRuntimeFailure("nginx_persistence", fmt.Errorf("read Nginx baseline: %w", err))
			s.nginxMu.Unlock()
			writeError(w, http.StatusInternalServerError, "baseline_read_failed", "读取 Nginx 基线失败")
			return
		}
		if baseline == "" {
			if err := s.store.SaveNginxBaseline(r.Context(), fingerprint.Hash, nginxFingerprintVersion); err != nil {
				s.setSecurityRuntimeFailure("nginx_persistence", fmt.Errorf("save Nginx baseline: %w", err))
				s.nginxMu.Unlock()
				writeError(w, http.StatusInternalServerError, "baseline_failed", "保存 Nginx 基线失败")
				return
			}
		}
		s.setSecurityRuntimeFailure("nginx_persistence", nil)
		s.nginxMu.Unlock()
	}
	if err := s.store.SaveSecurityConfig(r.Context(), config); err != nil {
		writeError(w, http.StatusInternalServerError, "security_save_failed", "保存安全策略失败")
		return
	}
	s.setSecurityConfig(config)
	s.store.Audit(r.Context(), "admin", "security.protection.updated", "system", s.realIP(r), config)
	s.adminSecurityStatus(w, r)
}

type nginxFingerprintResult struct {
	Available        bool     `json:"available"`
	Hash             string   `json:"-"`
	FileCount        int      `json:"file_count"`
	TotalBytes       int64    `json:"total_bytes"`
	Truncated        bool     `json:"truncated"`
	Paths            []string `json:"paths"`
	MissingPaths     []string `json:"missing_paths,omitempty"`
	Errors           []string `json:"errors,omitempty"`
	ExistingRoots    int      `json:"-"`
	MissingRoots     int      `json:"-"`
	PermissionDenied bool     `json:"-"`
	fatal            bool
}

func (s *Server) nginxFingerprint() nginxFingerprintResult {
	return s.nginxFingerprintWithLimits(nginxMaxFiles, nginxMaxFileBytes, nginxMaxTotalBytes)
}

func (s *Server) nginxFingerprintWithLimits(maxFiles int, maxFileBytes, maxTotalBytes int64) nginxFingerprintResult {
	result := nginxFingerprintResult{Paths: append([]string(nil), s.cfg.NginxMonitorPaths...)}
	if maxFiles < 1 || maxFileBytes < 1 || maxTotalBytes < 1 {
		result.Errors = append(result.Errors, "invalid Nginx monitor limits")
		result.fatal = true
		return result
	}
	seen := map[string]bool{}
	directories := map[string]bool{}
	rootStates := make([]string, 0, len(s.cfg.NginxMonitorPaths))
	var files []string
	for _, configured := range s.cfg.NginxMonitorPaths {
		root := filepath.Clean(strings.TrimSpace(configured))
		if root == "." || root == "" {
			continue
		}
		info, err := os.Lstat(root)
		if err != nil {
			if os.IsNotExist(err) {
				result.MissingRoots++
				result.MissingPaths = append(result.MissingPaths, root)
				rootStates = append(rootStates, root+"\x00missing")
				// An uninstalled/unmounted optional Nginx tree is a real N/A
				// state, not an integrity error. Keep the paths separately so
				// the UI remains truthful without presenting expected lstat noise.
				continue
			}
			if os.IsPermission(err) {
				result.PermissionDenied = true
				result.fatal = true
			}
			result.fatal = true
			result.Errors = append(result.Errors, root+": "+err.Error())
			continue
		}
		result.ExistingRoots++
		rootStates = append(rootStates, root+"\x00present")
		if !info.IsDir() {
			if !seen[root] {
				if len(files) >= maxFiles {
					result.Truncated = true
					result.fatal = true
					result.Errors = append(result.Errors, fmt.Sprintf("Nginx monitor file limit exceeded (%d)", maxFiles))
					continue
				}
				seen[root] = true
				files = append(files, root)
			}
			continue
		}
		err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				if os.IsPermission(walkErr) {
					result.PermissionDenied = true
				}
				result.fatal = true
				result.Errors = append(result.Errors, path+": "+walkErr.Error())
				return nil
			}
			if entry.IsDir() {
				if !directories[path] && len(directories) >= maxFiles {
					result.Truncated = true
					result.fatal = true
					result.Errors = append(result.Errors, fmt.Sprintf("Nginx monitor directory limit exceeded (%d)", maxFiles))
					return filepath.SkipAll
				}
				directories[path] = true
				return nil
			}
			if !seen[path] {
				if len(files) >= maxFiles {
					result.Truncated = true
					result.fatal = true
					result.Errors = append(result.Errors, fmt.Sprintf("Nginx monitor file limit exceeded (%d)", maxFiles))
					return filepath.SkipAll
				}
				seen[path] = true
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			result.fatal = true
			result.Errors = append(result.Errors, root+": "+err.Error())
		}
	}
	sort.Strings(rootStates)
	sort.Strings(files)
	digest := sha256.New()
	for _, state := range rootStates {
		_, _ = io.WriteString(digest, "root\x00"+state+"\x00")
	}
	directoryPaths := make([]string, 0, len(directories))
	for path := range directories {
		directoryPaths = append(directoryPaths, path)
	}
	sort.Strings(directoryPaths)
	for _, path := range directoryPaths {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() {
			result.fatal = true
			if err != nil {
				result.Errors = append(result.Errors, path+": "+err.Error())
			} else {
				result.Errors = append(result.Errors, path+": directory changed while fingerprinting")
			}
			continue
		}
		writeNginxFileIdentity(digest, "directory", path, info)
	}
	for _, path := range files {
		linkInfo, err := os.Lstat(path)
		if err != nil {
			result.fatal = true
			result.Errors = append(result.Errors, path+": "+err.Error())
			continue
		}
		writeNginxFileIdentity(digest, "entry", path, linkInfo)
		resolvedInfo := linkInfo
		if linkInfo.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				result.fatal = true
				result.Errors = append(result.Errors, path+": "+err.Error())
				continue
			}
			_, _ = io.WriteString(digest, "link:"+target+"\x00")
			resolvedInfo, err = os.Stat(path)
			if err != nil {
				result.fatal = true
				result.Errors = append(result.Errors, path+": "+err.Error())
				continue
			}
			writeNginxFileIdentity(digest, "target", path, resolvedInfo)
		}
		if !resolvedInfo.Mode().IsRegular() {
			result.fatal = true
			result.Errors = append(result.Errors, path+": not a regular file")
			continue
		}
		if resolvedInfo.Size() < 0 || resolvedInfo.Size() > maxFileBytes {
			result.Truncated = true
			result.fatal = true
			result.Errors = append(result.Errors, fmt.Sprintf("%s: file exceeds %d byte monitor limit", path, maxFileBytes))
			continue
		}
		if result.TotalBytes+resolvedInfo.Size() > maxTotalBytes {
			result.Truncated = true
			result.fatal = true
			result.Errors = append(result.Errors, fmt.Sprintf("Nginx monitor total byte limit exceeded (%d)", maxTotalBytes))
			continue
		}
		fd, openErr := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if openErr != nil {
			wrapped := os.NewSyscallError("open", openErr)
			if os.IsPermission(wrapped) {
				result.PermissionDenied = true
			}
			result.fatal = true
			result.Errors = append(result.Errors, path+": "+wrapped.Error())
			continue
		}
		file := os.NewFile(uintptr(fd), path)
		openedInfo, statErr := file.Stat()
		if statErr != nil || !openedInfo.Mode().IsRegular() || !sameNginxFileIdentity(resolvedInfo, openedInfo) {
			_ = file.Close()
			result.fatal = true
			switch {
			case statErr != nil:
				result.Errors = append(result.Errors, path+": "+statErr.Error())
			case !openedInfo.Mode().IsRegular():
				result.Errors = append(result.Errors, path+": opened object is not a regular file")
			default:
				result.Errors = append(result.Errors, path+": file target changed while fingerprinting")
			}
			continue
		}
		contentDigest := sha256.New()
		readBytes, readErr := io.Copy(contentDigest, io.LimitReader(file, maxFileBytes+1))
		afterInfo, afterErr := file.Stat()
		closeErr := file.Close()
		if readErr != nil || afterErr != nil || closeErr != nil || readBytes > maxFileBytes || readBytes != openedInfo.Size() || !sameNginxFileIdentity(openedInfo, afterInfo) {
			result.Truncated = result.Truncated || readBytes > maxFileBytes
			result.fatal = true
			switch {
			case readErr != nil:
				result.Errors = append(result.Errors, path+": "+readErr.Error())
			case afterErr != nil:
				result.Errors = append(result.Errors, path+": "+afterErr.Error())
			case closeErr != nil:
				result.Errors = append(result.Errors, path+": "+closeErr.Error())
			case readBytes > maxFileBytes:
				result.Errors = append(result.Errors, fmt.Sprintf("%s: file grew beyond %d byte monitor limit", path, maxFileBytes))
			default:
				result.Errors = append(result.Errors, path+": file changed while fingerprinting")
			}
			continue
		}
		_, _ = io.WriteString(digest, strconv.FormatInt(readBytes, 10)+"\x00")
		_, _ = digest.Write(contentDigest.Sum(nil))
		_, _ = digest.Write([]byte{0})
		result.FileCount++
		result.TotalBytes += readBytes
	}
	result.Available = result.FileCount > 0 && !result.fatal
	if result.Available {
		result.Hash = hex.EncodeToString(digest.Sum(nil))
	}
	return result
}

func writeNginxFileIdentity(digest io.Writer, kind, path string, info os.FileInfo) {
	uid, gid := uint32(0), uint32(0)
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		uid, gid = stat.Uid, stat.Gid
	}
	_, _ = io.WriteString(digest, kind+"\x00"+path+"\x00"+info.Mode().String()+"\x00"+
		strconv.FormatUint(uint64(uid), 10)+"\x00"+strconv.FormatUint(uint64(gid), 10)+"\x00")
}

func sameNginxFileIdentity(first, second os.FileInfo) bool {
	if first == nil || second == nil || !os.SameFile(first, second) || first.Mode() != second.Mode() || first.Size() != second.Size() || !first.ModTime().Equal(second.ModTime()) {
		return false
	}
	firstStat, firstOK := first.Sys().(*syscall.Stat_t)
	secondStat, secondOK := second.Sys().(*syscall.Stat_t)
	return !firstOK || !secondOK || (firstStat.Uid == secondStat.Uid && firstStat.Gid == secondStat.Gid)
}

func (s *Server) nginxIntegrityStatus(ctx context.Context, record bool) map[string]any {
	s.nginxMu.Lock()
	defer s.nginxMu.Unlock()
	config := s.currentSecurityConfig()
	fingerprint := s.nginxFingerprint()
	baseline, baselineErr := s.store.SettingValue(ctx, "security_nginx_baseline")
	baselineVersion, versionErr := s.store.SettingValue(ctx, "security_nginx_baseline_version")
	lastAlert, markerErr := s.store.SettingValue(ctx, "security_nginx_last_alert_hash")
	var readErrors []error
	if baselineErr != nil {
		readErrors = append(readErrors, fmt.Errorf("read Nginx baseline: %w", baselineErr))
	}
	if versionErr != nil {
		readErrors = append(readErrors, fmt.Errorf("read Nginx baseline version: %w", versionErr))
	}
	if markerErr != nil {
		readErrors = append(readErrors, fmt.Errorf("read Nginx alert marker: %w", markerErr))
	}
	if persistenceErr := errors.Join(readErrors...); persistenceErr != nil {
		s.setSecurityRuntimeFailure("nginx_persistence", persistenceErr)
		baselineKnown := baselineErr == nil
		versionKnown := versionErr == nil
		baselineOutdated := baselineKnown && versionKnown && baseline != "" && baselineVersion != nginxFingerprintVersion
		return map[string]any{
			"enabled": config.ProtectionEnabled && config.NginxProtection, "configured": config.NginxProtection, "applicable": true, "available": fingerprint.Available, "state": "persistence_error",
			"modified": false, "baseline_set": baselineKnown && baseline != "", "baseline_known": baselineKnown, "baseline_outdated": baselineOutdated, "baseline_version": baselineVersion,
			"file_count": fingerprint.FileCount, "total_bytes": fingerprint.TotalBytes, "truncated": fingerprint.Truncated,
			"paths": fingerprint.Paths, "missing_paths": fingerprint.MissingPaths, "errors": fingerprint.Errors, "persistence_error": truncate(persistenceErr.Error(), 300), "checked_at": time.Now().Unix(),
		}
	}
	baselineOutdated := baseline != "" && baselineVersion != nginxFingerprintVersion
	modified := baseline != "" && !baselineOutdated && (!fingerprint.Available || fingerprint.Hash != baseline)
	var persistenceErr error
	if record && config.ProtectionEnabled && config.NginxProtection && modified {
		alertMarker := nginxAlertMarker(fingerprint)
		if lastAlert != alertMarker {
			if err := s.store.RecordSecurityEvent(ctx, "system", "nginx_config_modified", strings.Join(s.cfg.NginxMonitorPaths, ","), "当前 SHA-256 与管理员确认的基线不一致"); err != nil {
				persistenceErr = fmt.Errorf("persist Nginx modification event: %w", err)
			} else if err := s.store.SetSetting(ctx, "security_nginx_last_alert_hash", alertMarker); err != nil {
				persistenceErr = fmt.Errorf("persist Nginx alert marker: %w", err)
			}
		}
	} else if record && baseline != "" && fingerprint.Available && fingerprint.Hash == baseline && lastAlert != "" {
		// Clearing the episode marker is essential: if the exact same modification
		// happens again after a recovery, it must produce a fresh event.
		if err := s.store.RecordSecurityEvent(ctx, "system", "nginx_config_recovered", strings.Join(s.cfg.NginxMonitorPaths, ","), "当前 SHA-256 已恢复为管理员确认的基线"); err != nil {
			persistenceErr = fmt.Errorf("persist Nginx recovery event: %w", err)
		} else if err := s.store.SetSetting(ctx, "security_nginx_last_alert_hash", ""); err != nil {
			persistenceErr = fmt.Errorf("clear Nginx alert marker: %w", err)
		}
	}
	s.setSecurityRuntimeFailure("nginx_persistence", persistenceErr)
	state := "monitoring"
	if baselineOutdated {
		state = "baseline_outdated"
	} else if !fingerprint.Available {
		state = "unavailable"
		if fingerprint.PermissionDenied {
			state = "permission_denied"
		} else if fingerprint.ExistingRoots == 0 && fingerprint.MissingRoots == len(s.cfg.NginxMonitorPaths) {
			state = "not_installed_or_not_mounted"
		}
	}
	// An installed-but-unreadable or malformed Nginx tree is applicable and
	// unhealthy, not N/A. Only an entirely absent/unmounted tree with no prior
	// baseline is excluded from the health denominator.
	applicable := fingerprint.Available || baseline != "" || fingerprint.ExistingRoots > 0 || fingerprint.PermissionDenied
	return map[string]any{
		"enabled": config.ProtectionEnabled && config.NginxProtection && applicable, "configured": config.NginxProtection, "applicable": applicable, "available": fingerprint.Available, "state": state,
		"modified": modified, "baseline_set": baseline != "", "baseline_outdated": baselineOutdated, "baseline_version": baselineVersion, "file_count": fingerprint.FileCount,
		"total_bytes": fingerprint.TotalBytes, "truncated": fingerprint.Truncated,
		"paths": fingerprint.Paths, "missing_paths": fingerprint.MissingPaths, "errors": fingerprint.Errors, "checked_at": time.Now().Unix(),
	}
}

func nginxAlertMarker(fingerprint nginxFingerprintResult) string {
	identity := fingerprint.Hash
	if identity == "" {
		sum := sha256.Sum256([]byte(strings.Join(fingerprint.Paths, "\x00") + "\x01" + strings.Join(fingerprint.Errors, "\x00") +
			fmt.Sprintf("\x01%d\x01%d\x01%t", fingerprint.FileCount, fingerprint.TotalBytes, fingerprint.Truncated)))
		identity = hex.EncodeToString(sum[:])
	}
	return "alert:" + identity
}

func (s *Server) adminNginxBaseline(w http.ResponseWriter, r *http.Request) {
	s.nginxMu.Lock()
	fingerprint := s.nginxFingerprint()
	if !fingerprint.Available {
		s.nginxMu.Unlock()
		writeError(w, http.StatusConflict, "nginx_unavailable", "没有找到可读的 Nginx 配置文件，不能建立基线")
		return
	}
	err := s.store.SaveNginxBaseline(r.Context(), fingerprint.Hash, nginxFingerprintVersion)
	s.nginxMu.Unlock()
	if err != nil {
		s.setSecurityRuntimeFailure("nginx_persistence", fmt.Errorf("save Nginx baseline: %w", err))
		writeError(w, http.StatusInternalServerError, "baseline_failed", "保存 Nginx 基线失败")
		return
	}
	s.setSecurityRuntimeFailure("nginx_persistence", nil)
	s.store.Audit(r.Context(), "admin", "nginx.baseline.confirmed", strconv.Itoa(fingerprint.FileCount), s.realIP(r), map[string]any{"paths": fingerprint.Paths})
	s.adminSecurityStatus(w, r)
}

func (s *Server) securityStatus(ctx context.Context) map[string]any {
	config := s.currentSecurityConfig()
	observabilityErr := s.store.CheckObservability(ctx)
	events, anomaliesErr := s.store.ListSecurityEvents(ctx, 50)
	if anomaliesErr != nil {
		s.setSecurityRuntimeFailure("security_log_read", anomaliesErr)
	} else {
		s.setSecurityRuntimeFailure("security_log_read", nil)
	}
	setupRequired, setupStateErr := s.store.AdminSetupRequired(ctx)
	totpHealthErr := s.store.CheckAdminTOTP(ctx)
	nginx := s.nginxIntegrityStatus(ctx, true)
	// Nginx monitoring may itself persist a security event, so calculate this
	// after that operation to keep the check and runtime_errors consistent in
	// the very same response.
	logPipelinesHealthy := !s.hasSecurityRuntimeFailure("usage_log", "audit_log", "security_log", "security_log_read")
	nginxAvailable, _ := nginx["available"].(bool)
	nginxModified, _ := nginx["modified"].(bool)
	nginxBaselineSet, _ := nginx["baseline_set"].(bool)
	nginxBaselineOutdated, _ := nginx["baseline_outdated"].(bool)
	nginxApplicable, _ := nginx["applicable"].(bool)
	nginxPersistenceHealthy := !s.hasSecurityRuntimeFailure("nginx_persistence")
	nginxMode := "runtime"
	nginxDetail := "实时读取文件并对内容、所有者、权限与符号链接计算 SHA-256"
	if !nginxApplicable {
		nginxMode = "not_applicable"
		nginxDetail = "当前环境未安装或未挂载 Nginx；此项不计入健康分"
	}
	browserBoundaryDetail := "CSP、nosniff、DENY frame 与权限策略由统一中间件强制；"
	if s.cfg.SecureCookies {
		browserBoundaryDetail += "已配置 Secure Cookie 与 HSTS（反向代理证书需在代理层独立验证）"
	} else {
		browserBoundaryDetail += "Secure Cookie/HSTS 未配置，公网使用前必须先启用 HTTPS"
	}
	banCacheHealthy := !s.hasSecurityRuntimeFailure("ban_cache")
	banCancellationHealthy := !s.hasSecurityRuntimeFailure("ban_request_cancel")
	unauthorizedBanHealthy := banCacheHealthy && banCancellationHealthy && !s.hasSecurityRuntimeFailure("unauthorized_ban")
	http404BanHealthy := banCacheHealthy && banCancellationHealthy && !s.hasSecurityRuntimeFailure("http_404_ban")
	http502BanHealthy := banCacheHealthy && banCancellationHealthy && !s.hasSecurityRuntimeFailure("http_502_ban")
	checks := []SecurityCheck{
		{Key: "observability", Name: "数据库与安全记录", Enabled: true, Healthy: observabilityErr == nil && logPipelinesHealthy, Mode: "runtime", Detail: func() string {
			if observabilityErr != nil {
				return "SQLite 记录库当前无法完成可回滚的读写检查"
			}
			if !logPipelinesHealthy {
				return "日志表实时探针可用，但最近的真实使用、审计或安全记录读写曾失败，需在对应真实操作成功后恢复"
			}
			return "SQLite 核心日志表存在，且已通过可回滚的实时读写检查"
		}()},
		{Key: "totp", Name: "管理员 Microsoft 2FA", Enabled: true, Healthy: setupStateErr == nil && !setupRequired && totpHealthErr == nil, Mode: "runtime", Detail: func() string {
			if setupStateErr != nil {
				return "无法读取管理员初始化状态；创建渠道保持关闭，需检查 SQLite"
			}
			if setupRequired {
				return "管理员尚未完成 Microsoft Authenticator 绑定"
			}
			if totpHealthErr != nil {
				return "加密 TOTP 密钥或防重放计数无法通过实时校验；管理员登录可能不可用"
			}
			return "加密 TOTP 密钥已完成解密与格式校验，登录执行 RFC 6238 与防重放"
		}()},
		{Key: "csrf", Name: "CSRF 与同源校验", Enabled: true, Healthy: true, Mode: "enforced", Detail: "后台写操作强制校验会话 CSRF Token"},
		{Key: "login_limit", Name: "管理员登录限流", Enabled: true, Healthy: true, Mode: "enforced", Detail: "进程内按来源 IP 限制登录与初始化失败尝试，并使用固定容量防止内存耗尽"},
		{Key: "api_acl", Name: "API Key 与 IP 白名单", Enabled: true, Healthy: true, Mode: "enforced", Detail: "每次请求查询 Key 状态并校验 IPv4/IPv6 设备授权"},
		{Key: "unauthorized_ban", Name: "未授权访问自动封禁", Enabled: true, Healthy: unauthorizedBanHealthy, Mode: "runtime", Detail: fmt.Sprintf("%d 次异常 API 鉴权触发；计数持久化与封禁缓存均接受实时检查", s.cfg.BanThreshold)},
		{Key: "http_404_ban", Name: "HTTP 404 自动封禁", Enabled: config.ProtectionEnabled, Healthy: config.ProtectionEnabled && http404BanHealthy, Mode: "runtime", Detail: fmt.Sprintf("API/邀请端 %d 次 / %d 分钟；运行错误会在本页降级显示", config.Threshold404, config.WindowMinutes)},
		{Key: "http_502_ban", Name: "HTTP 502 自动封禁", Enabled: config.ProtectionEnabled, Healthy: config.ProtectionEnabled && http502BanHealthy, Mode: "runtime", Detail: fmt.Sprintf("API/邀请端 %d 次 / %d 分钟；运行错误会在本页降级显示", config.Threshold502, config.WindowMinutes)},
		{Key: "request_limits", Name: "请求体与方法限制", Enabled: true, Healthy: true, Mode: "enforced", Detail: fmt.Sprintf("最大请求体 %d MiB、64 KiB 请求头和读取超时", s.cfg.MaxBodyBytes>>20)},
		{Key: "headers", Name: "浏览器安全边界与 HTTPS 配置", Enabled: true, Healthy: s.cfg.SecureCookies, Mode: "configured", Detail: browserBoundaryDetail},
		{Key: "nginx", Name: "Nginx 配置完整性", Enabled: nginxApplicable && config.ProtectionEnabled && config.NginxProtection, Healthy: nginxApplicable && config.ProtectionEnabled && config.NginxProtection && nginxAvailable && nginxBaselineSet && !nginxBaselineOutdated && !nginxModified && nginxPersistenceHealthy, Mode: nginxMode, Detail: nginxDetail},
	}
	healthy, applicable := 0, 0
	for _, check := range checks {
		if check.Mode == "not_applicable" {
			continue
		}
		applicable++
		if check.Healthy {
			healthy++
		}
	}
	recent := events[:0]
	cutoff := time.Now().Add(-24 * time.Hour).Unix()
	for _, event := range events {
		if event.CreatedAt >= cutoff {
			recent = append(recent, event)
		}
		if len(recent) == 20 {
			break
		}
	}
	healthPercent := 0
	if applicable > 0 {
		healthPercent = healthy * 100 / applicable
	}
	result := map[string]any{
		"config": config, "checks": checks, "health_percent": healthPercent, "health_applicable_checks": applicable,
		"nginx": nginx, "anomalies": recent, "runtime_errors": s.securityRuntimeFailures(),
	}
	if observabilityErr != nil {
		result["observability_error"] = truncate(observabilityErr.Error(), 300)
	}
	if anomaliesErr != nil {
		result["anomalies_error"] = truncate(anomaliesErr.Error(), 300)
	}
	return result
}

func (s *Server) adminSecurityStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.securityStatus(r.Context()))
}

func (s *Server) securityMonitorLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !s.beginRuntimeOperation() {
				continue
			}
			config := s.currentSecurityConfig()
			if config.ProtectionEnabled && config.NginxProtection {
				_ = s.nginxIntegrityStatus(context.Background(), true)
			}
			s.refreshBanCache(context.Background())
			s.restoreGate.RUnlock()
		}
	}
}
