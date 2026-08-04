package app

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	APIAddr      string
	AdminAddr    string
	InviteAddr   string
	GuideAddr    string
	PortalAddr   string
	DataDir      string
	DatabasePath string
	// PlatformDatabaseURL is the PostgreSQL authority for the unified
	// multi-user product domain. It is intentionally separate during the
	// verified SQLite-to-PostgreSQL migration: existing gateway credentials are
	// never silently copied or discarded merely because a URL is configured.
	PlatformDatabaseURL string
	// PlatformGatewayEnabled switches the public /v1 gateway to the
	// PostgreSQL-backed product domain. It is deliberately opt-in during the
	// audited SQLite-to-PostgreSQL transition, so setting a database URL alone
	// can never silently move existing external keys to a different authority.
	PlatformGatewayEnabled bool
	PlatformDBMaxOpen      int
	PlatformDBMaxIdle      int
	PlatformDBMaxLife      time.Duration
	AdminUsername          string
	AdminPassword          string
	PublicInviteURL        string
	PublicGuideURL         string
	PublicPortalURL        string
	PublicAPIURL           string
	PublicIPv4ProbeURL     string
	PublicIPv6ProbeURL     string
	UpstreamBaseURL        string
	QuotaBaseURL           string
	MasterKey              []byte
	SecureCookies          bool
	TrustedProxies         []netip.Prefix
	BanThreshold           int
	BanWindow              time.Duration
	BanDuration            time.Duration
	InviteTTL              time.Duration
	RevealTTL              time.Duration
	SessionTTL             time.Duration
	UserSessionTTL         time.Duration
	DesktopFlowTTL         time.Duration
	DesktopAccessTTL       time.Duration
	DesktopRefreshTTL      time.Duration
	StickyTTL              time.Duration
	AccountCooldown        time.Duration
	QuotaSyncInterval      time.Duration
	MaxBodyBytes           int64
	ShutdownTimeout        time.Duration
	NginxMonitorPaths      []string
}

func LoadConfig() (Config, error) {
	cfg := Config{
		APIAddr:                env("LITE_API_ADDR", ":8080"),
		AdminAddr:              env("LITE_ADMIN_ADDR", ":8081"),
		InviteAddr:             env("LITE_INVITE_ADDR", ":8082"),
		GuideAddr:              env("LITE_GUIDE_ADDR", ":8083"),
		PortalAddr:             env("LITE_PORTAL_ADDR", ":8084"),
		DataDir:                env("LITE_DATA_DIR", "./data/lite"),
		PlatformDatabaseURL:    strings.TrimSpace(os.Getenv("LITE_DATABASE_URL")),
		PlatformGatewayEnabled: envBool("LITE_PLATFORM_GATEWAY_ENABLED", false),
		PlatformDBMaxOpen:      envInt("LITE_DATABASE_MAX_OPEN", 8),
		PlatformDBMaxIdle:      envInt("LITE_DATABASE_MAX_IDLE", 4),
		PlatformDBMaxLife:      envDuration("LITE_DATABASE_MAX_LIFETIME", 30*time.Minute),
		AdminUsername:          env("LITE_ADMIN_USERNAME", "admin"),
		AdminPassword:          os.Getenv("LITE_ADMIN_PASSWORD"),
		PublicInviteURL:        strings.TrimRight(env("LITE_PUBLIC_INVITE_URL", "http://localhost:8082"), "/"),
		PublicGuideURL:         strings.TrimRight(env("LITE_PUBLIC_GUIDE_URL", "http://localhost:8083"), "/"),
		PublicPortalURL:        strings.TrimRight(env("LITE_PUBLIC_PORTAL_URL", "http://localhost:8084"), "/"),
		PublicAPIURL:           strings.TrimRight(env("LITE_PUBLIC_API_URL", "http://localhost:8080/v1"), "/"),
		PublicIPv4ProbeURL:     strings.TrimRight(os.Getenv("LITE_PUBLIC_IPV4_PROBE_URL"), "/"),
		PublicIPv6ProbeURL:     strings.TrimRight(os.Getenv("LITE_PUBLIC_IPV6_PROBE_URL"), "/"),
		UpstreamBaseURL:        strings.TrimRight(env("LITE_UPSTREAM_BASE_URL", "https://chatgpt.com/backend-api/codex"), "/"),
		QuotaBaseURL:           strings.TrimRight(env("LITE_QUOTA_BASE_URL", "https://chatgpt.com/backend-api/wham"), "/"),
		SecureCookies:          envBool("LITE_SECURE_COOKIES", false),
		BanThreshold:           envInt("LITE_BAN_THRESHOLD", 20),
		BanWindow:              envDuration("LITE_BAN_WINDOW", time.Minute),
		BanDuration:            envDuration("LITE_BAN_DURATION", 24*time.Hour),
		InviteTTL:              envDuration("LITE_INVITE_TTL", 7*24*time.Hour),
		RevealTTL:              60 * time.Second,
		SessionTTL:             envDuration("LITE_ADMIN_SESSION_TTL", 12*time.Hour),
		UserSessionTTL:         envDuration("LITE_USER_SESSION_TTL", 7*24*time.Hour),
		DesktopFlowTTL:         envDuration("LITE_DESKTOP_FLOW_TTL", 10*time.Minute),
		DesktopAccessTTL:       envDuration("LITE_DESKTOP_ACCESS_TTL", 15*time.Minute),
		DesktopRefreshTTL:      envDuration("LITE_DESKTOP_REFRESH_TTL", 30*24*time.Hour),
		StickyTTL:              envDuration("LITE_STICKY_SESSION_TTL", time.Hour),
		AccountCooldown:        envDuration("LITE_ACCOUNT_COOLDOWN", 5*time.Minute),
		QuotaSyncInterval:      envDuration("LITE_QUOTA_SYNC_INTERVAL", 5*time.Minute),
		MaxBodyBytes:           int64(envInt("LITE_MAX_BODY_MIB", 64)) << 20,
		ShutdownTimeout:        15 * time.Second,
		NginxMonitorPaths:      splitCSV(env("LITE_NGINX_MONITOR_PATHS", "/etc/nginx/nginx.conf,/etc/nginx/conf.d,/etc/nginx/sites-enabled")),
	}
	if strings.TrimSpace(cfg.AdminPassword) == "" {
		return Config{}, errors.New("LITE_ADMIN_PASSWORD is required")
	}
	if cfg.BanThreshold < 3 || cfg.BanThreshold > 10000 {
		return Config{}, fmt.Errorf("LITE_BAN_THRESHOLD must be between 3 and 10000")
	}
	if cfg.MaxBodyBytes < 1<<20 || cfg.MaxBodyBytes > 512<<20 {
		return Config{}, fmt.Errorf("LITE_MAX_BODY_MIB must be between 1 and 512")
	}
	if cfg.PlatformDatabaseURL != "" {
		if !strings.HasPrefix(cfg.PlatformDatabaseURL, "postgres://") && !strings.HasPrefix(cfg.PlatformDatabaseURL, "postgresql://") {
			return Config{}, errors.New("LITE_DATABASE_URL must be a PostgreSQL URL")
		}
		if cfg.PlatformDBMaxOpen < 1 || cfg.PlatformDBMaxOpen > 64 || cfg.PlatformDBMaxIdle < 0 || cfg.PlatformDBMaxIdle > cfg.PlatformDBMaxOpen || cfg.PlatformDBMaxLife <= 0 {
			return Config{}, errors.New("invalid PostgreSQL connection pool settings")
		}
	}
	if cfg.PlatformGatewayEnabled && cfg.PlatformDatabaseURL == "" {
		return Config{}, errors.New("LITE_PLATFORM_GATEWAY_ENABLED requires LITE_DATABASE_URL")
	}
	if cfg.StickyTTL <= 0 || cfg.AccountCooldown <= 0 || cfg.QuotaSyncInterval <= 0 ||
		cfg.UserSessionTTL <= 0 || cfg.DesktopFlowTTL <= 0 || cfg.DesktopAccessTTL <= 0 || cfg.DesktopRefreshTTL <= cfg.DesktopAccessTTL {
		return Config{}, errors.New("sticky session TTL and account cooldown must be positive")
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return Config{}, fmt.Errorf("create data directory: %w", err)
	}
	// MkdirAll does not tighten an already-existing bind mount or a directory
	// created by an operator's default umask. The SQLite database contains IPs,
	// audit history and encrypted credentials, so prevent other local users from
	// traversing the data directory even though the individual secrets are also
	// protected by the vault.
	if err := os.Chmod(cfg.DataDir, 0o700); err != nil {
		return Config{}, fmt.Errorf("secure data directory permissions: %w", err)
	}
	cfg.DatabasePath = filepath.Join(cfg.DataDir, "friendgate.db")
	key, err := loadMasterKey(cfg.DataDir, os.Getenv("LITE_MASTER_KEY"))
	if err != nil {
		return Config{}, err
	}
	cfg.MasterKey = key
	for _, raw := range splitCSV(os.Getenv("LITE_TRUSTED_PROXIES")) {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid trusted proxy %q: %w", raw, err)
		}
		cfg.TrustedProxies = append(cfg.TrustedProxies, prefix.Masked())
	}
	return cfg, nil
}

func loadMasterKey(dataDir, configured string) ([]byte, error) {
	if strings.TrimSpace(configured) != "" {
		key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(configured))
		if err != nil || len(key) != 32 {
			return nil, errors.New("LITE_MASTER_KEY must be 32 random bytes encoded as unpadded base64url")
		}
		return key, nil
	}
	path := filepath.Join(dataDir, "master.key")
	if value, err := os.ReadFile(path); err == nil {
		key, decodeErr := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(value)))
		if decodeErr != nil || len(key) != 32 {
			return nil, errors.New("data/lite/master.key is invalid")
		}
		return key, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read master key: %w", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate master key: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(key)
	if err := os.WriteFile(path, []byte(encoded+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("persist master key: %w", err)
	}
	return key, nil
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func splitCSV(value string) []string {
	var result []string
	for _, part := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
