package app

type Account struct {
	ID               int64  `json:"id"`
	Name             string `json:"name"`
	ChatGPTAccountID string `json:"chatgpt_account_id"`
	Active           bool   `json:"active"`
	// Retained only for migration compatibility with early Lite databases.
	// Proxy traffic is intentionally unlimited at the account layer.
	MaxConcurrency   int      `json:"-"`
	ExpiresAt        int64    `json:"expires_at,omitempty"`
	LastUsedAt       int64    `json:"last_used_at,omitempty"`
	LastError        string   `json:"last_error,omitempty"`
	CooldownUntil    int64    `json:"cooldown_until,omitempty"`
	PlanType         string   `json:"plan_type,omitempty"`
	Quota5HUsed      float64  `json:"quota_5h_used"`
	Quota5HResetAt   int64    `json:"quota_5h_reset_at,omitempty"`
	Quota7DUsed      float64  `json:"quota_7d_used"`
	Quota7DResetAt   int64    `json:"quota_7d_reset_at,omitempty"`
	QuotaUpdatedAt   int64    `json:"quota_updated_at,omitempty"`
	QuotaError       string   `json:"quota_error,omitempty"`
	ResetCredits     int      `json:"reset_credits"`
	ResetCreditTimes []string `json:"reset_credit_times,omitempty"`
	CreatedAt        int64    `json:"created_at"`
	AccessToken      string   `json:"-"`
	RefreshToken     string   `json:"-"`
	ClientID         string   `json:"-"`
}

type APIKey struct {
	ID            int64   `json:"id"`
	Role          string  `json:"role"`
	MaskedKey     string  `json:"masked_key"`
	AffinityCount int64   `json:"affinity_count,omitempty"`
	QuotaRequests int64   `json:"quota_requests"`
	UsedRequests  int64   `json:"used_requests"`
	Status        string  `json:"status"`
	LastUsedAt    int64   `json:"last_used_at,omitempty"`
	CreatedAt     int64   `json:"created_at"`
	AllowedIPs    []KeyIP `json:"allowed_ips,omitempty"`
	DeviceBound   bool    `json:"device_bound,omitempty"`
	EncryptedKey  string  `json:"-"`
	AccountID     int64   `json:"-"`
}

type KeyIP struct {
	ID          int64  `json:"id"`
	IP          string `json:"ip"`
	Family      string `json:"family,omitempty"`
	DeviceNote  string `json:"device_note"`
	DeviceGroup string `json:"-"`
	CreatedAt   int64  `json:"created_at"`
	LastSeenAt  int64  `json:"last_seen_at,omitempty"`
}

type DesktopUser struct {
	ID          int64  `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	APIKeyID    int64  `json:"api_key_id,omitempty"`
	KeyRole     string `json:"key_role,omitempty"`
	LastLoginAt int64  `json:"last_login_at,omitempty"`
	CreatedAt   int64  `json:"created_at"`
}

type DesktopDevice struct {
	ID           int64  `json:"id"`
	UserID       int64  `json:"user_id"`
	UserEmail    string `json:"user_email,omitempty"`
	Name         string `json:"name"`
	Platform     string `json:"platform,omitempty"`
	MAC          string `json:"mac,omitempty"`
	RegisteredIP string `json:"registered_ip"`
	LastIP       string `json:"last_ip,omitempty"`
	Status       string `json:"status"`
	LastSeenAt   int64  `json:"last_seen_at,omitempty"`
	CreatedAt    int64  `json:"created_at"`
}

type DesktopPolicy struct {
	RegistrationEnabled bool `json:"registration_enabled"`
	// ExternalAPIMode is the authoritative three-state policy for callers that
	// are not the signed desktop client: authenticated_public,
	// official_client_only, or disabled. The two booleans remain in the wire
	// shape while existing installations migrate their stored settings.
	ExternalAPIMode     string   `json:"external_api_mode"`
	PublicAPIEnabled    bool     `json:"public_api_enabled"`
	OfficialDesktopOnly bool     `json:"official_desktop_only"`
	GatewayBaseURL      string   `json:"gateway_base_url"`
	ProviderName        string   `json:"provider_name"`
	DefaultModel        string   `json:"default_model"`
	AllowedModels       []string `json:"allowed_models"`
	SystemPrompt        string   `json:"system_prompt"`
}

type Invitation struct {
	ID               int64          `json:"id"`
	Role             string         `json:"role"`
	Token            string         `json:"-"`
	InviteURL        string         `json:"invite_url,omitempty"`
	Status           string         `json:"status"`
	AccountID        int64          `json:"account_id,omitempty"`
	QuotaRequests    int64          `json:"quota_requests"`
	ExpiresAt        int64          `json:"expires_at"`
	CreatedAt        int64          `json:"created_at"`
	GeneratedAt      int64          `json:"generated_at,omitempty"`
	RevealUntil      int64          `json:"reveal_until,omitempty"`
	VerifiedIP       string         `json:"verified_ip,omitempty"`
	ObservedIPs      []InvitationIP `json:"observed_ips,omitempty"`
	DeviceNote       string         `json:"device_note,omitempty"`
	BindingMode      string         `json:"binding_mode"`
	APIKeyID         int64          `json:"api_key_id,omitempty"`
	APIKeyStatus     string         `json:"api_key_status,omitempty"`
	ClaimSessionHash string         `json:"-"`
	ProbeTokenHash   string         `json:"-"`
}

type InvitationIP struct {
	IP        string `json:"ip"`
	Family    string `json:"family"`
	CreatedAt int64  `json:"created_at"`
}

type UsageLog struct {
	ID           int64  `json:"id"`
	Role         string `json:"role"`
	AccountName  string `json:"account_name"`
	IP           string `json:"ip"`
	Method       string `json:"method"`
	Path         string `json:"path"`
	Model        string `json:"model,omitempty"`
	Status       int    `json:"status"`
	DurationMS   int64  `json:"duration_ms"`
	InputTokens  int64  `json:"input_tokens,omitempty"`
	OutputTokens int64  `json:"output_tokens,omitempty"`
	TotalTokens  int64  `json:"total_tokens,omitempty"`
	RequestID    string `json:"request_id,omitempty"`
	Error        string `json:"error,omitempty"`
	CreatedAt    int64  `json:"created_at"`
}

type ModelUsageRank struct {
	Model       string `json:"model"`
	Calls       int64  `json:"calls"`
	TotalTokens int64  `json:"total_tokens"`
}

type AuditLog struct {
	ID        int64  `json:"id"`
	Actor     string `json:"actor"`
	Action    string `json:"action"`
	Target    string `json:"target"`
	IP        string `json:"ip"`
	Detail    string `json:"detail,omitempty"`
	CreatedAt int64  `json:"created_at"`
}

type SecurityEvent struct {
	ID        int64  `json:"id"`
	IP        string `json:"ip"`
	Kind      string `json:"kind"`
	Path      string `json:"path,omitempty"`
	Detail    string `json:"detail,omitempty"`
	CreatedAt int64  `json:"created_at"`
}

type BannedIP struct {
	IP        string `json:"ip"`
	Reason    string `json:"reason"`
	Scope     string `json:"scope"`
	Attempts  int64  `json:"attempts"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

type SecurityConfig struct {
	ProtectionEnabled bool `json:"protection_enabled"`
	NginxProtection   bool `json:"nginx_protection"`
	Threshold404      int  `json:"threshold_404"`
	Threshold502      int  `json:"threshold_502"`
	WindowMinutes     int  `json:"window_minutes"`
	BanHours          int  `json:"ban_hours"`
}

type SecurityCheck struct {
	Key     string `json:"key"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Healthy bool   `json:"healthy"`
	Mode    string `json:"mode"`
	Detail  string `json:"detail"`
}
