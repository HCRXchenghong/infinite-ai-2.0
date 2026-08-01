package antigravity

// Safe fixtures for tests; deployment OAuth credentials are supplied through
// ANTIGRAVITY_OAUTH_CLIENT_ID/ANTIGRAVITY_OAUTH_CLIENT_SECRET at runtime.
func init() {
	ClientID = "test-antigravity-client-id"
	defaultClientSecret = "test-antigravity-client-secret"
}
