package geminicli

// Keep OAuth unit tests self-contained without embedding a deployable Google
// client credential in the repository.
func init() {
	GeminiCLIOAuthClientID = "test-gemini-client-id"
	GeminiCLIOAuthClientSecret = "test-gemini-client-secret"
}
