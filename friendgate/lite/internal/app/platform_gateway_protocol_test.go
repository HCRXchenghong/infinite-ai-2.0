package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPlatformGatewayProtocolSpecAndGeminiRequest(t *testing.T) {
	spec, ok := platformGatewayProtocolForPath("/v1beta/models/infinite-pro:generateContent")
	if !ok || spec.Protocol != "generate_content" || spec.RequiredProviderKind != "gemini_compatible" || spec.RequestedModel != "infinite-pro" || spec.RequiresBodyModel {
		t.Fatalf("unexpected Gemini spec: %+v ok=%v", spec, ok)
	}
	streamSpec, ok := platformGatewayProtocolForPath("/v1/models/infinite-pro:streamGenerateContent")
	if !ok || streamSpec.GeminiAction != "streamGenerateContent" {
		t.Fatalf("unexpected Gemini stream spec: %+v ok=%v", streamSpec, ok)
	}
	msgSpec, ok := platformGatewayProtocolForPath("/v1/messages")
	if !ok || msgSpec.Protocol != "messages" || msgSpec.RequiredProviderKind != "anthropic_compatible" || !msgSpec.RequiresBodyModel {
		t.Fatalf("unexpected Anthropic spec: %+v ok=%v", msgSpec, ok)
	}
	if _, ok := platformGatewayProtocolForPath("/v1beta/models/infinite/pro:generateContent"); ok {
		t.Fatal("Gemini public model aliases must not accept slash-separated private IDs")
	}

	req := httptest.NewRequest(http.MethodPost, "http://gateway.invalid/v1beta/models/infinite-pro:generateContent", strings.NewReader(`{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"generationConfig":{"maxOutputTokens":42},"cachedContent":"cachedContents/abc"}`))
	parsed, err := readPlatformGatewayRequestForSpec(httptest.NewRecorder(), req, 1<<20, spec)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.RequestedModel != "infinite-pro" || parsed.SessionSeed != "cachedContents/abc" || parsed.ReservationTokens <= 42 {
		t.Fatalf("Gemini request metadata mismatch: %+v", parsed)
	}
}

func TestPlatformNativeUsageParsing(t *testing.T) {
	input, output, total := parseUsage([]byte(`{"type":"message","usage":{"input_tokens":3,"output_tokens":4}}`))
	if input != 3 || output != 4 || total != 7 {
		t.Fatalf("Anthropic usage parsed as input=%d output=%d total=%d", input, output, total)
	}
	input, output, total = parseUsage([]byte(`{"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":7,"thoughtsTokenCount":2,"totalTokenCount":14}}`))
	if input != 5 || output != 9 || total != 14 {
		t.Fatalf("Gemini usage parsed as input=%d output=%d total=%d", input, output, total)
	}
	input, output, total = parseUsage([]byte("data: {\"usageMetadata\":{\"promptTokenCount\":2,\"candidatesTokenCount\":6,\"totalTokenCount\":8}}\n\n"))
	if input != 2 || output != 6 || total != 8 {
		t.Fatalf("Gemini SSE usage parsed as input=%d output=%d total=%d", input, output, total)
	}
}

func TestPlatformGeminiModelResource(t *testing.T) {
	got, err := platformGeminiModelResource("gemini-2.5-pro")
	if err != nil || got != "models/gemini-2.5-pro" {
		t.Fatalf("Gemini short model resource=%q err=%v", got, err)
	}
	got, err = platformGeminiModelResource("models/gemini-2.5-pro")
	if err != nil || got != "models/gemini-2.5-pro" {
		t.Fatalf("Gemini full model resource=%q err=%v", got, err)
	}
}
