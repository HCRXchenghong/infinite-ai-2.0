package pbws

import (
	"testing"

	gatewayv2 "github.com/liveagent/agent-gateway/internal/proto/v2"
	"github.com/liveagent/agent-gateway/internal/session"
)

func TestVetAgentRequestAllowsProviderUsage(t *testing.T) {
	env := &gatewayv2.GatewayEnvelope{
		Payload: &gatewayv2.GatewayEnvelope_ProviderUsage{
			ProviderUsage: &gatewayv2.ProviderUsageRequest{
				ProviderId: "provider-1",
				Refresh:    true,
			},
		},
	}

	if err := vetAgentRequest(session.AgentView{}, env); err != nil {
		t.Fatalf("vetAgentRequest() error = %v", err)
	}
}
