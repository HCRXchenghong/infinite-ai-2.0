package shared

import (
	"testing"

	gatewayv2 "github.com/liveagent/agent-gateway/internal/proto/v2"
	"github.com/liveagent/agent-gateway/internal/session"
)

// SSH 本地端口转发动作必须走 SSH 终端门：漏加白名单会落入 default 分支、
// 被本地终端开关（enableWebTerminal）错误放行/拦截。
func TestTerminalRequestAllowedGatesSshLocalForwardOnSshToggle(t *testing.T) {
	actions := []string{
		"ssh_local_forward_start",
		"ssh_local_forward_list",
		"ssh_local_forward_stop",
		"ssh_local_forward_check_port",
	}

	manager := session.NewManager()
	manager.ApplySettingsJSON("test-agent", `{"remote":{"enableWebTerminal":true,"enableWebSshTerminal":false}}`)
	view := manager.AgentView("test-agent")
	for _, action := range actions {
		if TerminalRequestAllowed(view, action, "") {
			t.Fatalf("action %q must not be allowed by the local terminal toggle", action)
		}
		if TerminalPermissionError(action) != "web SSH terminal is disabled in desktop Remote settings" {
			t.Fatalf("action %q must report the SSH permission error", action)
		}
	}

	manager.ApplySettingsJSON("test-agent", `{"remote":{"enableWebTerminal":false,"enableWebSshTerminal":true}}`)
	for _, action := range actions {
		if !TerminalRequestAllowed(view, action, "") {
			t.Fatalf("action %q must be allowed once web SSH terminal is enabled", action)
		}
	}
}

// 转发事件不携带 session 载荷，门控必须直接按 kind 判 SSH 开关，
// 不得回落到 session 缓存推断出的本地终端门。
func TestTerminalEventAllowedGatesSshLocalForwardKind(t *testing.T) {
	event := &gatewayv2.TerminalEvent{
		Kind:           "ssh_local_forward",
		SessionId:      "ssh-1",
		ProjectPathKey: "/project",
	}

	manager := session.NewManager()
	manager.ApplySettingsJSON("test-agent", `{"remote":{"enableWebTerminal":true,"enableWebSshTerminal":false}}`)
	view := manager.AgentView("test-agent")
	if TerminalEventAllowed(view, event) {
		t.Fatal("ssh_local_forward events must not pass with only the local terminal enabled")
	}

	manager.ApplySettingsJSON("test-agent", `{"remote":{"enableWebTerminal":false,"enableWebSshTerminal":true}}`)
	if !TerminalEventAllowed(view, event) {
		t.Fatal("ssh_local_forward events must pass once web SSH terminal is enabled")
	}
}
