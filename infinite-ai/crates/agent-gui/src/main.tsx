import React from "react";
import ReactDOM from "react-dom/client";
import FriendGateBootstrap from "./FriendGateBootstrap";
import "./index.css";
import "katex/dist/katex.min.css";
import "streamdown/styles.css";
import { inferRuntimePlatform } from "./lib/runtimePlatform";
import { installWebviewNavigationGuard } from "./lib/system/webviewNavigationGuard";

type RootErrorBoundaryState = { error: Error | null };

class RootErrorBoundary extends React.Component<React.PropsWithChildren, RootErrorBoundaryState> {
  state: RootErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): RootErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error) {
    console.error("[Infinite AI boot]", error);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <main
        style={{
          alignItems: "center",
          background:
            "radial-gradient(ellipse 72% 58% at 12% 8%, rgba(191,219,254,.52), transparent 62%), radial-gradient(ellipse 58% 55% at 88% 88%, rgba(221,214,254,.42), transparent 60%), #ffffff",
          color: "#0f172a",
          display: "flex",
          fontFamily: "system-ui, sans-serif",
          height: "100vh",
          justifyContent: "center",
          padding: "32px",
        }}
      >
        <section
          style={{
            background: "rgba(255,255,255,.72)",
            border: "1px solid rgba(226,232,240,.78)",
            borderRadius: "24px",
            boxShadow: "0 30px 80px -40px rgba(15,23,42,.45)",
            maxWidth: "720px",
            padding: "32px",
            width: "100%",
            backdropFilter: "blur(30px) saturate(1.25)",
          }}
        >
          <h1 style={{ fontSize: "22px", margin: "0 0 12px" }}>Infinite AI 启动失败</h1>
          <p style={{ color: "#657487", lineHeight: 1.7 }}>
            前端已捕获到异常，详细信息如下。请保留此页便于排查。
          </p>
          <pre
            style={{
              background: "#f8fafc",
              border: "1px solid #e2e8f0",
              borderRadius: "10px",
              color: "#991b1b",
              overflow: "auto",
              padding: "16px",
              whiteSpace: "pre-wrap",
            }}
          >
            {this.state.error.stack || this.state.error.message}
          </pre>
          <button
            type="button"
            onClick={() => window.location.reload()}
            style={{
              background: "#0f172a",
              border: 0,
              borderRadius: "10px",
              color: "white",
              cursor: "pointer",
              fontWeight: 600,
              marginTop: "16px",
              padding: "12px 18px",
            }}
          >
            重新加载
          </button>
        </section>
      </main>
    );
  }
}

// F5/Ctrl+R 等 webview 内置浏览器行为会把整个应用当网页刷新/导航走——在 React
// 挂载前安装守卫。dev 下放行刷新组合键，保留本地整页重载的调试手段。
installWebviewNavigationGuard({
  isMac: inferRuntimePlatform() === "macos",
  allowReloadChords: import.meta.env.DEV,
});

if (import.meta.env.DEV) {
  // Dev console hook for transcript perf work: window.__seedLongConversation()
  void import("./lib/debug/seedLongConversation").then(({ seedLongConversation }) => {
    const devWindow = window as Window & { __seedLongConversation?: typeof seedLongConversation };
    devWindow.__seedLongConversation = seedLongConversation;
  });
}

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <RootErrorBoundary>
      <FriendGateBootstrap />
    </RootErrorBoundary>
  </React.StrictMode>,
);
