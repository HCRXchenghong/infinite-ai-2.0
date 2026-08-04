import { invoke } from "@tauri-apps/api/core";
import { lazy, Suspense, useEffect, useState } from "react";
import {
  FriendGateLoginGate,
  type FriendGateAuthState,
} from "./components/FriendGateLoginGate";

const AuthenticatedApp = lazy(() => import("./App"));

function asErrorMessage(error: unknown) {
  if (error instanceof Error && error.message.trim()) return error.message.trim();
  const message = String(error ?? "").trim();
  return message || "Infinite AI 登录模块初始化失败。";
}

function LoadingScreen(props: { message: string }) {
  return (
    <main
      className="flex h-full w-full items-center justify-center bg-[#fafafa] text-sm text-[#666666] dark:bg-[#111111] dark:text-gray-400"
    >
      <span className="rounded-2xl border border-[#e5e5e5] bg-white px-4 py-3 shadow-2xl dark:border-[#333] dark:bg-[#171717]">
        {props.message}
      </span>
    </main>
  );
}

export default function FriendGateBootstrap() {
  const [auth, setAuth] = useState<FriendGateAuthState | null>(null);

  useEffect(() => {
    let cancelled = false;
    void invoke<FriendGateAuthState>("friendgate_auth_state")
      .then((state) => {
        if (!cancelled) setAuth(state);
      })
      .catch((error) => {
        if (cancelled) return;
        setAuth({
          authenticated: false,
          configured: false,
          email: "",
          displayName: "",
          deviceName: "",
          provisioned: false,
          serverUrl: "",
          error: asErrorMessage(error),
        });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    document.title = auth?.authenticated && auth.provisioned ? "Infinite AI" : "Infinite AI · 登录";
  }, [auth?.authenticated, auth?.provisioned]);

  if (!auth) return <LoadingScreen message="正在安全启动 Infinite AI…" />;

  if (!auth.authenticated || !auth.provisioned) {
    return <FriendGateLoginGate initialState={auth} onAuthenticated={setAuth} />;
  }

  return (
    <Suspense fallback={<LoadingScreen message="正在加载 Infinite AI 开发工作台…" />}>
      <AuthenticatedApp />
    </Suspense>
  );
}
