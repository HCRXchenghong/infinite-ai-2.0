import { invoke } from "@tauri-apps/api/core";
import { useCallback, useEffect, useRef, useState } from "react";
import { ExternalLink, Loader2, RefreshCw } from "./icons";

export type FriendGateAuthState = {
  authenticated: boolean;
  configured: boolean;
  email: string;
  displayName: string;
  deviceName: string;
  provisioned: boolean;
  serverUrl: string;
  error: string;
};

type AuthStart = {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  verificationUriComplete: string;
  expiresAt: number;
  interval: number;
};

function errorMessage(error: unknown, fallback: string) {
  if (error instanceof Error && error.message.trim()) return error.message.trim();
  const text = String(error ?? "").trim();
  return text || fallback;
}

export function FriendGateLoginGate(props: {
  initialState: FriendGateAuthState;
  onAuthenticated: (state: FriendGateAuthState) => void;
}) {
  const [auth, setAuth] = useState(props.initialState);
  const [flow, setFlow] = useState<AuthStart | null>(null);
  const [starting, setStarting] = useState(false);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState(props.initialState.error);
  const pollBusy = useRef(false);

  const refreshState = useCallback(async () => {
    setChecking(true);
    try {
      const next = await invoke<FriendGateAuthState>("friendgate_auth_state");
      setAuth(next);
      setError(next.error);
      if (next.authenticated && next.provisioned) props.onAuthenticated(next);
    } catch (nextError) {
      setError(errorMessage(nextError, "无法读取 Infinite AI 登录状态。"));
    } finally {
      setChecking(false);
    }
  }, [props]);

  const startLogin = useCallback(async () => {
    setStarting(true);
    setError("");
    try {
      const next = await invoke<AuthStart>("friendgate_auth_start");
      setFlow(next);
    } catch (nextError) {
      setError(errorMessage(nextError, "无法发起网页登录。"));
    } finally {
      setStarting(false);
    }
  }, []);

  useEffect(() => {
    if (!flow) return;
    let cancelled = false;
    const interval = window.setInterval(
      async () => {
        if (cancelled || pollBusy.current) return;
        if (Date.now() / 1000 >= flow.expiresAt) {
          setFlow(null);
          setError("网页登录请求已过期，请重新发起。");
          return;
        }
        pollBusy.current = true;
        try {
          const result = await invoke<{ status: string }>("friendgate_auth_poll", {
            deviceCode: flow.deviceCode,
          });
          if (!cancelled && result.status === "authorized") {
            setFlow(null);
            await refreshState();
          }
        } catch (nextError) {
          if (!cancelled) {
            const message = errorMessage(nextError, "等待网页登录失败。");
            if (!message.includes("等待") && !message.includes("pending")) setError(message);
          }
        } finally {
          pollBusy.current = false;
        }
      },
      Math.max(1000, (flow.interval || 2) * 1000),
    );
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [flow, refreshState]);

  const logout = useCallback(async () => {
    try {
      await invoke("friendgate_auth_logout");
      setFlow(null);
      setAuth((current) => ({ ...current, authenticated: false, provisioned: false }));
    } catch (nextError) {
      setError(errorMessage(nextError, "退出失败。"));
    }
  }, []);

  const title = auth.authenticated ? `你好，${auth.displayName || auth.email}` : "欢迎回来";

  return (
    <div className="flex h-full min-h-0 items-center justify-center overflow-auto bg-[#fafafa] p-4 text-[#111111] dark:bg-[#111111] dark:text-white sm:p-6">
      <main className="relative w-full max-w-md rounded-2xl border border-[#e5e5e5] bg-white px-8 py-10 shadow-2xl dark:border-[#333] dark:bg-[#171717]">
        <div className="mb-6 flex justify-center">
          <img
            src="/brand-logo.png"
            alt="Infinite AI"
            className="h-24 w-24 object-contain dark:invert"
          />
        </div>
        <h1 className="mb-2 text-center text-2xl font-bold">{title}</h1>
        <p className="mb-6 text-center text-sm text-[#666666] dark:text-gray-400">
          {auth.authenticated && !auth.provisioned ? "管理员尚未为当前账号分配可用密钥。" : flow ? "请在浏览器中确认这台设备。" : "使用浏览器完成登录或注册。"}
        </p>
        {flow && (
          <section className="mb-5 rounded-2xl border border-[#e5e5e5] bg-[#fafafa] px-5 py-5 text-center dark:border-[#333] dark:bg-[#111111]">
            <div className="text-xs text-[#666666] dark:text-gray-400">设备授权码</div>
            <div className="mt-2 font-mono text-2xl font-semibold tracking-[.15em]">{flow.userCode}</div>
            <button type="button" onClick={() => void startLogin()} className="mt-4 inline-flex items-center gap-1.5 rounded-md border border-[#e5e5e5] px-4 py-2 text-sm font-medium hover:bg-[#f5f5f5] dark:border-[#333] dark:hover:bg-[#222]">重新打开浏览器 <ExternalLink className="h-4 w-4" /></button>
          </section>
        )}
        {error && <div className="mb-5 rounded-xl border border-red-500/20 bg-red-500/[0.07] px-4 py-3 text-sm leading-6 text-red-500">{error}</div>}
        <div className="grid gap-3">
          {!auth.authenticated && !flow && <button type="button" disabled={starting} onClick={() => void startLogin()} className="flex w-full items-center justify-center gap-2 rounded-md bg-[#111111] px-4 py-3 text-sm font-medium text-white hover:bg-black disabled:cursor-not-allowed disabled:opacity-60 dark:bg-white dark:text-black dark:hover:bg-[#ececec]">{starting && <Loader2 className="h-4 w-4 animate-spin" />}打开浏览器登录或注册</button>}
          {auth.authenticated && !auth.provisioned && <><button type="button" disabled={checking} onClick={() => void refreshState()} className="flex w-full items-center justify-center gap-2 rounded-md bg-[#111111] px-4 py-3 text-sm font-medium text-white hover:bg-black disabled:cursor-not-allowed disabled:opacity-60 dark:bg-white dark:text-black dark:hover:bg-[#ececec]"><RefreshCw className={`h-4 w-4 ${checking ? "animate-spin" : ""}`} />重新检查授权</button><button type="button" onClick={() => void logout()} className="rounded-md border border-[#e5e5e5] px-4 py-3 text-sm font-medium text-[#666666] hover:bg-[#f5f5f5] dark:border-[#333] dark:text-gray-400 dark:hover:bg-[#222]">退出账号</button></>}
        </div>
        <p className="mt-6 text-center text-xs text-[#666666]/70 dark:text-gray-500">{auth.deviceName || "正在识别设备"}</p>
      </main>
    </div>
  );
}
