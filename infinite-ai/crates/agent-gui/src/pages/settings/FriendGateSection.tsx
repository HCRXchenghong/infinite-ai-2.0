import { invoke } from "@tauri-apps/api/core";
import { useCallback, useEffect, useState } from "react";
import { Check, Copy, Loader2, LogOut, RefreshCw, Shield } from "../../components/icons";

type AuthState = {
  authenticated: boolean;
  email: string;
  displayName: string;
  deviceName: string;
  serverUrl: string;
};

type Policy = {
  providerName: string;
  defaultModel: string;
  allowedModels: string[];
  publicApiEnabled: boolean;
  officialDesktopOnly: boolean;
};

type ProxyInfo = {
  baseUrl: string;
  token: string;
  enabled: boolean;
};

function errorText(error: unknown) {
  return error instanceof Error ? error.message : String(error || "操作失败");
}

export function FriendGateSection() {
  const [auth, setAuth] = useState<AuthState | null>(null);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [proxy, setProxy] = useState<ProxyInfo | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState<"url" | "key" | "" | null>(null);
  const [error, setError] = useState("");

  const reload = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      const [nextAuth, nextPolicy, nextProxy] = await Promise.all([
        invoke<AuthState>("friendgate_auth_state"),
        invoke<Policy>("friendgate_policy"),
        invoke<ProxyInfo>("proxy_get_server_info"),
      ]);
      setAuth(nextAuth);
      setPolicy(nextPolicy);
      setProxy(nextProxy);
    } catch (nextError) {
      setError(errorText(nextError));
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  const copy = useCallback(async (kind: "url" | "key", value: string) => {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      setCopied(kind);
      window.setTimeout(() => setCopied(null), 1500);
    } catch (nextError) {
      setError(errorText(nextError));
    }
  }, []);

  const rotate = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      setProxy(await invoke<ProxyInfo>("proxy_rotate_sub_key"));
    } catch (nextError) {
      setError(errorText(nextError));
    } finally {
      setBusy(false);
    }
  }, []);

  const revoke = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      setProxy(await invoke<ProxyInfo>("proxy_revoke_sub_key"));
    } catch (nextError) {
      setError(errorText(nextError));
    } finally {
      setBusy(false);
    }
  }, []);

  const logout = useCallback(async () => {
    setBusy(true);
    try {
      await invoke("friendgate_auth_logout");
      window.location.reload();
    } catch (nextError) {
      setError(errorText(nextError));
      setBusy(false);
    }
  }, []);

  const localUrl = proxy?.baseUrl ? `${proxy.baseUrl.replace(/\/$/, "")}/friendgate/v1` : "";

  return (
    <div className="mx-auto w-full max-w-4xl space-y-5 p-1">
      <section className="rounded-xl border border-border bg-card p-5 shadow-sm">
        <div className="flex items-start justify-between gap-5">
          <div>
            <div className="flex items-center gap-2 text-sm font-semibold"><Shield className="h-4 w-4 text-primary" />Infinite AI 账号</div>
            <p className="mt-2 text-xs leading-6 text-muted-foreground">账号、固定额度 Key、模型与系统提示词由 FriendGate 后台统一管理。</p>
          </div>
          <button type="button" onClick={() => void reload()} disabled={busy} className="rounded-lg border border-border px-3 py-2 text-xs font-medium hover:bg-accent disabled:opacity-50"><RefreshCw className={`mr-1.5 inline h-3.5 w-3.5 ${busy ? "animate-spin" : ""}`} />刷新</button>
        </div>
        {auth && (
          <div className="mt-5 grid gap-3 rounded-lg bg-muted/35 p-4 text-sm sm:grid-cols-2">
            <div><span className="text-xs text-muted-foreground">当前用户</span><strong className="mt-1 block">{auth.displayName || auth.email}</strong><span className="text-xs text-muted-foreground">{auth.email}</span></div>
            <div><span className="text-xs text-muted-foreground">已绑定设备</span><strong className="mt-1 block">{auth.deviceName}</strong><span className="text-xs text-muted-foreground">{auth.serverUrl}</span></div>
          </div>
        )}
        {policy && (
          <div className="mt-4 grid gap-3 text-xs sm:grid-cols-3">
            <div className="rounded-lg border border-border/70 p-3"><span className="text-muted-foreground">托管供应商</span><strong className="mt-1 block">{policy.providerName}</strong></div>
            <div className="rounded-lg border border-border/70 p-3"><span className="text-muted-foreground">默认模型</span><strong className="mt-1 block">{policy.defaultModel}</strong></div>
            <div className="rounded-lg border border-border/70 p-3"><span className="text-muted-foreground">外部 API</span><strong className="mt-1 block">{policy.publicApiEnabled && !policy.officialDesktopOnly ? "已开放" : "仅官方软件"}</strong></div>
          </div>
        )}
      </section>

      <section className="rounded-xl border border-border bg-card p-5 shadow-sm">
        <div>
          <h3 className="text-sm font-semibold">本机子 Key</h3>
          <p className="mt-2 text-xs leading-6 text-muted-foreground">仅当 Infinite AI 正在运行时有效。其他本地工具可使用此 URL 与 Key，共用当前账号在后台绑定的额度和 ChatGPT 账号。</p>
        </div>
        <div className="mt-5 space-y-3">
          <div><span className="text-xs text-muted-foreground">本地 Responses API URL</span><div className="mt-1.5 flex gap-2"><code className="min-w-0 flex-1 overflow-x-auto rounded-lg bg-muted px-3 py-2.5 text-xs">{localUrl || "正在读取"}</code><button type="button" disabled={!localUrl} onClick={() => void copy("url", localUrl)} className="rounded-lg border border-border px-3 hover:bg-accent disabled:opacity-40">{copied === "url" ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}</button></div></div>
          <div><span className="text-xs text-muted-foreground">本地 API Key</span><div className="mt-1.5 flex gap-2"><code className="min-w-0 flex-1 overflow-x-auto rounded-lg bg-muted px-3 py-2.5 text-xs">{proxy?.enabled ? proxy.token : "已撤销"}</code><button type="button" disabled={!proxy?.enabled || !proxy.token} onClick={() => void copy("key", proxy?.token || "")} className="rounded-lg border border-border px-3 hover:bg-accent disabled:opacity-40">{copied === "key" ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}</button></div></div>
        </div>
        <div className="mt-5 flex flex-wrap gap-2">
          <button type="button" disabled={busy} onClick={() => void rotate()} className="rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground disabled:opacity-50">{busy ? <Loader2 className="mr-1.5 inline h-3.5 w-3.5 animate-spin" /> : null}{proxy?.enabled ? "重新生成子 Key" : "生成子 Key"}</button>
          <button type="button" disabled={busy || !proxy?.enabled} onClick={() => void revoke()} className="rounded-lg border border-destructive/35 px-4 py-2 text-xs font-semibold text-destructive hover:bg-destructive/5 disabled:opacity-40">立即撤销</button>
        </div>
      </section>

      {error && <div className="rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3 text-xs text-destructive">{error}</div>}

      <section className="flex items-center justify-between gap-5 rounded-xl border border-border bg-card p-5 shadow-sm">
        <div><h3 className="text-sm font-semibold">退出当前软件</h3><p className="mt-1 text-xs text-muted-foreground">删除本机短期会话并返回网页登录页。</p></div>
        <button type="button" disabled={busy} onClick={() => void logout()} className="rounded-lg border border-destructive/35 px-4 py-2 text-xs font-semibold text-destructive hover:bg-destructive/5 disabled:opacity-40"><LogOut className="mr-1.5 inline h-3.5 w-3.5" />退出登录</button>
      </section>
    </div>
  );
}
