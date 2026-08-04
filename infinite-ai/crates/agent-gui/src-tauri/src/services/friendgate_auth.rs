use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::DateTime;
use reqwest::{Method, StatusCode};
use ring::{
    digest::{digest, SHA256},
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::{AppHandle, Emitter};
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::Request};
use uuid::Uuid;

const DEFAULT_FRIENDGATE_URL: &str = "http://127.0.0.1:18080";
pub(crate) const SESSION_REVOKED_EVENT: &str = "friendgate:session-revoked";
const LOCAL_SUB_KEY_TTL_SECONDS: i64 = 6 * 60 * 60;
const LOCAL_SUB_KEY_REFRESH_SKEW_SECONDS: i64 = 5 * 60;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceIdentityFile {
    pkcs8: String,
    public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DesktopSessionFile {
    access_token: String,
    refresh_token: String,
    access_expires_at: i64,
    refresh_expires_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LocalSubKeyFile {
    id: String,
    plain_key: String,
    expires_at: i64,
    project_id: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopAuthState {
    pub authenticated: bool,
    pub configured: bool,
    pub email: String,
    pub display_name: String,
    pub device_name: String,
    pub provisioned: bool,
    pub server_url: String,
    pub error: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all(serialize = "camelCase", deserialize = "snake_case"))]
pub struct DesktopAuthStart {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_at: i64,
    pub interval: i64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopAuthPoll {
    pub status: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all(serialize = "camelCase", deserialize = "snake_case"))]
pub struct FriendGatePolicy {
    pub registration_enabled: bool,
    pub public_api_enabled: bool,
    pub official_desktop_only: bool,
    pub gateway_base_url: String,
    pub provider_name: String,
    pub default_model: String,
    pub allowed_models: Vec<String>,
    pub system_prompt: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct SessionStatusResponse {
    authenticated: bool,
    email: String,
    display_name: String,
    device_name: String,
    provisioned: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    #[serde(deserialize_with = "deserialize_unix_timestamp")]
    access_expires_at: i64,
    #[serde(deserialize_with = "deserialize_unix_timestamp")]
    refresh_expires_at: i64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct AgentSubKeyInfo {
    id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct AgentSubKeyCreateResponse {
    key: AgentSubKeyInfo,
    plain_key: String,
    expires_at: i64,
}

#[derive(Clone, Debug, Deserialize)]
struct PollWireResponse {
    status: String,
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    refresh_token: String,
    #[serde(default, deserialize_with = "deserialize_unix_timestamp")]
    access_expires_at: i64,
    #[serde(default, deserialize_with = "deserialize_unix_timestamp")]
    refresh_expires_at: i64,
}

pub struct FriendGateAuthManager {
    base_url: String,
    client: reqwest::Client,
    identity: DeviceIdentityFile,
    session_path: PathBuf,
    sub_key_path: PathBuf,
    session: RwLock<Option<DesktopSessionFile>>,
    sub_key: RwLock<Option<LocalSubKeyFile>>,
    runtime_authorized: AtomicBool,
    refresh_lock: tokio::sync::Mutex<()>,
}

impl FriendGateAuthManager {
    pub fn open() -> Result<Arc<Self>, String> {
        let config_dir = crate::commands::settings::config_dir()?;
        fs::create_dir_all(&config_dir)
            .map_err(|error| format!("创建 Infinite AI 配置目录失败：{error}"))?;
        let identity_path = config_dir.join("friendgate-device.json");
        let session_path = config_dir.join("friendgate-session.json");
        let sub_key_path = config_dir.join("friendgate-local-sub-key.json");
        let identity = load_or_create_identity(&identity_path)?;
        let session = load_json_optional::<DesktopSessionFile>(&session_path)?;
        let sub_key = load_json_optional::<LocalSubKeyFile>(&sub_key_path)?;
        let base_url = std::env::var("INFINITE_AI_FRIENDGATE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .or_else(|| option_env!("INFINITE_AI_FRIENDGATE_URL").map(str::to_string))
            .unwrap_or_else(|| DEFAULT_FRIENDGATE_URL.to_string());
        let base_url = base_url.trim().trim_end_matches('/').to_string();
        let parsed = reqwest::Url::parse(&base_url)
            .map_err(|error| format!("FriendGate 地址无效：{error}"))?;
        if !matches!(parsed.scheme(), "http" | "https") || !parsed.has_host() {
            return Err("FriendGate 地址必须是有效的 HTTP(S) 地址".to_string());
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|error| format!("创建 FriendGate 客户端失败：{error}"))?;
        Ok(Arc::new(Self {
            base_url,
            client,
            identity,
            session_path,
            sub_key_path,
            session: RwLock::new(session),
            sub_key: RwLock::new(sub_key),
            runtime_authorized: AtomicBool::new(false),
            refresh_lock: tokio::sync::Mutex::new(()),
        }))
    }

    pub fn has_session(&self) -> bool {
        self.session
            .read()
            .map(|session| session.is_some())
            .unwrap_or(false)
    }

    pub fn runtime_authorized(&self) -> bool {
        if !self.runtime_authorized.load(Ordering::Acquire) {
            return false;
        }
        self.session
            .read()
            .ok()
            .and_then(|session| session.as_ref().map(|value| value.refresh_expires_at))
            .is_some_and(|expires_at| expires_at > unix_timestamp())
    }

    pub async fn start_auth(&self) -> Result<DesktopAuthStart, String> {
        let body = serde_json::json!({
            "public_key": self.identity.public_key,
            "device_name": device_name(),
            "platform": std::env::consts::OS,
            "mac": primary_mac_address(),
        });
        let response = self
            .client
            .post(format!("{}/api/desktop/auth/start", self.base_url))
            .json(&body)
            .send()
            .await
            .map_err(|error| format!("无法连接 FriendGate：{error}"))?;
        decode_response(response).await
    }

    pub async fn poll_auth(&self, device_code: &str) -> Result<DesktopAuthPoll, String> {
        let path = "/api/desktop/auth/poll";
        let body = serde_json::to_vec(&serde_json::json!({"device_code": device_code}))
            .map_err(|error| format!("创建桌面登录请求失败：{error}"))?;
        let request = self
            .signed_request(Method::POST, path, None, &body)?
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
        let response = request
            .send()
            .await
            .map_err(|error| format!("等待网页登录失败：{error}"))?;
        if response.status() == StatusCode::ACCEPTED {
            let payload: PollWireResponse = decode_response(response).await?;
            return Ok(DesktopAuthPoll {
                status: payload.status,
            });
        }
        let payload: PollWireResponse = decode_response(response).await?;
        if payload.status != "authorized"
            || payload.access_token.is_empty()
            || payload.refresh_token.is_empty()
        {
            return Err("FriendGate 返回了无效的桌面登录凭证".to_string());
        }
        self.clear_local_sub_key()?;
        self.save_session(DesktopSessionFile {
            access_token: payload.access_token,
            refresh_token: payload.refresh_token,
            access_expires_at: payload.access_expires_at,
            refresh_expires_at: payload.refresh_expires_at,
        })?;
        Ok(DesktopAuthPoll {
            status: "authorized".to_string(),
        })
    }

    pub async fn state(&self) -> DesktopAuthState {
        if !self.has_session() {
            self.runtime_authorized.store(false, Ordering::Release);
            let _ = self.clear_local_sub_key();
            return DesktopAuthState {
                authenticated: false,
                configured: true,
                email: String::new(),
                display_name: String::new(),
                device_name: device_name(),
                provisioned: false,
                server_url: self.base_url.clone(),
                error: String::new(),
            };
        }
        if let Err(error) = self.ensure_access_token().await {
            self.runtime_authorized.store(false, Ordering::Release);
            return DesktopAuthState {
                authenticated: false,
                configured: true,
                email: String::new(),
                display_name: String::new(),
                device_name: device_name(),
                provisioned: false,
                server_url: self.base_url.clone(),
                error,
            };
        }
        match self
            .signed_access_request(Method::GET, "/api/desktop/session")
            .await
        {
            Ok(response) if response.status().is_success() => {
                match response.json::<SessionStatusResponse>().await {
                    Ok(payload) => {
                        self.runtime_authorized.store(
                            payload.authenticated && payload.provisioned,
                            Ordering::Release,
                        );
                        DesktopAuthState {
                            authenticated: payload.authenticated,
                            configured: true,
                            email: payload.email,
                            display_name: payload.display_name,
                            device_name: payload.device_name,
                            provisioned: payload.provisioned,
                            server_url: self.base_url.clone(),
                            error: String::new(),
                        }
                    }
                    Err(error) => self.error_state(format!("读取登录状态失败：{error}")),
                }
            }
            Ok(response) if response.status() == StatusCode::UNAUTHORIZED => {
                let _ = self.clear_session();
                self.error_state("桌面登录已被撤销，请重新登录".to_string())
            }
            Ok(response) => self.error_state(response_error(response).await),
            Err(error) => self.error_state(error),
        }
    }

    pub async fn policy(&self) -> Result<FriendGatePolicy, String> {
        self.ensure_access_token().await?;
        let response = self
            .signed_access_request(Method::GET, "/api/desktop/policy")
            .await?;
        decode_response(response).await
    }

    pub async fn local_sub_key(&self) -> Result<String, String> {
        self.ensure_local_sub_key(false).await
    }

    pub async fn rotate_local_sub_key(&self) -> Result<String, String> {
        self.ensure_local_sub_key(true).await
    }

    pub async fn revoke_local_sub_key(&self) -> Result<(), String> {
        let current = self
            .sub_key
            .read()
            .map_err(|_| "读取本地子 Key 失败".to_string())?
            .clone();

        let mut revoke_error = None;
        if let Some(sub_key) = current.filter(|value| !value.id.trim().is_empty()) {
            if self.has_session() && self.ensure_access_token().await.is_ok() {
                match self.current_access_token() {
                    Ok(token) => {
                        let path = format!("/api/desktop/agent/sub-keys/{}", sub_key.id.trim());
                        let body = b"{}".to_vec();
                        let request = self
                            .signed_request(Method::DELETE, &path, Some(&token), &body)?
                            .header(reqwest::header::CONTENT_TYPE, "application/json")
                            .body(body);
                        match request.send().await {
                            Ok(response)
                                if response.status().is_success()
                                    || response.status() == StatusCode::NOT_FOUND
                                    || response.status() == StatusCode::UNAUTHORIZED => {}
                            Ok(response) => revoke_error = Some(response_error(response).await),
                            Err(error) => {
                                revoke_error =
                                    Some(format!("撤销 FriendGate 本地子 Key 失败：{error}"));
                            }
                        }
                    }
                    Err(error) => revoke_error = Some(error),
                }
            }
        }

        self.clear_local_sub_key()?;
        if let Some(error) = revoke_error {
            return Err(error);
        }
        Ok(())
    }

    pub async fn forward_gateway_request(
        &self,
        method: Method,
        path_and_query: &str,
        headers: reqwest::header::HeaderMap,
        body: Vec<u8>,
    ) -> Result<reqwest::Response, String> {
        self.ensure_access_token().await?;
        let token = self.current_access_token()?;
        let mut request = self
            .signed_request(method, path_and_query, Some(&token), &body)?
            .headers(headers);
        if !body.is_empty() {
            request = request.body(body);
        }
        let response = request
            .send()
            .await
            .map_err(|error| format!("连接 FriendGate 网关失败：{error}"))?;
        if response.status() == StatusCode::UNAUTHORIZED {
            let _ = self.clear_session();
        }
        Ok(response)
    }

    pub async fn gateway_websocket_request(
        &self,
        path_and_query: &str,
        subprotocols: Option<&str>,
    ) -> Result<Request<()>, String> {
        self.ensure_access_token().await?;
        let token = self.current_access_token()?;
        let timestamp = unix_timestamp().to_string();
        let nonce = Uuid::new_v4().to_string();
        let content_digest = content_sha256(&[]);
        let mac_hash = desktop_mac_hash()?;
        let canonical =
            format!("GET\n{path_and_query}\n{timestamp}\n{nonce}\n{content_digest}\n{mac_hash}");
        let signature =
            URL_SAFE_NO_PAD.encode(self.key_pair()?.sign(canonical.as_bytes()).as_ref());
        let mut url = reqwest::Url::parse(&format!("{}{}", self.base_url, path_and_query))
            .map_err(|error| format!("FriendGate WebSocket 地址无效：{error}"))?;
        let websocket_scheme = if url.scheme() == "https" { "wss" } else { "ws" };
        url.set_scheme(websocket_scheme)
            .map_err(|_| "FriendGate WebSocket 协议无效".to_string())?;
        let mut request = url
            .as_str()
            .into_client_request()
            .map_err(|error| format!("创建 FriendGate WebSocket 请求失败：{error}"))?;
        let headers = request.headers_mut();
        headers.insert(
            "authorization",
            format!("Bearer {token}")
                .parse()
                .map_err(|_| "桌面登录凭证无效".to_string())?,
        );
        headers.insert(
            "x-infinite-device-timestamp",
            timestamp
                .parse()
                .map_err(|_| "设备时间戳无效".to_string())?,
        );
        headers.insert(
            "x-infinite-device-nonce",
            nonce.parse().map_err(|_| "设备 nonce 无效".to_string())?,
        );
        headers.insert(
            "x-infinite-content-sha256",
            content_digest
                .parse()
                .map_err(|_| "请求正文摘要无效".to_string())?,
        );
        headers.insert(
            "x-infinite-device-mac-hash",
            mac_hash
                .parse()
                .map_err(|_| "设备网卡摘要无效".to_string())?,
        );
        headers.insert(
            "x-infinite-device-signature",
            signature.parse().map_err(|_| "设备签名无效".to_string())?,
        );
        if let Some(protocols) = subprotocols.filter(|value| !value.trim().is_empty()) {
            headers.insert(
                "sec-websocket-protocol",
                protocols
                    .parse()
                    .map_err(|_| "WebSocket 子协议无效".to_string())?,
            );
        }
        Ok(request)
    }

    pub async fn logout(&self) -> Result<(), String> {
        if self.has_session() {
            if self.ensure_access_token().await.is_ok() {
                if let Ok(response) = self
                    .signed_access_request(Method::POST, "/api/desktop/session/logout")
                    .await
                {
                    if !response.status().is_success()
                        && response.status() != StatusCode::UNAUTHORIZED
                    {
                        return Err(response_error(response).await);
                    }
                }
            }
        }
        self.clear_session()
    }

    pub fn start_revocation_watch(self: &Arc<Self>, app: AppHandle) {
        let manager = Arc::clone(self);
        tauri::async_runtime::spawn(async move {
            let mut last_verified = Instant::now();
            loop {
                if !manager.has_session() {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                if manager.ensure_access_token().await.is_err() {
                    if last_verified.elapsed() >= Duration::from_secs(30)
                        && manager.runtime_authorized.swap(false, Ordering::AcqRel)
                    {
                        let _ = app.emit(
                            SESSION_REVOKED_EVENT,
                            serde_json::json!({"reason":"verification_unavailable"}),
                        );
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                match manager
                    .signed_access_request(Method::GET, "/api/desktop/session/watch")
                    .await
                {
                    Ok(response) if response.status() == StatusCode::UNAUTHORIZED => {
                        let _ = manager.clear_session();
                        let _ = app.emit(
                            SESSION_REVOKED_EVENT,
                            serde_json::json!({"reason":"revoked"}),
                        );
                    }
                    Ok(response) if response.status().is_success() => {
                        last_verified = Instant::now();
                        manager.runtime_authorized.store(true, Ordering::Release);
                    }
                    Ok(_) | Err(_) => {
                        if last_verified.elapsed() >= Duration::from_secs(30)
                            && manager.runtime_authorized.swap(false, Ordering::AcqRel)
                        {
                            let _ = app.emit(
                                SESSION_REVOKED_EVENT,
                                serde_json::json!({"reason":"verification_unavailable"}),
                            );
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
    }

    async fn signed_access_request(
        &self,
        method: Method,
        path: &str,
    ) -> Result<reqwest::Response, String> {
        let token = self.current_access_token()?;
        self.signed_request(method, path, Some(&token), &[])?
            .send()
            .await
            .map_err(|error| format!("无法连接 FriendGate：{error}"))
    }

    fn signed_request(
        &self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        body: &[u8],
    ) -> Result<reqwest::RequestBuilder, String> {
        let timestamp = unix_timestamp().to_string();
        let nonce = Uuid::new_v4().to_string();
        let content_digest = content_sha256(body);
        let mac_hash = desktop_mac_hash()?;
        let canonical = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method.as_str(),
            path,
            timestamp,
            nonce,
            content_digest,
            mac_hash
        );
        let key_pair = self.key_pair()?;
        let signature = URL_SAFE_NO_PAD.encode(key_pair.sign(canonical.as_bytes()).as_ref());
        let mut request = self
            .client
            .request(method, format!("{}{}", self.base_url, path))
            .header("X-Infinite-Device-Timestamp", timestamp)
            .header("X-Infinite-Device-Nonce", nonce)
            .header("X-Infinite-Content-SHA256", content_digest)
            .header("X-Infinite-Device-MAC-Hash", mac_hash)
            .header("X-Infinite-Device-Signature", signature);
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        Ok(request)
    }

    async fn ensure_local_sub_key(&self, force: bool) -> Result<String, String> {
        self.ensure_access_token().await?;
        if !force {
            if let Some(existing) = self
                .sub_key
                .read()
                .map_err(|_| "读取本地子 Key 失败".to_string())?
                .clone()
                .filter(|value| {
                    value.plain_key.starts_with("fgsk_")
                        && value.expires_at > unix_timestamp() + LOCAL_SUB_KEY_REFRESH_SKEW_SECONDS
                })
            {
                return Ok(existing.plain_key);
            }
        } else {
            self.revoke_local_sub_key().await?;
        }

        let token = self.current_access_token()?;
        let body = serde_json::to_vec(&serde_json::json!({
            "ttl_seconds": LOCAL_SUB_KEY_TTL_SECONDS,
        }))
        .map_err(|error| format!("创建本地子 Key 请求失败：{error}"))?;
        let request = self
            .signed_request(
                Method::POST,
                "/api/desktop/agent/sub-keys",
                Some(&token),
                &body,
            )?
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
        let response = request
            .send()
            .await
            .map_err(|error| format!("签发 FriendGate 本地子 Key 失败：{error}"))?;
        let payload: AgentSubKeyCreateResponse = decode_response(response).await?;
        if payload.key.id.trim().is_empty()
            || !payload.plain_key.starts_with("fgsk_")
            || payload.expires_at <= unix_timestamp()
        {
            return Err("FriendGate 返回了无效的本地子 Key".to_string());
        }
        let sub_key = LocalSubKeyFile {
            id: payload.key.id,
            plain_key: payload.plain_key,
            expires_at: payload.expires_at,
            project_id: String::new(),
        };
        write_private_json(&self.sub_key_path, &sub_key)?;
        let plain_key = sub_key.plain_key.clone();
        *self
            .sub_key
            .write()
            .map_err(|_| "保存本地子 Key 失败".to_string())? = Some(sub_key);
        Ok(plain_key)
    }

    async fn ensure_access_token(&self) -> Result<(), String> {
        let _refresh_guard = self.refresh_lock.lock().await;
        let session = self
            .session
            .read()
            .map_err(|_| "读取 FriendGate 会话失败".to_string())?
            .clone()
            .ok_or_else(|| "请先登录 Infinite AI".to_string())?;
        let now = unix_timestamp();
        if session.refresh_expires_at <= now {
            self.clear_session()?;
            return Err("桌面登录已过期，请重新登录".to_string());
        }
        if session.access_expires_at > now + 30 {
            return Ok(());
        }
        let path = "/api/desktop/auth/refresh";
        let response = self
            .signed_request(Method::POST, path, Some(&session.refresh_token), &[])?
            .send()
            .await
            .map_err(|error| format!("刷新 FriendGate 登录失败：{error}"))?;
        if response.status() == StatusCode::UNAUTHORIZED {
            self.clear_session()?;
            return Err("桌面登录已失效，请重新登录".to_string());
        }
        let payload: TokenResponse = decode_response(response).await?;
        self.save_session(DesktopSessionFile {
            access_token: payload.access_token,
            refresh_token: payload.refresh_token,
            access_expires_at: payload.access_expires_at,
            refresh_expires_at: payload.refresh_expires_at,
        })
    }

    fn current_access_token(&self) -> Result<String, String> {
        self.session
            .read()
            .map_err(|_| "读取 FriendGate 会话失败".to_string())?
            .as_ref()
            .map(|session| session.access_token.clone())
            .ok_or_else(|| "请先登录 Infinite AI".to_string())
    }

    fn key_pair(&self) -> Result<Ed25519KeyPair, String> {
        let pkcs8 = URL_SAFE_NO_PAD
            .decode(&self.identity.pkcs8)
            .map_err(|_| "本机设备私钥损坏".to_string())?;
        Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_| "本机设备私钥损坏".to_string())
    }

    fn save_session(&self, session: DesktopSessionFile) -> Result<(), String> {
        write_private_json(&self.session_path, &session)?;
        *self
            .session
            .write()
            .map_err(|_| "保存 FriendGate 会话失败".to_string())? = Some(session);
        Ok(())
    }

    fn clear_session(&self) -> Result<(), String> {
        self.runtime_authorized.store(false, Ordering::Release);
        *self
            .session
            .write()
            .map_err(|_| "清除 FriendGate 会话失败".to_string())? = None;
        let session_result = match fs::remove_file(&self.session_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("删除本机会话失败：{error}")),
        };
        session_result.and(self.clear_local_sub_key())
    }

    fn clear_local_sub_key(&self) -> Result<(), String> {
        *self
            .sub_key
            .write()
            .map_err(|_| "清除本地子 Key 失败".to_string())? = None;
        match fs::remove_file(&self.sub_key_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("删除本地子 Key 失败：{error}")),
        }
    }

    fn error_state(&self, error: String) -> DesktopAuthState {
        self.runtime_authorized.store(false, Ordering::Release);
        DesktopAuthState {
            authenticated: false,
            configured: true,
            email: String::new(),
            display_name: String::new(),
            device_name: device_name(),
            provisioned: false,
            server_url: self.base_url.clone(),
            error,
        }
    }
}

fn content_sha256(body: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(digest(&SHA256, body).as_ref())
}

fn desktop_mac_hash() -> Result<String, String> {
    let mac = primary_mac_address();
    if mac.is_empty() {
        return Err("未读取到有效网卡 MAC 地址，无法完成设备安全校验".to_string());
    }
    Ok(URL_SAFE_NO_PAD.encode(digest(&SHA256, mac.as_bytes()).as_ref()))
}

fn load_or_create_identity(path: &Path) -> Result<DeviceIdentityFile, String> {
    if let Some(identity) = load_json_optional::<DeviceIdentityFile>(path)? {
        let pkcs8 = URL_SAFE_NO_PAD
            .decode(&identity.pkcs8)
            .map_err(|_| "本机设备身份文件损坏".to_string())?;
        let pair =
            Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_| "本机设备身份文件损坏".to_string())?;
        if URL_SAFE_NO_PAD.encode(pair.public_key().as_ref()) != identity.public_key {
            return Err("本机设备身份公私钥不匹配".to_string());
        }
        return Ok(identity);
    }
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| "生成本机设备私钥失败".to_string())?;
    let pair =
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| "读取新设备私钥失败".to_string())?;
    let identity = DeviceIdentityFile {
        pkcs8: URL_SAFE_NO_PAD.encode(pkcs8.as_ref()),
        public_key: URL_SAFE_NO_PAD.encode(pair.public_key().as_ref()),
    };
    write_private_json(path, &identity)?;
    Ok(identity)
}

fn load_json_optional<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>, String> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| format!("读取 {} 失败：{error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("读取 {} 失败：{error}", path.display())),
    }
}

fn write_private_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| format!("序列化本机凭证失败：{error}"))?;
    let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("创建本机凭证失败：{error}"))?;
    if let Err(error) = file.write_all(&bytes).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("写入本机凭证失败：{error}"));
    }
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("设置本机凭证权限失败：{error}"))?;
    }
    fs::rename(&temporary, path).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        format!("保存本机凭证失败：{error}")
    })
}

fn primary_mac_address() -> String {
    let raw = mac_address::get_mac_address()
        .ok()
        .flatten()
        .map(|address| address.to_string())
        .unwrap_or_default();
    let compact: String = raw
        .chars()
        .filter(|value| value.is_ascii_hexdigit())
        .map(|value| value.to_ascii_lowercase())
        .collect();
    if compact.len() != 12 {
        return String::new();
    }
    format!(
        "{}:{}:{}:{}:{}:{}",
        &compact[0..2],
        &compact[2..4],
        &compact[4..6],
        &compact[6..8],
        &compact[8..10],
        &compact[10..12]
    )
}

fn device_name() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("Infinite AI {} 设备", std::env::consts::OS))
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn deserialize_unix_timestamp<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    if let Some(timestamp) = value.as_i64() {
        return Ok(timestamp);
    }
    if let Some(raw) = value
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if let Ok(timestamp) = raw.parse::<i64>() {
            return Ok(timestamp);
        }
        return DateTime::parse_from_rfc3339(raw)
            .map(|value| value.timestamp())
            .map_err(serde::de::Error::custom);
    }
    Err(serde::de::Error::custom(
        "expected unix timestamp or RFC3339 string",
    ))
}

async fn decode_response<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
) -> Result<T, String> {
    if !response.status().is_success() {
        return Err(response_error(response).await);
    }
    response
        .json::<T>()
        .await
        .map_err(|error| format!("FriendGate 响应格式无效：{error}"))
}

async fn response_error(response: reqwest::Response) -> String {
    let status = response.status();
    match response.json::<Value>().await {
        Ok(payload) => payload
            .pointer("/error/message")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| format!("FriendGate 请求失败（{status}）")),
        Err(_) => format!("FriendGate 请求失败（{status}）"),
    }
}
