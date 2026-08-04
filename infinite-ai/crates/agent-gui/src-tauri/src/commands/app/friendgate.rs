use std::sync::Arc;
use tauri_plugin_opener::OpenerExt;

use crate::services::friendgate_auth::{
    DesktopAuthPoll, DesktopAuthStart, DesktopAuthState, FriendGateAuthManager, FriendGatePolicy,
};

#[tauri::command]
pub async fn friendgate_auth_state(
    state: tauri::State<'_, Arc<FriendGateAuthManager>>,
) -> Result<DesktopAuthState, String> {
    Ok(state.state().await)
}

#[tauri::command]
pub async fn friendgate_auth_start(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<FriendGateAuthManager>>,
) -> Result<DesktopAuthStart, String> {
    let flow = state.start_auth().await?;
    app.opener()
        .open_url(&flow.verification_uri_complete, None::<&str>)
        .map_err(|error| format!("打开网页登录失败：{error}"))?;
    Ok(flow)
}

#[tauri::command]
pub async fn friendgate_auth_poll(
    state: tauri::State<'_, Arc<FriendGateAuthManager>>,
    device_code: String,
) -> Result<DesktopAuthPoll, String> {
    state.poll_auth(device_code.trim()).await
}

#[tauri::command]
pub async fn friendgate_auth_logout(
    state: tauri::State<'_, Arc<FriendGateAuthManager>>,
) -> Result<(), String> {
    state.logout().await
}

#[tauri::command]
pub async fn friendgate_policy(
    state: tauri::State<'_, Arc<FriendGateAuthManager>>,
) -> Result<FriendGatePolicy, String> {
    state.policy().await
}
