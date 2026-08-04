import { invoke } from "@tauri-apps/api/core";

export async function openExternalUrl(url: string): Promise<void> {
  await invoke("app_open_url", { url });
}

export async function revealItemInDirectory(path: string): Promise<void> {
  await invoke("app_reveal_item_in_dir", { path });
}
