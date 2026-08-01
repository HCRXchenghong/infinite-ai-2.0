#!/usr/bin/env bash
set -euo pipefail

# Portable Linux launcher.  WebKitGTK may not ship the host's IBus GTK
# module, so route composition through XIM and keep native Qt dialogs on the
# same IBus session.  Existing user-provided values are respected.
export GTK_IM_MODULE="${GTK_IM_MODULE:-xim}"
export QT_IM_MODULE="${QT_IM_MODULE:-ibus}"
export XMODIFIERS="${XMODIFIERS:-@im=ibus}"
export LC_CTYPE="${LC_CTYPE:-${LANG:-C.UTF-8}}"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
appimage="${INFINITE_AI_APPIMAGE:-}"
if [[ -z "$appimage" ]]; then
  appimage="$(find "$repo_root/../releases/linux" -maxdepth 1 -type f -name 'Infinite-AI-*.AppImage' -print -quit 2>/dev/null || true)"
fi
# The repository also keeps the historical v1.2.3 AppImage as a compatibility
# archive.  It is intentionally a last-resort fallback and is not presented
# as a newly branded Infinite AI build.
if [[ -z "$appimage" ]]; then
  appimage="$(find "$repo_root/../releases/linux" -maxdepth 1 -type f -name 'LiveAgent-v1.2.3-*.AppImage' -print -quit 2>/dev/null || true)"
fi

if [[ -n "$appimage" && -x "$appimage" ]]; then
  exec "$appimage" "$@"
fi

binary="$repo_root/crates/agent-gui/src-tauri/target/release/infinite-ai"
if [[ -x "$binary" ]]; then
  exec "$binary" "$@"
fi

cat >&2 <<'EOF'
Infinite AI Linux binary not found.
Build it with:
  cd infinite-ai/crates/agent-gui
  pnpm install --frozen-lockfile
  pnpm tauri build --config src-tauri/tauri.linux.release.conf.json
EOF
exit 127
