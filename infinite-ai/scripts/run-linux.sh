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

# Prefer the freshly built source tree.  The old launcher searched the
# compatibility archive first, which made a local checkout silently start an
# outdated binary after every rebuild.
binary="${INFINITE_AI_BINARY:-}"
if [[ -z "$binary" ]]; then
  binary="$repo_root/target/release/infinite-ai"
fi
if [[ ! -x "$binary" ]]; then
  binary="$repo_root/crates/agent-gui/src-tauri/target/release/infinite-ai"
fi
if [[ -x "$binary" ]]; then
  # A source binary built on a newer distribution can be present while its
  # WebKitGTK runtime is absent on the host.  In that case prefer the
  # self-contained AppImage below instead of opening a blank window or
  # emitting a loader error.
  if ! ldd "$binary" 2>/dev/null | grep -q 'not found'; then
    exec "$binary" "$@"
  fi
fi

appimage="${INFINITE_AI_APPIMAGE:-}"
if [[ -z "$appimage" ]]; then
  appimage="$(find "$repo_root/../releases/linux" -maxdepth 1 -type f -name 'Infinite-AI-*.AppImage' -print -quit 2>/dev/null || true)"
fi
if [[ -n "$appimage" && -x "$appimage" ]]; then
  exec "$appimage" "$@"
fi

cat >&2 <<'EOF'
Infinite AI Linux binary not found.
Build it with:
  cd infinite-ai/crates/agent-gui
  pnpm install --frozen-lockfile
  pnpm tauri build --config src-tauri/tauri.linux.release.conf.json
EOF
exit 127
