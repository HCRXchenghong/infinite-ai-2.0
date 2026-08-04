#!/usr/bin/env bash
set -euo pipefail

# Portable Linux launcher.  WebKitGTK may not ship the host's IBus GTK
# module, so route composition through XIM and keep native Qt dialogs on the
# same IBus session.  Existing user-provided values are respected.
export GTK_IM_MODULE="${GTK_IM_MODULE:-xim}"
export QT_IM_MODULE="${QT_IM_MODULE:-ibus}"
export XMODIFIERS="${XMODIFIERS:-@im=ibus}"
export LC_CTYPE="${LC_CTYPE:-${LANG:-C.UTF-8}}"

# Keep the desktop client and its local FriendGate gateway in lockstep.  This
# is also used when the source-tree launcher is started directly instead of
# through the installed desktop entry.
if command -v systemctl >/dev/null 2>&1; then
  systemctl --user start friendgate-infinite-ai.service >/dev/null 2>&1 || true
  if command -v curl >/dev/null 2>&1; then
    friendgate_root="${INFINITE_AI_FRIENDGATE_URL:-http://127.0.0.1:18080}"
    friendgate_root="${friendgate_root%/}"
    friendgate_root="${friendgate_root%/v1}"
    friendgate_ready=false
    for _ in {1..30}; do
      if curl --silent --fail --max-time 1 --output /dev/null "${friendgate_root}/health" 2>/dev/null; then
        friendgate_ready=true
        break
      fi
      sleep 0.2
    done
    if [[ "${friendgate_ready}" != true ]]; then
      echo "FriendGate local service is unavailable (${friendgate_root}/health)." >&2
      exit 1
    fi
  fi
fi

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
  # Never pick an older compatibility build just because it happens to be
  # first in find(1)'s directory order.  In particular, 1.3.x predates the
  # FriendGate bootstrap and will render the raw localhost error page.
  preferred="$repo_root/../releases/linux/Infinite-AI-2.0.0-x86_64.AppImage"
  if [[ -x "$preferred" ]]; then
    appimage="$preferred"
  else
    appimage="$(find "$repo_root/../releases/linux" -maxdepth 1 -type f -name 'Infinite-AI-*.AppImage' -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n 1 | cut -d' ' -f2- || true)"
  fi
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
