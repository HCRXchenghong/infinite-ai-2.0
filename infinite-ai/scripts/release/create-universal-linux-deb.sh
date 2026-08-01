#!/usr/bin/env bash
set -euo pipefail

# Build a dependency-light Debian package from the already verified AppImage.
#
# Tauri 2 currently links WebKitGTK 4.1, which is not present in Ubuntu 20.04.
# The normal Tauri .deb therefore cannot be installed with `dpkg -i` on Focal.
# This package keeps the WebKitGTK runtime in the AppDir, includes the loader
# used by the build host, and patches the two ELF entry points to use that
# private loader.  The package deliberately has no Debian `Depends` entry:
# `dpkg -i` succeeds on both Ubuntu 20.04 and 22.04, while X11/GTK/DRM driver
# libraries remain resolved from the host so graphics drivers are not copied
# into the application.

usage() {
  echo "Usage: $0 <source.AppImage> <output.deb> [version]" >&2
  exit 2
}

[[ $# -ge 2 && $# -le 3 ]] || usage
source_appimage="$(realpath "$1")"
output_deb="$(realpath -m "$2")"
version="${3:-1.3.0-dev.0}"

for command_name in dpkg-deb mktemp patchelf realpath cp find install; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "create-universal-linux-deb: missing $command_name" >&2
    exit 1
  }
done

[[ -x "$source_appimage" ]] || { echo "source AppImage is not executable: $source_appimage" >&2; exit 1; }

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/infinite-ai-deb.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT

extract_dir="$work_dir/extract"
mkdir -p "$extract_dir"
(
  cd "$extract_dir"
  "$source_appimage" --appimage-extract >/dev/null
)
app_dir="$extract_dir/squashfs-root"
[[ -x "$app_dir/usr/bin/infinite-ai" ]] || { echo "AppImage has no Infinite AI executable" >&2; exit 1; }

package_root="$work_dir/package"
runtime_root="$package_root/opt/infinite-ai"
install -d "$runtime_root/app" "$package_root/usr/bin"
cp -a "$app_dir/." "$runtime_root/app/"

# Private glibc/loader: this is what makes the Jammy-built WebKitGTK bundle
# usable on Focal's older glibc.  Do not copy host GPU drivers; Mesa/NVIDIA
# libraries must continue to come from the running system.
private_lib="$runtime_root/app/usr/lib/infinite-ai-runtime"
install -d "$private_lib"
for library in \
  /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 \
  /lib/x86_64-linux-gnu/libc.so.6 \
  /lib/x86_64-linux-gnu/libm.so.6 \
  /lib/x86_64-linux-gnu/libpthread.so.0 \
  /lib/x86_64-linux-gnu/libdl.so.2 \
  /lib/x86_64-linux-gnu/librt.so.1 \
  /lib/x86_64-linux-gnu/libresolv.so.2 \
  /lib/x86_64-linux-gnu/libutil.so.1 \
  /lib/x86_64-linux-gnu/libgcc_s.so.1 \
  /lib/x86_64-linux-gnu/libstdc++.so.6; do
  [[ -e "$library" ]] || { echo "missing runtime library: $library" >&2; exit 1; }
  # Follow distro symlinks (notably libstdc++.so.6 -> libstdc++.so.6.0.xx)
  # so the private loader never falls back to Ubuntu 20.04's older C++ ABI.
  cp -L "$library" "$private_lib/"
done

# These are the small set of desktop libraries normally supplied by a stock
# Ubuntu installation but not bundled by linuxdeploy.  Keeping them in the
# package makes a clean desktop install deterministic while leaving hardware
# drivers (libGL/libEGL/libdrm) on the host.
for library in \
  /lib/x86_64-linux-gnu/libfontconfig.so.1 \
  /lib/x86_64-linux-gnu/libexpat.so.1 \
  /lib/x86_64-linux-gnu/libfreetype.so.6 \
  /lib/x86_64-linux-gnu/libharfbuzz.so.0 \
  /lib/x86_64-linux-gnu/libfribidi.so.0; do
  [[ -e "$library" ]] && cp -L "$library" "$private_lib/"
done

# AppRun.wrapped uses /proc/self/exe to locate its AppDir.  Patching its
# interpreter (and the real Rust executable) keeps that lookup intact while
# forcing both processes to use the private loader and libc.
interpreter="/opt/infinite-ai/app/usr/lib/infinite-ai-runtime/ld-linux-x86-64.so.2"
patchelf --set-interpreter "$interpreter" "$runtime_root/app/AppRun.wrapped"
patchelf --set-interpreter "$interpreter" "$runtime_root/app/usr/bin/infinite-ai"
patchelf --set-rpath "/opt/infinite-ai/app/usr/lib/infinite-ai-runtime:/opt/infinite-ai/app/usr/lib:/opt/infinite-ai/app/usr/lib/x86_64-linux-gnu" \
  "$runtime_root/app/AppRun.wrapped" "$runtime_root/app/usr/bin/infinite-ai"

launcher="$package_root/usr/bin/infinite-ai"
install -m 0755 /dev/null "$launcher"
cat >"$launcher" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
app_root=/opt/infinite-ai/app
if [[ ! -x "$app_root/AppRun" ]]; then
  echo "Infinite AI is not installed correctly: $app_root/AppRun is missing" >&2
  exit 127
fi
export GTK_IM_MODULE="${GTK_IM_MODULE:-xim}"
export QT_IM_MODULE="${QT_IM_MODULE:-ibus}"
export XMODIFIERS="${XMODIFIERS:-@im=ibus}"
export LC_CTYPE="${LC_CTYPE:-${LANG:-C.UTF-8}}"
export APPDIR="$app_root"
private_lib="$app_root/usr/lib/infinite-ai-runtime"
export LD_LIBRARY_PATH="$private_lib:$app_root/usr/lib:$app_root/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exec "$app_root/AppRun" "$@"
EOF

control_dir="$package_root/DEBIAN"
install -d "$control_dir"
cat >"$control_dir/control" <<EOF
Package: infinite-ai
Version: ${version}
Section: utils
Priority: optional
Architecture: amd64
Maintainer: Infinite AI maintainers
Description: Infinite AI desktop application (portable Linux runtime)
 A self-contained Infinite AI desktop application for Ubuntu 20.04 and 22.04.
 This package intentionally has no runtime dependency on WebKitGTK 4.1.
EOF
cat >"$control_dir/postinst" <<'EOF'
#!/bin/sh
set -eu
chmod 0755 /usr/bin/infinite-ai /opt/infinite-ai/app/AppRun 2>/dev/null || true
exit 0
EOF
chmod 0755 "$control_dir/postinst"

mkdir -p "$(dirname "$output_deb")"
dpkg-deb --build --root-owner-group "$package_root" "$output_deb" >/dev/null
echo "Created $output_deb"
sha256sum "$output_deb"
