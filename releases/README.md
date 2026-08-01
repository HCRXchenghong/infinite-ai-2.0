# 发行包归档

这里保存用于迁移和回滚的 LiveAgent v1.2.3 兼容发行包，按操作系统分目录：

- `linux/`：Linux x86_64 安装包和兼容归档
- `windows/`：Windows x64 安装包、MSI 和便携版
- `macos/`：macOS Intel 与 Apple Silicon 安装包

这些文件是历史构建产物，包内仍可能显示 LiveAgent 名称；它们没有被伪装成已经重新编译的 Infinite AI。新的 Infinite AI 构建会使用仓库内的品牌和图标资源，并通过发布流水线生成。

## Infinite AI Debian 包

`linux/Infinite-AI-1.3.0-dev.0-ubuntu22.04-amd64.deb` 是当前源码构建的 Ubuntu 22.04 x86_64 包：

```bash
sudo dpkg -i Infinite-AI-1.3.0-dev.0-ubuntu22.04-amd64.deb
```

安装前请确认系统已安装 WebKitGTK 4.1、GTK 3 和 Ayatana AppIndicator 运行库。当前 Tauri 2 桌面运行时使用 WebKitGTK 4.1，而 Ubuntu 20.04 官方仓库只有 WebKitGTK 4.0，因此这个包不会冒充支持 Ubuntu 20.04。20.04 专用包需要以 Focal 基线重新构建 WebKitGTK 运行时后再发布；在该包发布前请使用源码或 AppImage 方案，不要在 20.04 上强行安装此包。

SHA-256：

```text
cc41d9f44b14eda1b9f4d72b912d2c6fb8fb27fc3425c2c908495f3bb39af67f  linux/Infinite-AI-1.3.0-dev.0-ubuntu22.04-amd64.deb
```

下载后请先校验 SHA-256：

```text
9619e93020d384ebc5df1d75deca58adfb83a3d64a7421ec9934f3a254231003  macos/LiveAgent-v1.2.3-macOS-aarch64.app.tar.gz
43acd09ba3580c2e3d0a4ce1e281d606479c929328e239ba78665d35d31d19ca  macos/LiveAgent-v1.2.3-macOS-aarch64.dmg
884c358a1af86e8e687c7fb93302af5417819f6749dfcf4eacb3fd9672ab2e1b  macos/LiveAgent-v1.2.3-macOS-x64.app.tar.gz
1b985688e06f38f8d938d507f1c43d9802410f98be6f3a850c207822ef808f71  macos/LiveAgent-v1.2.3-macOS-x64.dmg
3e20b5b361a2b0eb21547a89a6cfe816068d879a8b85b58c705f84423e2e490e  windows/LiveAgent-v1.2.3-Windows-x64-Setup.exe
c80fa345fd23c0d044068f33bf94dd5bee7a9a7ceea2fe12483c21c595bd4781  windows/LiveAgent-v1.2.3-Windows-x64-portable.zip
d2ad3eab6c75550df091ef5d95556939dccad0eb232d4913b5f737770a6e4b98  windows/LiveAgent-v1.2.3-Windows-x64.msi
```
