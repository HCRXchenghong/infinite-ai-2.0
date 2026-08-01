# 发行包归档

这里保存用于迁移和回滚的 LiveAgent v1.2.3 兼容发行包，按操作系统分目录：

- `linux/`：Linux x86_64 AppImage（本机测试包；文件超过 GitHub 普通仓库 100 MiB 限制，不纳入 Git）
- `windows/`：Windows x64 安装包、MSI 和便携版
- `macos/`：macOS Intel 与 Apple Silicon 安装包

这些文件是历史构建产物，包内仍可能显示 LiveAgent 名称；它们没有被伪装成已经重新编译的 Infinite AI。新的 Infinite AI 构建会使用仓库内的品牌和图标资源，并通过发布流水线生成。

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
