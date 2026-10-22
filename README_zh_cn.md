# 自定义证书

[English](./README.md)

本模块基于 [AdGuard Certificate](https://github.com/AdguardTeam/adguardcert) 和 [custom-certificate-authorities](https://github.com/Magisk-Modules-Alt-Repo/custom-certificate-authorities)。
它与上述模块不兼容，因此在使用本模块前请先移除它们。

为了隐藏可能被某些 Root 检测应用发现的 tmpfs 痕迹，本模块新增支持 Metamodule。请先安装一个。

**警告**
重启后，所有用户证书都会被复制到系统证书存储中。
请自行承担信任这些证书的风险。

## 支持的 Metamodule

本模块会自动检测当前使用的 KernelSU Metamodule，并应用正确的证书清理策略：

| Metamodule | 默认后端 | 清理策略 |
| ------------ | ---------- | ---------- |
| [meta-overlayfs](https://github.com/tiann/KernelSU/releases) | OverlayFS | 创建 whiteout 文件 (`mknod c 0 0`) |
| [meta-hybrid_mount](https://github.com/Hybrid-Mount/meta-hybrid_mount) | 可配置 | OverlayFS 创建 whiteout；bind mount 直接删除即可 |
| [Kagami](https://github.com/Rouyashiki/Kagami) | OverlayFS (Kasumi 可选) | Whiteout 文件（OverlayFS 默认）；Kasumi 需显式按模块/全局启用 |

## 安全：eMudhra 中间 CA 密钥泄露缓解措施

**自 v3.3 起**，本模块在启动时会自动清理受损的 eMudhra 中间 CA 证书。

2026 年 10 月，发现八个 eMudhra 中间 CA 证书的私钥因密钥生成过弱而泄露。这些证书链接到 Android、Chrome、Mozilla 等主流信任存储所信任的根证书。

每次启动时，本模块将按已知受损证书的 **subject_hash_old 前缀** 删除匹配文件：

- `869fbf79` — emSign ECC Root CA - C3
- `b74d2bd5` — emSign ECC Root CA - G3
- `dbff3a01` — emSign Root CA - C1
- `f459871d` — emSign Root CA - G1
Android 系统存储中通常存在这 4 个此类证书。清理完成后，模块将清理过的证书存储挂载回系统位置，确保应用和浏览器不再信任这些受损的中间 CA。

## 简单用法

1. 信任你想使用的证书。
2. 重启。

## 高级用法

仅当你不想看到恼人的系统通知时再使用此方式。

1. 信任你想使用的证书。
2. 使用 Root 文件管理器，将你已信任的 `subject_hash_old.N` 证书文件从 `/data/misc/user/0/cacerts-added` 移动到自建的 `/data/misc/user/0/cacerts-custom`。
3. 重启。

## WebUI

在 KernelSU Manager 中，本模块内置了一个 WebUI，可用于：

1. 列出 `/data/misc/user/0/cacerts-custom` 和 `/data/misc/user/0/cacerts-added` 中的证书。
2. 显示解析后的证书详情。
3. 在这两个目录之间移动证书。
4. 导入 PEM/DER 证书，转换格式后保存到目标证书存储位置。
5. 永久删除证书。

**警告**
目录改动会立即写入，但系统信任链的变化仍需要重启后才能完全生效。

这样你就可以不用再深入系统里那些隐藏很深的证书设置菜单来管理证书了。

## 致谢

感谢 [@peculiar/x509](https://github.com/PeculiarVentures/x509) 和 [@abraham/reflection](https://github.com/abraham/reflection)。由于当前环境中无法使用 OpenSSL CLI，正是他们让这里的证书解析与格式化成为可能。
