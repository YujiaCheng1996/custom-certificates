# 自定义证书

[English](./README.md)

本模块基于 [AdGuard Certificate](https://github.com/AdguardTeam/adguardcert) 和 [custom-certificate-authorities](https://github.com/Magisk-Modules-Alt-Repo/custom-certificate-authorities)。
它与上述模块不兼容，因此在使用本模块前请先移除它们。

为了隐藏可能被某些 Root 检测应用发现的 tmpfs 痕迹，本模块支持 [meta-hybrid_mount](https://github.com/Hybrid-Mount/meta-hybrid_mount)。请先安装它，并在安装本模块之前将 `apex` 加入其分区列表。

**警告**
重启后，所有用户证书都会被复制到系统证书存储中。
请自行承担信任这些证书的风险。

如果你禁用或卸载了 [meta-hybrid_mount](https://github.com/Hybrid-Mount/meta-hybrid_mount)，请记得删除 `/data/adb/meta-hybrid/config.toml`（或旧版路径 `/data/adb/hybrid-mount/config.toml`），或者从该文件的分区列表中移除 `apex`。否则，本模块可能无法正常工作。

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
