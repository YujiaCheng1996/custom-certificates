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
| [meta-hybrid_mount](https://github.com/Hybrid-Mount/meta-hybrid_mount) | 可配置（OverlayFS / Magic Mount / VFS） | 登记系统库服务规则：优先 VFS 后端，OverlayFS 兜底；apex 同样以 VFS 规则服务，provider 缺席时回退 bind |
| [Kagami](https://github.com/Rouyashiki/Kagami) | OverlayFS / Magic Mount（Kasumi 可选启用） | Whiteout 文件（OverlayFS / Magic Mount）；选择 Kasumi 时采用**完整清理副本 + 目录 bind** |

## Kasumi（Kagami 内核 LKM）行为说明

当本模块被 [Kasumi](https://github.com/Rouyashiki/Kasumi) 后端接管时（全局 `/data/adb/kagami/config.json` 中 `mount_backend = kasumi`，或 `/data/adb/kagami/module_mode.json` 中 `"custom-certificates": "kasumi"`）， 模块不注册任何内核规则：先暂存一份**完整清理副本**（全部系统原始证书 + 用户证书 − 四个受损 eMudhra 证书 − AdGuard 中间证书），再以目录 bind 覆盖 `/system/etc/security/cacerts`，并附带与 apex 相同的 nsenter 补挂流程。 

bind 视图是唯一能让所有观察者（包括 root 及其它特权进程）都看不到受损证书的 机制——内核 hide 规则按设计不会作用于这些进程。本模块完全不触碰 Kagami 的 规则机制，因此 Kasumi 自身的环境隐藏行为不受任何影响。 

Kagami 不管理 `/apex`（apex 激活树由 apexd 负责），因此本模块自行挂载处理过的 apex 证书库，并带有幂等保护（重复执行不会叠加重复挂载）。 

如果最看重"系统修改环境"的隐蔽性，建议优先选择 OverlayFS / Magic Mount 后端：它们更贴近原生探测行为。 

## meta-hybrid_mount 行为说明 

meta-hybrid_mount 由它自己的后端服务模块目录，因此在该模式下本模块不再自挂 系统证书库，而是把一条服务规则登记进 `/data/adb/hybrid-mount/config.toml` 的 `[rules.custom-certificates]` 小节： 优先 VFS 后端，OverlayFS 兜底。暂存的 whiteout 对两者都是同一形态 （`mknod c 0 0` 设备文件），删除机制一致。由用户手写的小节属于用户自管， 模块不改动。 

登记的规则会在 post-mount 阶段按实际 provider 状态收敛：首次记录跟随配置中的 全局后端；`hybridmount` provider 在位时提升为 VFS。若 provider 未能加载，其 规则会静默退回原生视图，模块会在当次启动应急 bind 自己的清理副本兜底，并把 登记改回 OverlayFS；后续启动会继续重试 provider。 

meta-hybrid_mount 不管理 `/apex`（apex 激活树由 apexd 负责）。provider 在位时， apex 证书库以零挂载方式服务：一批 whiteout 隐藏受损条目，用户证书通过注入代理 读取暂存副本，全部是每次开机重放的 UID 0 全局规则（内核按 路径 + UID 键替换， 重放不会累积规则）。若 provider 缺席或拒绝下发，该次启动回退为模块自挂的 无 whiteout bind，删除保证不变。

## 安全：eMudhra 中间 CA 密钥泄露缓解措施

**自 v3.3 起**，本模块在启动时会自动清理受损的 eMudhra 中间 CA 证书。

2026 年 10 月，发现八个 eMudhra 中间 CA 证书的私钥因密钥生成过弱而泄露。这些证书链接到 Android、Chrome、Mozilla 等主流信任存储所信任的根证书。

每次启动时，本模块将按已知受损证书的 **subject_hash_old 前缀** 删除匹配文件：

- `869fbf79` — emSign ECC Root CA - C3
- `b74d2bd5` — emSign ECC Root CA - G3
- `dbff3a01` — emSign Root CA - C1
- `f459871d` — emSign Root CA - G1
Android 系统存储中通常存在这 4 个此类证书。清理完成后，处理过的证书库由当前
生效的后端对外呈现——真实 bind 视图（Kasumi 模式同样适用）、OverlayFS 分层，
或 meta-hybrid_mount 的 VFS 注入——确保应用和浏览器不再信任这些受损的中间 CA。

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
