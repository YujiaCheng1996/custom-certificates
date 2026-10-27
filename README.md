# Custom Certificates

[简体中文](./README_zh_cn.md)

This module is based on [AdGuard Certificate](https://github.com/AdguardTeam/adguardcert) and [custom-certificate-authorities](https://github.com/Magisk-Modules-Alt-Repo/custom-certificate-authorities).
It is not compatible with those modules, so remove them before using this one.

To hide tmpfs traces that may be detected by some root detection apps, this module supports Metamodule. Install one first.

**Warning**
After reboot, all user certificates will be copied into the system certificate store.
Trust them at your own risk.

## Simple Usage

1. In Android system settings, trust the certificates you want to use / untrust the system ones you do not.
2. Reboot.

## Advanced Usage

Use this only if you do not want to see the annoying system notification.

1. In Android system settings, trust the certificates you want to use / untrust the system ones you do not.
2. Using a root file explorer, move the `subject_hash_old.N` certificate file(s) you already trusted from `/data/misc/user/0/cacerts-added` into a self-created `/data/misc/user/0/cacerts-custom`, keeping the permissions correct.
3. Reboot.

## WebUI

In KernelSU Manager, this module includes a built-in WebUI that can:

1. List certificates from `/data/misc/user/0/cacerts-custom`, `/data/misc/user/0/cacerts-added`, and `/data/misc/user/0/cacerts-removed`.
2. Show parsed certificate details; unparseable entries fall back to their `subject_hash_old`.
3. Move certificates between these two directories.
4. Import PEM/DER certificates, convert them, and save them to the target certificate storage location.
5. Manage untrusted certificates: browse the system directories in a popup multi-select and queue certificates for deletion after the next reboot (the fixed compromised four are locked).

**Warning**
Directory changes are written immediately, but the system trust chain still needs a reboot to fully take effect.

This way you no longer have to dig through the deeply hidden certificate settings menus in Android to manage certificates.

## Security: eMudhra Intermediate CA Compromise Mitigation

**Since v3.3**, this module automatically removes compromised eMudhra intermediate CA certificate files during boot.

In October 2026, private keys for eight eMudhra intermediate CA certificates were found to be compromised due to weak key generation. These certificates chain to roots trusted by Android, Chrome, Mozilla, and other major trust stores.

On every boot, this module deletes matching files by the known compromised **subject_hash_old prefixes**:

- `869fbf79` — emSign ECC Root CA - C3
- `b74d2bd5` — emSign ECC Root CA - G3
- `dbff3a01` — emSign Root CA - C1
- `f459871d` — emSign Root CA - G1

Typically 4 such certificates exist in the Android system store. After removal, the cleaned certificate stores are served by the active backend — a real bind view (Kasumi included), an OverlayFS layer, or the meta-hybrid_mount VFS injection — ensuring apps and browsers no longer trust these compromised intermediates.

## User-Managed Removal Set

Beyond the fixed compromised list, any certificate visible in the served system view can be queued for deletion the same way.
Place `<subject_hash_old>.N` entries into the per-profile store `/data/misc/user/<uid>/cacerts-removed`.
The WebUI handles user 0 for you: in a popup multi-select, browse the two system directories, and confirmed picks are copied into `/data/misc/user/0/cacerts-removed`.
Certificates added through Android system settings may fail to parse; they stay addressable by their `subject_hash_old` name, and the interface only shows that hash.

On every boot, the backend merges the collected hashes into the fixed list and cleans both system directories (the system store and the conscrypt apex store), exactly like the compromised four.
Before cleaning, it copies the fixed four plus every listed certificate still present back into each existing `cacerts-removed` store, so the readable certificate information survives on its own after the stores get cleaned.
The fixed four always belong to the removal set: shown locked in the WebUI, refused on removal from the set, and refused again on re-addition.

## Supported Metamodules

This module automatically detects the currently used KernelSU Metamodule and applies the correct certificate removal strategy:

| Metamodule | Default Backend | Removal Strategy |
| ------------ | ----------------- | ------------------ |
| [meta-overlayfs](https://github.com/tiann/KernelSU/releases) | OverlayFS | Creates whiteout files (`mknod c 0 0`) |
| [meta-hybrid_mount](https://github.com/Hybrid-Mount/meta-hybrid_mount) | Configurable (OverlayFS / Magic Mount / VFS) | Records a serving rule for the system store: VFS preferred, OverlayFS fallback; apex is served as VFS rules too, with a bind fallback when the provider is missing |
| [Kagami](https://github.com/Rouyashiki/Kagami) | OverlayFS / Magic Mount (Kasumi opt-in) | Whiteout files (OverlayFS / Magic Mount); when Kasumi is selected, a **full cleaned copy + directory bind** is used |

## Kasumi (Kagami Kernel LKM) Behavior

When this module is taken over by the [Kasumi](https://github.com/Rouyashiki/Kasumi) backend (global `mount_backend = kasumi` in `/data/adb/kagami/config.json`, or `"custom-certificates": "kasumi"` in `/data/adb/kagami/module_mode.json`), the module registers no kernel rules: it stages a **full cleaned copy** first (all stock system certificates + user certificates − the four compromised eMudhra certificates − the AdGuard intermediate), then bind-mounts it over `/system/etc/security/cacerts`, with the same nsenter retry flow as for the apex store.

The bind view is the only mechanism that makes the compromised certificates invisible to every observer, including root and other privileged processes — kernel hide rules do not apply to them by design. This module does not touch Kagami's rule machinery at all, so Kasumi's own environment concealment remains untouched.

Kagami does not manage `/apex` (the apex activation tree is owned by apexd), so this module mounts its own cleaned apex store, with an idempotency guard (re-running never stacks duplicate mounts).

If you care most about concealing the "system modification environment", prefer the OverlayFS / Magic Mount backends: they stay closer to stock probing behavior.

## meta-hybrid_mount Behavior

meta-hybrid_mount serves the module directory with its own backends, so in this mode the module no longer mounts the system store itself; instead it records one serving rule into the `[rules.custom-certificates]` section of `/data/adb/hybrid-mount/config.toml`: VFS preferred, OverlayFS fallback. The staged whiteouts are the same shape for both (`mknod c 0 0` device files), so the deletion mechanism stays uniform. A user-written section is user-managed and is never modified by the module.

The recorded rule is reconciled in post-mount against the live provider state: the first record follows the global backend in the config; once the `hybridmount` provider is confirmed up, it is promoted to VFS. If the provider fails to load, its rules would silently fall back to the stock view, so the module emergency-binds its own cleaned copy for that boot and reconciles the record back to OverlayFS; later boots keep retrying the provider.

meta-hybrid_mount does not manage `/apex` (the apex activation tree is owned by apexd). When the provider is up, the apex store is served with zero mounts: one whiteout batch hides the compromised entries, and user certificates are read through injected proxies into the staged copies — all as global (UID 0) rules replayed every boot (the kernel replaces rules keyed by path + UID, so replays never accumulate). If the provider is missing or refuses the rules, that boot falls back to the module's own whiteout-free bind, keeping the deletion guarantee unchanged.

## Acknowledgements

Thanks to [@peculiar/x509](https://github.com/PeculiarVentures/x509) and [@abraham/reflection](https://github.com/abraham/reflection). Since the OpenSSL CLI is not available in this environment, they make parsing and formatting certificates here possible.
