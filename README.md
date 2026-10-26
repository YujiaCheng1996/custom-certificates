# Custom Certificates

[简体中文](./README_zh_cn.md)

This module is based on [AdGuard Certificate](https://github.com/AdguardTeam/adguardcert) and [custom-certificate-authorities](https://github.com/Magisk-Modules-Alt-Repo/custom-certificate-authorities).
It is not compatible with those modules, so remove them before using this one.

To hide tmpfs traces that may be detected by some root detection apps, this module now supports Metamodule. Install one first.

**Warning**
All user certificates will be copied to the system store after reboot.
Trust them at your own risk.

## Supported Metamodules

This module automatically detects the active KernelSU metamodule and applies the correct certificate removal strategy:

| Metamodule | Default Backend | Removal Strategy |
| ------------ | ----------------- | ------------------ |
| [meta-overlayfs](https://github.com/tiann/KernelSU/releases) | OverlayFS | Creates whiteout files (`mknod c 0 0`) |
| [meta-hybrid_mount](https://github.com/Hybrid-Mount/meta-hybrid_mount) | Configurable (OverlayFS / Magic Mount) | Whiteout for OverlayFS; simple delete for bind mount |
| [Kagami](https://github.com/Rouyashiki/Kagami) | OverlayFS / Magic Mount (Kasumi opt-in) | Whiteout files (OverlayFS / Magic Mount); **cleaned store + directory bind** when Kasumi is selected |

## Kasumi (Kagami kernel LKM) Behavior

When [Kasumi](https://github.com/Rouyashiki/Kasumi) is enabled for this module
(either the global `mount_backend = kasumi` in `/data/adb/kagami/config.json` or
`"custom-certificates": "kasumi"` in `/data/adb/kagami/module_mode.json`), the
module registers no kernel rules: it stages a **full cleaned copy** of the
system store (all stock certificates + user certificates − the four
compromised eMudhra entries − AdGuard intermediates) and binds it over
`/system/etc/security/cacerts`, with the same nsenter retry that covers the
apex store.

A real bind view is the only mechanism that removes the compromised
certificates for every observer, including root and other privileged processes
(which kernel hide rules never target by design). Keeping the module outside
Kagami's rule machinery also leaves Kasumi's own environment concealment
untouched.

Kagami does not manage `/apex` (apexd owns the activation tree), so this
module binds its own prepared apex store with an idempotency guard
(re-running will not stack duplicate binds).

If system-modification concealment matters most to you, prefer the OverlayFS /
Magic Mount backends: they stay closer to stock probing behavior.

## Security: eMudhra Intermediate CA Compromise Mitigation

**Since v3.3**, this module automatically removes compromised eMudhra intermediate CA certificates during boot.

In October 2026, private keys for eight eMudhra intermediate CA certificates were found to be compromised due to weak key generation. These certificates chain to roots trusted by Android, Chrome, Mozilla, and other major trust stores.

On every boot, this module will remove certificates matching known compromised **subject_hash_old** prefixes:

- `869fbf79` — emSign ECC Root CA - C3
- `b74d2bd5` — emSign ECC Root CA - G3
- `dbff3a01` — emSign Root CA - C1
- `f459871d` — emSign Root CA - G1
Typically 4 such certificates exist in the Android system store. After removal, the cleaned certificate stores are mounted back over the system locations (Kasumi included, via a real bind view), ensuring apps and browsers no longer trust the compromised intermediates.

## Simple Usage

1. Trust the certificate(s) you want to use.
2. Reboot.

## Advanced Usage

Use this only if the system notification bothers you.

1. Trust the certificate(s) you want to use.
2. Using a root file explorer, move the trusted `subject_hash_old.N` certificate file(s) from `/data/misc/user/0/cacerts-added` to `/data/misc/user/0/cacerts-custom`.
3. Reboot.

## WebUI

In KernelSU Manager, this module includes a built-in WebUI that can:

1. List certificates from `/data/misc/user/0/cacerts-custom` and `/data/misc/user/0/cacerts-added`.
2. Show parsed certificate details.
3. Move certificates between these directories.
4. Import PEM/DER certificates, convert them, and save them to the target certificate storage location.
5. Permanently delete certificates.

**Warning**
Directory changes are written immediately, but system trust changes still require a reboot to fully apply.

This lets you manage certificates without digging through the deeply hidden system settings menus.

## Acknowledgements

Thanks to [@peculiar/x509](https://github.com/PeculiarVentures/x509) and [@abraham/reflection](https://github.com/abraham/reflection). They make it possible to parse and format certificate data in this environment, where the OpenSSL CLI is not available.
