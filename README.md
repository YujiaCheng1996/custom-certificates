# Custom Certificates

[简体中文](./README_zh_cn.md)

This module is based on [AdGuard Certificate](https://github.com/AdguardTeam/adguardcert) and [custom-certificate-authorities](https://github.com/Magisk-Modules-Alt-Repo/custom-certificate-authorities).
It is not compatible with those modules, so remove them before using this one.

To hide tmpfs traces that may be detected by some root detection apps, this module supports [meta-hybrid_mount](https://github.com/Hybrid-Mount/meta-hybrid_mount). Install it and add `apex` to its partitions list before installing this module.

**Warning**
All user certificates will be copied to the system store after reboot.
Trust them at your own risk.

If you disable or uninstall [meta-hybrid_mount](https://github.com/Hybrid-Mount/meta-hybrid_mount), remember to either delete `/data/adb/meta-hybrid/config.toml` (or the older `/data/adb/hybrid-mount/config.toml`) or remove `apex` from the partitions list in that file. Otherwise, this module may stop working properly.

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
