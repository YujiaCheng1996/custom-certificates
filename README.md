# Custom Certificate(s)

Based on [AdGuard Certificate](https://github.com/AdguardTeam/adguardcert) and [custom-certificate-authorities](https://github.com/Magisk-Modules-Alt-Repo/custom-certificate-authorities).
This doesn't work along with modules above, remove them before using this module.

To hide tmpfs traces that may be detected by some root detector apps, this module now supports [meta-hybrid_mount](https://github.com/Hybrid-Mount/meta-hybrid_mount). Install it and add `apex` to its partitions list before installing this module.

**Attention**
All user Certificates will be copied to the system store after reboot!!!
Trust them at your own risk!!!

If you disable or uninstall [meta-hybrid_mount](https://github.com/Hybrid-Mount/meta-hybrid_mount), remember to either delete `/data/adb/meta-hybrid/config.toml` (or the older `/data/adb/hybrid-mount/config.toml`) or remove `apex` from the partitions list in that file, otherwise this module may not work properly!!!

## Simple Usage

1. Trust the certificate(s) you want to use.
2. Reboot.

## Advanced Usage

Only if you are annoyed by the system notification.

1. Trust the certificate(s) you want to use.
2. Using a root file explorer, MOVE the .0 certificate file(s) you trusted from /data/misc/user/0/cacerts-added to /data/misc/user/0/cacerts-custom.
3. Reboot.
