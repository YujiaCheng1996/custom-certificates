# Custom Certificate(s)

Based on [AdGuard Certificate](https://github.com/AdguardTeam/adguardcert) and [custom-certificate-authorities](https://github.com/Magisk-Modules-Alt-Repo/custom-certificate-authorities).

**Attention**
This doesn't work along with modules above, remove them before using this module.

**Attention**
All user Certificates will be copied to the system store after reboot!!!
Trust them at your own risk!!!

## Simple Usage
1. Trust the certificate(s) you want to use.
2. Reboot.

## Advanced Usage

Only if you are annoyed by the system notification.

1. Trust the certificate(s) you want to use.
2. Using a root file explorer, MOVE the .0 certificate file(s) you trusted from /data/misc/user/0/cacerts-added to /data/misc/user/0/cacerts-custom.
3. Reboot.