#!/system/bin/sh

exec > /data/local/tmp/custom-certificates.log
exec 2>&1

set -x

MODDIR=${0%/*}

set_context() {
    [ "$(getenforce)" = "Enforcing" ] || return 0

    default_selinux_context=u:object_r:system_file:s0
    selinux_context=$(ls -Zd $1 | awk '{print $1}')

    if [ -n "$selinux_context" ] && [ "$selinux_context" != "?" ]; then
        chcon -R $selinux_context $2
    else
        chcon -R $default_selinux_context $2
    fi
}

# Copy All certificates from /data/misc/user/0/cacerts-added/* and /data/misc/user/0/cacerts-custom/* to the system store
# Note that some apps may ignore other certs.

# Keep AdGuard Personal Intermediate Certificate in user store.
AdGuard_Personal_Intermediate_HASH=47ec1af8

chmod -R 644 /data/misc/user/0/cacerts-custom
cp -f /data/misc/user/0/cacerts-custom/* $MODDIR/system/etc/security/cacerts/
cp -f /data/misc/user/0/cacerts-added/* $MODDIR/system/etc/security/cacerts/
rm $MODDIR/system/etc/security/cacerts/${AdGuard_Personal_Intermediate_HASH}.*
chown -R 0:0 $MODDIR/system/etc/security/cacerts
chmod -R 644 $MODDIR/system/etc/security/cacerts
chcon -R u:object_r:system_security_cacerts_file:s0 $MODDIR/system/etc/security/cacerts
set_context /system/etc/security/cacerts ${MODDIR}/system/etc/security/cacerts

# Android 14 support
# Since Magisk ignore /apex for module file injections, use non-Magisk way
if [ -d /apex/com.android.conscrypt/cacerts ]; then
    # Clone directory into tmpfs
    rm -f /data/local/tmp/all-ca-copy
    mkdir -p /data/local/tmp/all-ca-copy
    mount -t tmpfs tmpfs /data/local/tmp/all-ca-copy
    cp -f /apex/com.android.conscrypt/cacerts/* /data/local/tmp/all-ca-copy/

    # Do the same as in Magisk module
    cp -f /data/misc/user/0/cacerts-custom/* /data/local/tmp/all-ca-copy
    cp -f /data/misc/user/0/cacerts-added/* /data/local/tmp/all-ca-copy
    rm /data/local/tmp/all-ca-copy/${AdGuard_Personal_Intermediate_HASH}.*
    set_context /apex/com.android.conscrypt/cacerts /data/local/tmp/all-ca-copy

    # Mount directory inside APEX and remove temporary one.
    CERTS_NUM="$(ls -1 /data/local/tmp/all-ca-copy | wc -l)"
    if [ "$CERTS_NUM" -gt 15 ]; then
        mount --bind /data/local/tmp/all-ca-copy /apex/com.android.conscrypt/cacerts
    else
        echo "Cancelling replacing CA storage due to safety"
    fi
    umount /data/local/tmp/all-ca-copy
    rmdir /data/local/tmp/all-ca-copy
fi
