#!/system/bin/sh

exec > /dev/null
exec 2>&1

MODDIR=${MODDIR:-${0%/*}}

META_HYBRID_CONFIG=

find_meta_hybrid_config() {
    for config in \
        /data/adb/meta-hybrid/config.toml \
        /data/adb/hybrid-mount/config.toml \
        /data/adb/modules/hybrid_mount/config.toml; do
        if [ -f "$config" ]; then
            META_HYBRID_CONFIG=$config
            return 0
        fi
    done
    META_HYBRID_CONFIG=
    return 1
}

meta_hybrid_handles_apex() {
    find_meta_hybrid_config || return 1
    grep -Eq 'partitions.*"apex"|^[[:space:]]*"apex"[[:space:]]*$' "$META_HYBRID_CONFIG"
}

set_context() {
    [ "$(getenforce)" = "Enforcing" ] || return 0

    default_selinux_context=u:object_r:system_file:s0
    selinux_context=$(ls -Zd "$1" | awk '{print $1}')

    if [ -n "$selinux_context" ] && [ "$selinux_context" != "?" ]; then
        chcon -R "$selinux_context" "$2"
    else
        chcon -R "$default_selinux_context" "$2"
    fi
}

fix_user_store_permissions() {
    store_dir=$1
    [ -d "$store_dir" ] || return 0

    chown 0:0 "$store_dir"
    chmod 755 "$store_dir"
    for certificate in "$store_dir"/*; do
        [ -f "$certificate" ] || continue
        chown 0:0 "$certificate"
        chmod 644 "$certificate"
    done
}

copy_user_certificates() {
    source_dir=$1
    target_dir=$2
    [ -d "$source_dir" ] || return 0

    for certificate in "$source_dir"/*; do
        [ -f "$certificate" ] || continue
        cp -f "$certificate" "$target_dir"/
    done
}

copy_store_certificates() {
    source_dir=$1
    target_dir=$2
    [ -d "$source_dir" ] || return 0

    for certificate in "$source_dir"/*; do
        [ -f "$certificate" ] || continue
        cp -f "$certificate" "$target_dir"/
    done
}

ADGUARD_PERSONAL_INTERMEDIATE_HASH=47ec1af8
CUSTOM_DIR=/data/misc/user/0/cacerts-custom
ADDED_DIR=/data/misc/user/0/cacerts-added
SYSTEM_STORE=$MODDIR/system/etc/security/cacerts

fix_user_store_permissions "$CUSTOM_DIR"
fix_user_store_permissions "$ADDED_DIR"
mkdir -p "$SYSTEM_STORE"
rm -f "$SYSTEM_STORE/.gitkeep"
# Preserve the stock system store in the generated directory so a directory
# bind/overlay cannot hide the built-in certificates.
copy_store_certificates /system/etc/security/cacerts "$SYSTEM_STORE"
for user_store in \
    "$CUSTOM_DIR" "$ADDED_DIR" \
    /data/misc/user/*/cacerts-custom \
    /data/misc/user/*/cacerts-added; do
    copy_user_certificates "$user_store" "$SYSTEM_STORE"
done
rm -f "$SYSTEM_STORE"/${ADGUARD_PERSONAL_INTERMEDIATE_HASH}.*
chown -R 0:0 "$SYSTEM_STORE"
chmod 755 "$SYSTEM_STORE"
chmod 644 "$SYSTEM_STORE"/* 2>/dev/null
chcon -R u:object_r:system_security_cacerts_file:s0 "$SYSTEM_STORE"
set_context /system/etc/security/cacerts "$SYSTEM_STORE"

if [ -d /apex/com.android.conscrypt/cacerts ]; then
    if meta_hybrid_handles_apex; then
        APEX_STORE=$MODDIR/apex/com.android.conscrypt/cacerts
        mkdir -p "$APEX_STORE"
        cp -f /apex/com.android.conscrypt/cacerts/* "$APEX_STORE"/ 2>/dev/null
        cp -f "$SYSTEM_STORE"/* "$APEX_STORE"/ 2>/dev/null
        rm -f "$APEX_STORE"/${ADGUARD_PERSONAL_INTERMEDIATE_HASH}.*
        chown -R 0:0 "$APEX_STORE"
        chmod 755 "$APEX_STORE"
        chmod 644 "$APEX_STORE"/* 2>/dev/null
        set_context /apex/com.android.conscrypt/cacerts "$APEX_STORE"
    else
        rm -rf /data/local/tmp/custom-certificates-cacerts
        mkdir -p /data/local/tmp/custom-certificates-cacerts
        cp -f /apex/com.android.conscrypt/cacerts/* /data/local/tmp/custom-certificates-cacerts/ 2>/dev/null
        cp -f "$SYSTEM_STORE"/* /data/local/tmp/custom-certificates-cacerts/ 2>/dev/null
        rm -f /data/local/tmp/custom-certificates-cacerts/${ADGUARD_PERSONAL_INTERMEDIATE_HASH}.*
        chown -R 0:0 /data/local/tmp/custom-certificates-cacerts
        chmod 755 /data/local/tmp/custom-certificates-cacerts
        chmod 644 /data/local/tmp/custom-certificates-cacerts/* 2>/dev/null
        set_context /apex/com.android.conscrypt/cacerts /data/local/tmp/custom-certificates-cacerts
        mount --bind /data/local/tmp/custom-certificates-cacerts /apex/com.android.conscrypt/cacerts
    fi
fi
