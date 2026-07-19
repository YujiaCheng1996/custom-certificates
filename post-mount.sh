#!/system/bin/sh

exec > /dev/null
exec 2>&1

MODDIR=${0%/*}

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

if ! meta_hybrid_handles_apex; then
    exit 0
fi

SYSTEM_STORE=$MODDIR/system/etc/security/cacerts
APEX_STORE=$MODDIR/apex/com.android.conscrypt/cacerts

bind_store() {
    source_dir=$1
    target_dir=$2
    [ -d "$source_dir" ] || return 0
    [ -d "$target_dir" ] || return 0

    mount --bind "$source_dir" "$target_dir"
    for pid in 1 $(pgrep zygote) $(pgrep zygote64) \
        $(pidof system_server) $(pidof com.android.settings) \
        $(pidof com.android.keychain) $(pidof adbd); do
        [ -d "/proc/$pid/ns" ] || continue
        nsenter --mount="/proc/$pid/ns/mnt" -- \
            /system/bin/mount --bind "$source_dir" "$target_dir"
    done
}

bind_store "$SYSTEM_STORE" /system/etc/security/cacerts
bind_store "$APEX_STORE" /apex/com.android.conscrypt/cacerts
