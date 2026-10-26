#!/system/bin/sh

exec > /dev/null
exec 2>&1

MODDIR=${0%/*}

# Global overlayfs detection - same logic as post-fs-data.sh
# use_overlayfs=1: KernelSU with metamodule (meta-overlayfs, meta-hybrid_mount, kagami)
# use_overlayfs=0: Magisk (no metamodule)
detect_overlayfs() {
    use_overlayfs=0

    # Check for KSU environment
    if [ -z "$KSU" ] && [ -z "$KSU_VER" ]; then
        # Magisk environment
        return 0
    fi

    # Any metamodule present -> overlayfs mode (metamodule handles mounting)
    if [ -d /data/adb/modules/meta-overlayfs ] || \
       [ -d /data/adb/modules/meta-hybrid_mount ] || \
       [ -d /data/adb/modules/kagami ]; then
        use_overlayfs=1
    fi
    return $use_overlayfs
}

# Run detection
detect_overlayfs

if [ "$use_overlayfs" -eq 0 ];  then
    exit 0
fi

SYSTEM_STORE=$MODDIR/system/etc/security/cacerts
APEX_STORE=$MODDIR/apex/com.android.conscrypt/cacerts

# True when the target path currently resolves to the same inode as the source
# (i.e. the desired bind mount is already in place).
is_bound_to() {
    [ -d "$1" ] && [ -d "$2" ] || return 1
    target_stat=$(stat -c '%d:%i' "$1" 2>/dev/null) || return 1
    source_stat=$(stat -c '%d:%i' "$2" 2>/dev/null) || return 1
    [ "$target_stat" = "$source_stat" ]
}

bind_store() {
    source_dir=$1
    target_dir=$2
    [ -d "$source_dir" ] || return 0
    [ -d "$target_dir" ] || return 0

    is_bound_to "$target_dir" "$source_dir" && return 0

    mount --bind "$source_dir" "$target_dir"
    for pid in 1 $(pgrep zygote) $(pgrep zygote64) \
        $(pidof system_server) $(pidof com.android.settings) \
        $(pidof com.android.keychain) $(pidof adbd); do
        [ -d "/proc/$pid/ns" ] || continue
        nsenter --mount="/proc/$pid/ns/mnt" -- \
            /system/bin/mount --bind "$source_dir" "$target_dir"
    done
}

# All metamodule backends (Kagami kasumi included) bind the same two stores.
bind_store "$SYSTEM_STORE" /system/etc/security/cacerts
bind_store "$APEX_STORE" /apex/com.android.conscrypt/cacerts
