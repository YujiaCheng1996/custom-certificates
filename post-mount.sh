#!/system/bin/sh

exec > /dev/null
exec 2>&1

MODDIR=${0%/*}

find_meta_hybrid_config() {
    for config in /data/adb/meta-hybrid/config.toml /data/adb/hybrid-mount/config.toml; do
        if [ -f "$config" ]; then
            META_HYBRID_CONFIG="$config"
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

if [ ! -d /apex/com.android.conscrypt/cacerts ]; then
    exit 0
fi

if ! meta_hybrid_handles_apex; then
    exit 0
fi

if [ ! -d $MODDIR/apex/com.android.conscrypt/cacerts ]; then
    exit 0
fi

mount --bind $MODDIR/apex/com.android.conscrypt/cacerts /apex/com.android.conscrypt/cacerts
for pid in 1 $(pgrep zygote) $(pgrep zygote64); do
    nsenter --mount=/proc/${pid}/ns/mnt -- \
        /bin/mount --bind $MODDIR/apex/com.android.conscrypt/cacerts /apex/com.android.conscrypt/cacerts
done
