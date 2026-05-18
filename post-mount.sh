#!/system/bin/sh

exec > /dev/null
exec 2>&1

MODDIR=${0%/*}

is_hybrid_mount_running() {
    local cli="/data/adb/metamodule/hybrid-mount"
    [ -f "$cli" ] && "$cli" api version >/dev/null 2>&1
}

if [ ! -d /apex/com.android.conscrypt/cacerts ]; then
    exit 0
fi

if ! is_hybrid_mount_running; then
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
