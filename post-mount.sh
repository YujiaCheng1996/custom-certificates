#!/system/bin/sh

exec > /dev/null
exec 2>&1

MODDIR=${0%/*}

KAGAMI_MODULES_DIR=/data/adb/modules/kagami
KAGAMI_DATA_DIR=/data/adb/kagami
HYBRID_MODE_MARKER=$MODDIR/.hybrid-mount-mode

# Known eMudhra/emSign certificate subject_hash_old prefixes (4 compromised certs)
EMUDHRA_HASHES="869fbf79 b74d2bd5 dbff3a01 f459871d"

# Global overlayfs detection - same logic as post-fs-data.sh
# use_overlayfs=1: KernelSU with metamodule (meta-overlayfs, hybrid_mount, kagami)
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
       [ -d /data/adb/modules/hybrid_mount ] || \
       [ -d /data/adb/modules/kagami ]; then
        use_overlayfs=1
    fi
    return $use_overlayfs
}

# Kagami kasumi backend detection - same logic as post-fs-data.sh. Guarding on
# an alive Kagami directory also decides whether meta-hybrid_mount is the
# serving pipeline at all.
detect_kagami_kasumi() {
    kagami_kasumi=0

    # Kagami is a KernelSU metamodule; never evaluate it under Magisk.
    if [ -z "$KSU" ] && [ -z "$KSU_VER" ]; then
        return 0
    fi

    if [ ! -d "$KAGAMI_MODULES_DIR" ] || \
       [ -f "$KAGAMI_MODULES_DIR/disable" ] || [ -f "$KAGAMI_MODULES_DIR/remove" ]; then
        return 0
    fi

    # Mirror Kagami's backend resolution (prepare_backend_plan): the global
    # mount_backend value (anything other than "auto", default "auto" when the
    # key is absent) overrides the per-module mode entry; with "auto" the
    # per-module mode decides.
    if [ -f "$KAGAMI_DATA_DIR/config.json" ]; then
        if grep -qs '"mount_backend"[[:space:]]*:[[:space:]]*"kasumi"' \
            "$KAGAMI_DATA_DIR/config.json"; then
            kagami_kasumi=1
            return 0
        fi
        if grep -qs '"mount_backend"' \
            "$KAGAMI_DATA_DIR/config.json" && \
            ! grep -qs '"mount_backend"[[:space:]]*:[[:space:]]*"auto"' \
            "$KAGAMI_DATA_DIR/config.json"; then
            # A different explicit global backend wins over the per-module mode.
            return 0
        fi
    fi

    if grep -qs '"custom-certificates"[[:space:]]*:[[:space:]]*"kasumi"' \
        "$KAGAMI_DATA_DIR/module_mode.json"; then
        kagami_kasumi=1
    fi
}

META_HYBRID_CONFIG=

# meta-hybrid_mount detection - same logic as post-fs-data.sh: only active
# when Kagami is absent or disabled.
detect_meta_hybrid() {
    hybrid_active=0

    # KernelSU metamodule; never evaluated under Magisk.
    if [ -z "$KSU" ] && [ -z "$KSU_VER" ]; then
        return 0
    fi
    [ "$use_overlayfs" -eq 1 ] || return 0

    if [ -d "$KAGAMI_MODULES_DIR" ] && \
       [ ! -f "$KAGAMI_MODULES_DIR/disable" ] && [ ! -f "$KAGAMI_MODULES_DIR/remove" ]; then
        return 0
    fi

    if [ -d /data/adb/modules/hybrid_mount ] || \
       [ -d /data/adb/modules/meta-hybrid_mount ]; then
        hybrid_active=1
    fi

    [ "$hybrid_active" -eq 1 ] && [ -f /data/adb/hybrid-mount/config.toml ] && \
        META_HYBRID_CONFIG=/data/adb/hybrid-mount/config.toml
    return 0
}

# Kernel executables that carry the VFS control CLI. Rule changes through it
# are runtime-only: they live in provider memory and must be re-applied per
# boot, which is exactly the cadence the former apex bind followed.
detect_hybrid_cli() {
    HYBRID_CLI=
    for cli in /data/adb/modules/hybrid_mount/hybrid-mount \
        /data/adb/modules/meta-hybrid_mount/hybrid-mount; do
        if [ -x "$cli" ]; then
            HYBRID_CLI=$cli
            break
        fi
    done
}

# Serve the apex store through the provider instead of a bind view: one
# whiteout batch for the compromised entries and one proxy batch from the
# virtual user certificate names to the staged real files. Both are global
# (UID 0) rules, so root sees the same view; replacement is keyed by
# (path, UID), so a re-run can never duplicate a serving rule. Returns 0 only
# when every rule read back confirmed.
apex_inject_rules() {
    [ -n "$HYBRID_CLI" ] || return 1
    [ -d "$APEX_CERT_DIR" ] || return 1

    names=
    for hash in $EMUDHRA_HASHES; do
        for certificate in "$APEX_CERT_DIR"/$hash.*; do
            [ -e "$certificate" ] || continue
            names="$names $certificate"
        done
    done
    if [ -n "$names" ]; then
        "$HYBRID_CLI" vfs rule add --whiteout $names >/dev/null 2>&1 || return 1
    fi

    pairs=
    for certificate in "$APEX_STORE"/*; do
        [ -f "$certificate" ] || continue
        name=$(basename "$certificate")
        [ -e "$APEX_CERT_DIR/$name" ] && continue
        pairs="$pairs $APEX_CERT_DIR/$name $certificate"
    done
    if [ -n "$pairs" ]; then
        "$HYBRID_CLI" vfs rule add $pairs >/dev/null 2>&1 || return 1
    fi
    return 0
}

# True when the hybrid-mount VFS provider is live. The provider is loaded
# inside the metamodule's own pipeline, which runs after post-fs-data, so this
# probe is only final at post-mount time.
hybrid_provider_present() {
    grep -qs '^hybridmount' /proc/modules && return 0
    [ -d /sys/module/hybridmount ]
}

# Reconcile the recorded serving mode: rewrite the marker and the canonical
# rule section. The drop-window removes the whole section for this module id,
# so a mode change can never leave a duplicate section behind.
hybrid_reconcile_rule() {
    mode=$1
    echo "$mode" > "$HYBRID_MODE_MARKER"
    [ -f "$META_HYBRID_CONFIG" ] || return 0
    awk '
        index($0, "[rules.custom-certificates]") == 1 { skip = 1; next }
        index($0, "[") == 1 { skip = 0 }
        skip { next }
        { print }
    ' "$META_HYBRID_CONFIG" > "$META_HYBRID_CONFIG.$$" &&
        mv "$META_HYBRID_CONFIG.$$" "$META_HYBRID_CONFIG"
    {
        echo ''
        echo '[rules.custom-certificates]'
        echo "default_mode = \"$mode\""
    } >> "$META_HYBRID_CONFIG"
}

# Run detection
detect_overlayfs

if [ "$use_overlayfs" -eq 0 ];  then
    exit 0
fi

detect_kagami_kasumi
detect_meta_hybrid

SYSTEM_STORE=$MODDIR/system/etc/security/cacerts
APEX_STORE=$MODDIR/apex/com.android.conscrypt/cacerts
APEX_CERT_DIR=/apex/com.android.conscrypt/cacerts

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

# The apex store serving mode is resolved per backend below.

if [ "$hybrid_active" -eq 1 ]; then
    # meta-hybrid_mount serves the system view itself: the recorded rule
    # prefers its VFS provider and falls back to OverlayFS, both interpreting
    # the staged whiteouts. The record is reconciled with the live provider
    # state, which is only final after the metamodule's own pipeline ran.
    provider_present=0
    HYBRID_CLI=
    if hybrid_provider_present; then
        provider_present=1
        detect_hybrid_cli
    fi

    if [ "$HYBRID_CLI" ] && apex_inject_rules; then
        # The provider serves the apex store through VFS rules: zero mounts
        # for this module the whole boot.
        :
    else
        # Triple fallback: provider missing, CLI absent, or the provider
        # refused verification. The bind keeps the deletion guarantee.
        bind_store "$APEX_STORE" "$APEX_CERT_DIR"
    fi

    marker=
    [ -f "$HYBRID_MODE_MARKER" ] && marker=$(head -n 1 "$HYBRID_MODE_MARKER" 2>/dev/null)
    if [ "$marker" = "vfs" ]; then
        if [ "$provider_present" -eq 0 ]; then
            # The VFS provider did not come up: its rules degrade silently to
            # a stock certificate view, so fall back to a module-provided bind
            # for this boot and reconcile the recorded rule back to OverlayFS.
            hybrid_reconcile_rule overlay
            bind_store "$SYSTEM_STORE" /system/etc/security/cacerts
        fi
    elif [ "$marker" = "overlay" ]; then
        if [ "$provider_present" -eq 1 ]; then
            # Provider up: promote the record to the preferred VFS backend.
            # This boot keeps the OverlayFS view, the next boot switches over.
            hybrid_reconcile_rule vfs
        fi
    fi
    # No marker: the store is served on defaults or the rule is user-managed
    # (marker intentionally absent); keep hands off both.
elif [ "$kagami_kasumi" -eq 1 ]; then
    # Kagami kasumi: the staged store is a plain cleaned copy; the bind view is
    # the deletion mechanism for every observer, root included.
    bind_store "$APEX_STORE" "$APEX_CERT_DIR"
    bind_store "$SYSTEM_STORE" /system/etc/security/cacerts
else
    # Every other metamodule backend is completed by the module's own store
    # binds: they are the only mechanism that removes the compromised
    # certificates for every observer, root included.
    bind_store "$APEX_STORE" "$APEX_CERT_DIR"
    bind_store "$SYSTEM_STORE" /system/etc/security/cacerts
fi
