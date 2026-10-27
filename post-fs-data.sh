#!/system/bin/sh

exec > /dev/null
exec 2>&1

MODDIR=${MODDIR:-${0%/*}}

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

# Known eMudhra/emSign certificate subject_hash_old prefixes (4 compromised certs)
EMUDHRA_HASHES="869fbf79 b74d2bd5 dbff3a01 f459871d"

# User-managed removal set, collected below from the per-Android-user removal
# stores. The WebUI writes <subject_hash_old>.<index> entries into them.
REMOVAL_HASHES=$EMUDHRA_HASHES

ADGUARD_PERSONAL_INTERMEDIATE_HASH=47ec1af8
CUSTOM_DIR=/data/misc/user/0/cacerts-custom
ADDED_DIR=/data/misc/user/0/cacerts-added
SYSTEM_STORE=$MODDIR/system/etc/security/cacerts
APEX_STORE=$MODDIR/apex/com.android.conscrypt/cacerts
TMP_STORE=/data/local/tmp/custom-certificates-cacerts
KAGAMI_MODULES_DIR=/data/adb/modules/kagami
KAGAMI_DATA_DIR=/data/adb/kagami
HYBRID_MODE_MARKER=$MODDIR/.hybrid-mount-mode

# Global overlayfs detection - runs once, sets use_overlayfs for entire script
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
       [ -d /data/adb/modules/hybrid_mount ] || \
       [ -d /data/adb/modules/kagami ]; then
        use_overlayfs=1
    fi
    return $use_overlayfs
}

# Kagami kasumi backend detection. Must stay in sync with post-mount.sh.
# Under this backend the module registers no kernel rules: it stages a fully
# cleaned store and post-mount binds it, like every other backend. Detection
# also decides whiteout staging, since a plain bind view cannot interpret
# whiteout device files.
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

# KernelSU meta-hybrid_mount detection. Must stay in sync with post-mount.sh.
# Only active when Kagami is absent or disabled: an enabled Kagami installation
# owns the mount pipeline, so meta-hybrid_mount would never be asked to serve
# the certificate view. The canonical configuration is
# /data/adb/hybrid-mount/config.toml; when it is absent the metamodule mounts
# module trees on defaults alone, which the module trusts without recording
# anything.
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

# Record this module's rule into the hybrid-mount configuration. The staged
# whiteouts are meaningful to the overlay and VFS backends alike (a whiteout
# char device is one shape for both), so the recorded mode only decides who
# serves the system view at post-mount: the VFS provider is preferred and
# OverlayFS is the fallback. Skipped when the configuration is absent; a
# pre-existing rule section under this module id is user-managed and the
# configuration stays byte-identical.
hybrid_record_rule() {
    [ "$hybrid_active" -eq 1 ] || return 0
    [ -f "$META_HYBRID_CONFIG" ] || return 0
    grep -qs '^\[rules\.custom-certificates\]' "$META_HYBRID_CONFIG" && return 0

    mode=overlay
    if [ -f "$HYBRID_MODE_MARKER" ]; then
        mode=$(head -n 1 "$HYBRID_MODE_MARKER" 2>/dev/null)
        [ "$mode" = "vfs" ] || mode=overlay
    else
        # Honor the configured global default for the first record so the
        # preferred backend applies from the first boot. Anything that is not
        # the VFS backend stages for OverlayFS.
        mode=$(awk -F'"' '/^\[/{exit} /^default_mode/{if (NF >= 2) {print $2; exit}}' \
            "$META_HYBRID_CONFIG" 2>/dev/null)
        [ "$mode" = "vfs" ] || mode=overlay
    fi
    echo "$mode" > "$HYBRID_MODE_MARKER"
    {
        echo ''
        echo '[rules.custom-certificates]'
        echo "default_mode = \"$mode\""
    } >> "$META_HYBRID_CONFIG"
}

# Collect the user-managed removal set: every subject_hash_old listed by an
# existing per-Android-user removal store (/data/misc/user/<uid>/cacerts-removed).
# Entry names follow the <subject_hash_old>.<index> netkeystore convention;
# anything that does not reduce to an eight-digit hex hash is ignored. The
# fixed compromised set stays part of the list in every case.
collect_removed_certificates() {
    collected=

    for removed_store in /data/misc/user/*/cacerts-removed; do
        [ -d "$removed_store" ] || continue

        for entry in "$removed_store"/*; do
            [ -f "$entry" ] || continue
            entry_name=$(basename "$entry")
            case "$entry_name" in .tmp-*) continue ;; esac
            hash=${entry_name%.*}
            case $hash in
                [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f])
                    case " $EMUDHRA_HASHES " in *" $hash "*) continue ;; esac
                    case " $collected " in *" $hash "*) continue ;; esac
                    collected="$collected $hash"
                    ;;
            esac
        done
    done

    REMOVAL_HASHES="$EMUDHRA_HASHES$collected"
}

# Keep a readable copy of the whole removal set inside every existing per-user
# removal store: the fixed compromised certificates plus every user-marked
# certificate still present in a real system store. Files stored on an earlier
# boot are left untouched, so the readable information survives even once the
# stores get cleaned. Directories are never created here: the WebUI owns the
# removal set and creates its store when the first entry is added.
preserve_removed_certificates() {
    for removed_store in /data/misc/user/*/cacerts-removed; do
        [ -d "$removed_store" ] || continue

        for source_store in /system/etc/security/cacerts \
            /apex/com.android.conscrypt/cacerts; do
            [ -d "$source_store" ] || continue

            for hash in $REMOVAL_HASHES; do
                for certificate in "$source_store"/$hash.*; do
                    [ -f "$certificate" ] || continue
                    cert_name=$(basename "$certificate")
                    [ -e "$removed_store/$cert_name" ] && continue
                    cp -f "$certificate" "$removed_store/$cert_name" 2>/dev/null
                done
            done
        done
    done
}

# Run detection ONCE at startup
detect_overlayfs
detect_kagami_kasumi
detect_meta_hybrid

# Build the removal list, then keep readable copies of it beside the markers.
collect_removed_certificates
preserve_removed_certificates

# Remove every certificate on the removal list (the fixed compromised set plus
# the user-managed set), matched by subject_hash_old prefix. use_whiteouts=1
# additionally leaves a whiteout char device (mknod c 0 0) with the original
# file name so that mount layers which interpret whiteouts (OverlayFS, Magic
# Mount) hide the lower-layer file.
clean_removed_certificates() {
    target_dir=$1
    use_whiteouts=$2

    for hash in $REMOVAL_HASHES; do
        for certificate in "$target_dir"/$hash.*; do
            [ -f "$certificate" ] || continue
            cert_name=$(basename "$certificate")
            rm -f "$certificate"

            if [ "$use_whiteouts" -eq 1 ]; then
                mknod "$target_dir/$cert_name" c 0 0 2>/dev/null
            fi
        done
    done
}

# True when the target path currently resolves to the same inode as the source
# (i.e. the desired bind mount is already in place).
is_bound_to() {
    [ -d "$1" ] && [ -d "$2" ] || return 1
    target_stat=$(stat -c '%d:%i' "$1" 2>/dev/null) || return 1
    source_stat=$(stat -c '%d:%i' "$2" 2>/dev/null) || return 1
    [ "$target_stat" = "$source_stat" ]
}

# Bind source over target unless that exact bind is already mounted.
bind_dir_if_needed() {
    source_dir=$1
    target_dir=$2
    [ -d "$source_dir" ] && [ -d "$target_dir" ] || return 0
    is_bound_to "$target_dir" "$source_dir" && return 0
    mount --bind "$source_dir" "$target_dir"
}

fix_user_store_permissions "$CUSTOM_DIR"
fix_user_store_permissions "$ADDED_DIR"
mkdir -p "$SYSTEM_STORE"
rm -f "$SYSTEM_STORE/.gitkeep"
rm -rf "$SYSTEM_STORE"/* 2>/dev/null
# Keep the stock certificates in the bind source so a directory bind cannot
# hide the built-in entries.
copy_store_certificates /system/etc/security/cacerts "$SYSTEM_STORE"
for user_store in \
    "$CUSTOM_DIR" "$ADDED_DIR" \
    /data/misc/user/*/cacerts-custom \
    /data/misc/user/*/cacerts-added; do
    copy_user_certificates "$user_store" "$SYSTEM_STORE"
done
# Remove compromised eMudhra certificates from system store. Under kasumi the
# store is bound as-is after post-mount, so it stages no whiteouts. Every
# mount-served backend interprets them: OverlayFS, Magic Mount, and both
# meta-hybrid_mount backends (its OverlayFS staging and the VFS provider, whose
# whiteouts are the same char-device shape). A directory bind view would only
# list them as device files.
if [ "$kagami_kasumi" -eq 1 ]; then
    clean_removed_certificates "$SYSTEM_STORE" 0
else
    clean_removed_certificates "$SYSTEM_STORE" "$use_overlayfs"
fi
rm -f "$SYSTEM_STORE"/${ADGUARD_PERSONAL_INTERMEDIATE_HASH}.*
chown -R 0:0 "$SYSTEM_STORE"
chmod 755 "$SYSTEM_STORE"
chmod 644 "$SYSTEM_STORE"/* 2>/dev/null
chcon -R u:object_r:system_security_cacerts_file:s0 "$SYSTEM_STORE"
set_context /system/etc/security/cacerts "$SYSTEM_STORE"

# With meta-hybrid_mount active, register the serving rule once the system
# store is fully staged.
hybrid_record_rule

# APEX handling - no metamodule manages /apex (apexd owns the activation
# tree), so the module binds its own prepared store. The system store is bound
# in post-mount for the backends that need a module-provided view.
if [ -d /apex/com.android.conscrypt/cacerts ]; then
    if [ "$use_overlayfs" -eq 0 ]; then
        # Bind mount mode (Magisk / plain KernelSU): prepare a cleaned copy in
        # tmp and bind it over the conscrypt apex certificate directory.
        rm -rf "$TMP_STORE"
        mkdir -p "$TMP_STORE"
        cp -f /apex/com.android.conscrypt/cacerts/* "$TMP_STORE"/ 2>/dev/null
        copy_user_certificates "$SYSTEM_STORE" "$TMP_STORE"
        clean_removed_certificates "$TMP_STORE" 0
        rm -f "$TMP_STORE"/${ADGUARD_PERSONAL_INTERMEDIATE_HASH}.*
        chown -R 0:0 "$TMP_STORE"
        chmod 755 "$TMP_STORE"
        chmod 644 "$TMP_STORE"/* 2>/dev/null
        set_context /apex/com.android.conscrypt/cacerts "$TMP_STORE"
        bind_dir_if_needed "$TMP_STORE" /apex/com.android.conscrypt/cacerts
    else
        # Metamodule mode: stage the store copy in the module tree. The
        # previous contents are cleared each boot, and user certificates are
        # copied through copy_user_certificates so store whiteouts never leak
        # into a plain directory bind. No backends interpret /apex, so this
        # store is always staged without whiteouts.
        mkdir -p "$APEX_STORE"
        rm -rf "$APEX_STORE"/* 2>/dev/null
        cp -f /apex/com.android.conscrypt/cacerts/* "$APEX_STORE"/ 2>/dev/null
        copy_user_certificates "$SYSTEM_STORE" "$APEX_STORE"
        clean_removed_certificates "$APEX_STORE" 0
        rm -f "$APEX_STORE"/${ADGUARD_PERSONAL_INTERMEDIATE_HASH}.*
        chown -R 0:0 "$APEX_STORE"
        chmod 755 "$APEX_STORE"
        chmod 644 "$APEX_STORE"/* 2>/dev/null
        set_context /apex/com.android.conscrypt/cacerts "$APEX_STORE"
        if [ "$hybrid_active" -eq 1 ]; then
            # meta-hybrid_mount never serves this store; the live provider gets
            # zero-mount VFS rules built from it in post-mount, while a missing
            # provider falls back to the same bind. Staged as a plain file copy.
            :
        else
            bind_dir_if_needed "$APEX_STORE" /apex/com.android.conscrypt/cacerts
        fi
    fi
fi
