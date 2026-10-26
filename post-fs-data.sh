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

ADGUARD_PERSONAL_INTERMEDIATE_HASH=47ec1af8
CUSTOM_DIR=/data/misc/user/0/cacerts-custom
ADDED_DIR=/data/misc/user/0/cacerts-added
SYSTEM_STORE=$MODDIR/system/etc/security/cacerts
APEX_STORE=$MODDIR/apex/com.android.conscrypt/cacerts
TMP_STORE=/data/local/tmp/custom-certificates-cacerts
KAGAMI_MODULES_DIR=/data/adb/modules/kagami
KAGAMI_DATA_DIR=/data/adb/kagami

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

# Run detection ONCE at startup
detect_overlayfs
detect_kagami_kasumi

# Remove the compromised eMudhra certificates known by subject_hash_old prefix.
# use_whiteouts=1 additionally leaves a whiteout char device (mknod c 0 0) with
# the original file name so that mount layers which interpret whiteouts
# (OverlayFS, Magic Mount) hide the lower-layer file.
clean_emudhra_certificates() {
    target_dir=$1
    use_whiteouts=$2

    for hash in $EMUDHRA_HASHES; do
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
# Remove compromised eMudhra certificates from system store. Whiteouts are only
# staged for mount layers that interpret them (OverlayFS / Magic Mount); a
# directory bind view would just list them as device files.
if [ "$kagami_kasumi" -eq 1 ]; then
    clean_emudhra_certificates "$SYSTEM_STORE" 0
else
    clean_emudhra_certificates "$SYSTEM_STORE" "$use_overlayfs"
fi
rm -f "$SYSTEM_STORE"/${ADGUARD_PERSONAL_INTERMEDIATE_HASH}.*
chown -R 0:0 "$SYSTEM_STORE"
chmod 755 "$SYSTEM_STORE"
chmod 644 "$SYSTEM_STORE"/* 2>/dev/null
chcon -R u:object_r:system_security_cacerts_file:s0 "$SYSTEM_STORE"
set_context /system/etc/security/cacerts "$SYSTEM_STORE"

# APEX handling - Kagami and the meta-* metamodules do not manage /apex, so the
# module binds its own prepared store; post-mount binds the system store.
if [ -d /apex/com.android.conscrypt/cacerts ]; then
    if [ "$use_overlayfs" -eq 0 ]; then
        # Bind mount mode (Magisk / plain KernelSU): prepare a cleaned copy in
        # tmp and bind it over the conscrypt apex certificate directory.
        rm -rf "$TMP_STORE"
        mkdir -p "$TMP_STORE"
        cp -f /apex/com.android.conscrypt/cacerts/* "$TMP_STORE"/ 2>/dev/null
        copy_user_certificates "$SYSTEM_STORE" "$TMP_STORE"
        clean_emudhra_certificates "$TMP_STORE" 0
        rm -f "$TMP_STORE"/${ADGUARD_PERSONAL_INTERMEDIATE_HASH}.*
        chown -R 0:0 "$TMP_STORE"
        chmod 755 "$TMP_STORE"
        chmod 644 "$TMP_STORE"/* 2>/dev/null
        set_context /apex/com.android.conscrypt/cacerts "$TMP_STORE"
        bind_dir_if_needed "$TMP_STORE" /apex/com.android.conscrypt/cacerts
    else
        # Metamodule mode: stage the store copy in the module tree. The
        # previous contents are cleared each boot, and user certificates are
        # copied through copy_user_certificates so store whiteouts (meaningful
        # to mount layers only) never leak into a plain directory bind.
        mkdir -p "$APEX_STORE"
        rm -rf "$APEX_STORE"/* 2>/dev/null
        cp -f /apex/com.android.conscrypt/cacerts/* "$APEX_STORE"/ 2>/dev/null
        copy_user_certificates "$SYSTEM_STORE" "$APEX_STORE"
        if meta_hybrid_handles_apex; then
            clean_emudhra_certificates "$APEX_STORE" 1
        else
            clean_emudhra_certificates "$APEX_STORE" 0
        fi
        rm -f "$APEX_STORE"/${ADGUARD_PERSONAL_INTERMEDIATE_HASH}.*
        chown -R 0:0 "$APEX_STORE"
        chmod 755 "$APEX_STORE"
        chmod 644 "$APEX_STORE"/* 2>/dev/null
        set_context /apex/com.android.conscrypt/cacerts "$APEX_STORE"
        bind_dir_if_needed "$APEX_STORE" /apex/com.android.conscrypt/cacerts
    fi
fi
