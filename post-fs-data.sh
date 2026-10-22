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

# Run detection ONCE at startup
detect_overlayfs

clean_emudhra_certificates() {
    target_dir=$1

    # use_overlayfs is already set globally by detect_overlayfs()

    # Match by subject_hash_old prefix (filename before the dot)
    for hash in $EMUDHRA_HASHES; do
        for certificate in "$target_dir"/$hash.*; do
            [ -f "$certificate" ] || continue
            cert_name=$(basename "$certificate")
            rm -f "$certificate"

            # For overlayfs: create whiteout file to hide lower layer file
            if [ "$use_overlayfs" -eq 1 ]; then
                mknod "$target_dir/$cert_name" c 0 0 2>/dev/null
            fi
        done
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
# Remove compromised eMudhra certificates from system store
clean_emudhra_certificates "$SYSTEM_STORE"
rm -f "$SYSTEM_STORE"/${ADGUARD_PERSONAL_INTERMEDIATE_HASH}.*
chown -R 0:0 "$SYSTEM_STORE"
chmod 755 "$SYSTEM_STORE"
chmod 644 "$SYSTEM_STORE"/* 2>/dev/null
chcon -R u:object_r:system_security_cacerts_file:s0 "$SYSTEM_STORE"
set_context /system/etc/security/cacerts "$SYSTEM_STORE"

# APEX handling - depends on use_overlayfs
if [ -d /apex/com.android.conscrypt/cacerts ]; then
    if [ "$use_overlayfs" -eq 1 ]; then
        # OverlayFS mode: prepare in module directory, metamodule will overlay
        APEX_STORE=$MODDIR/apex/com.android.conscrypt/cacerts
        mkdir -p "$APEX_STORE"
        cp -f /apex/com.android.conscrypt/cacerts/* "$APEX_STORE"/ 2>/dev/null
        cp -f "$SYSTEM_STORE"/* "$APEX_STORE"/ 2>/dev/null
        clean_emudhra_certificates "$APEX_STORE"
        rm -f "$APEX_STORE"/${ADGUARD_PERSONAL_INTERMEDIATE_HASH}.*
        chown -R 0:0 "$APEX_STORE"
        chmod 755 "$APEX_STORE"
        chmod 644 "$APEX_STORE"/* 2>/dev/null
        set_context /apex/com.android.conscrypt/cacerts "$APEX_STORE"
    else
        # Bind mount mode (Magisk): prepare in tmp, but Magisk handles mounting
        # We still prepare the cleaned certs here for completeness
        rm -rf /data/local/tmp/custom-certificates-cacerts
        mkdir -p /data/local/tmp/custom-certificates-cacerts
        cp -f /apex/com.android.conscrypt/cacerts/* /data/local/tmp/custom-certificates-cacerts/ 2>/dev/null
        cp -f "$SYSTEM_STORE"/* /data/local/tmp/custom-certificates-cacerts/ 2>/dev/null
        clean_emudhra_certificates /data/local/tmp/custom-certificates-cacerts
        rm -f /data/local/tmp/custom-certificates-cacerts/${ADGUARD_PERSONAL_INTERMEDIATE_HASH}.*
        chown -R 0:0 /data/local/tmp/custom-certificates-cacerts
        chmod 755 /data/local/tmp/custom-certificates-cacerts
        chmod 644 /data/local/tmp/custom-certificates-cacerts/* 2>/dev/null
        set_context /apex/com.android.conscrypt/cacerts /data/local/tmp/custom-certificates-cacerts
        mount --bind /data/local/tmp/custom-certificates-cacerts /apex/com.android.conscrypt/cacerts
    fi
fi
