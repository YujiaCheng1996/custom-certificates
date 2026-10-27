#!/system/bin/sh

umask 022

CUSTOM_DIR=/data/misc/user/0/cacerts-custom
ADDED_DIR=/data/misc/user/0/cacerts-added
REMOVED_DIR=/data/misc/user/0/cacerts-removed
ADGUARD_HASH=47ec1af8
SYSTEM_CERT_DIR=/system/etc/security/cacerts
APEX_CERT_DIR=/apex/com.android.conscrypt/cacerts
# Fixed compromised set: these entries are always part of the removal set and
# cannot be taken out again through the WebUI.
FIXED_REMOVED_HASHES="869fbf79 b74d2bd5 dbff3a01 f459871d"
RESOLVED_DIR=

print_error() {
    printf 'ERR\t%s\n' "$1"
    exit 1
}

sanitize_name() {
    case "$1" in
        ""|*/*|*\\*|*..*)
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

resolve_bucket_dir() {
    case "$1" in
        custom)
            RESOLVED_DIR=$CUSTOM_DIR
            ;;
        added)
            RESOLVED_DIR=$ADDED_DIR
            ;;
        removed)
            RESOLVED_DIR=$REMOVED_DIR
            ;;
        *)
            return 1
            ;;
    esac

    return 0
}

is_protected_name() {
    case "$1" in
        "$ADGUARD_HASH".*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# A removal-set entry name is safe when it reduces to an eight-digit lowercase
# hex subject_hash_old. The boot-side collector relies on the same shape.
is_removal_entry_name() {
    hash=${1%.*}
    case $hash in
        [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f])
            ;;
        *)
            return 1
            ;;
    esac
    return 0
}

is_fixed_removed_name() {
    hash=${1%.*}
    case " $FIXED_REMOVED_HASHES " in
        *" $hash "*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

cleanup_temp_artifacts() {
    target_dir=$1
    [ -d "$target_dir" ] || return 0

    find "$target_dir" -mindepth 1 -maxdepth 1 -type f \
        \( -name '.tmp-pem.*' -o -name '.tmp-cert.*' -o -name '.tmp-save.*' \) \
        -exec rm -f {} + 2>/dev/null
}

apply_file_owner() {
    owner=$(stat -c '%u:%g' "$1" 2>/dev/null)
    if [ -n "$owner" ]; then
        chown "$owner" "$2" 2>/dev/null
    fi
    chmod 0644 "$2" 2>/dev/null
}

apply_file_context() {
    context=$(ls -Zd "$1" 2>/dev/null | awk 'NR==1 {print $1}')
    if [ -z "$context" ] || [ "$context" = "?" ]; then
        context=$(ls -Z "$1"/* 2>/dev/null | awk 'NR==1 {print $1}')
    fi

    if [ -n "$context" ] && [ "$context" != "?" ]; then
        chcon "$context" "$2" 2>/dev/null
    fi
}

print_file_base64() {
    base64 "$1" | tr -d '\n'
}

print_stdin_base64() {
    base64 | tr -d '\n'
}

extract_certificate_payload() {
    if grep -aq -- '-----BEGIN CERTIFICATE-----' "$1"; then
        awk '
            /-----BEGIN CERTIFICATE-----/ { inside = 1 }
            inside { print }
            /-----END CERTIFICATE-----/ { exit }
        ' "$1"
    else
        cat "$1"
    fi
}

download() {
    if command -v curl > /dev/null 2>&1; then
        curl --connect-timeout 10 -Ls "$1"
    else
        busybox wget -T 10 --no-check-certificate -qO - "$1"
    fi
}

print_list_bucket() {
    resolve_bucket_dir "$1" || return 1
    cleanup_temp_artifacts "$RESOLVED_DIR"

    if [ ! -d "$RESOLVED_DIR" ]; then
        return 0
    fi

    find "$RESOLVED_DIR" -mindepth 1 -maxdepth 1 -type f 2>/dev/null | LC_ALL=C sort | while IFS= read -r cert_path; do
        cert_name=$(basename "$cert_path")
        protected=0

        case "$cert_name" in
            .tmp-*)
                continue
                ;;
        esac

        case "$1" in
            added)
                is_protected_name "$cert_name" && protected=1
                ;;
            removed)
                # The fixed compromised set always stays part of the removal
                # set: the WebUI shows these entries locked.
                is_fixed_removed_name "$cert_name" && protected=1
                ;;
        esac

        printf 'ITEM\t%s\t%s\t%s\n' \
            "$1" \
            "$cert_name" \
            "$protected"
    done
}

# Browse the two system stores as served to the system: the popup source for
# adding removal-set entries. Only regular files are listed, so whiteout
# char devices from the served view never leak into the selection. protected=1
# marks entries already stored in the removal set. The fifth field carries the
# certificate payload as base64, so the WebUI can show each entry's
# subject/issuer without one bridge call per entry.
print_system_entries() {
    source_label=$1
    [ -d "$2" ] || return 0

    find "$2" -mindepth 1 -maxdepth 1 -type f 2>/dev/null | LC_ALL=C sort | while IFS= read -r cert_path; do
        cert_name=$(basename "$cert_path")
        protected=0

        case "$cert_name" in
            .tmp-*)
                continue
                ;;
        esac

        is_removal_entry_name "$cert_name" || continue

        if [ -e "$REMOVED_DIR/$cert_name" ] || is_fixed_removed_name "$cert_name"; then
            protected=1
        fi

        printf 'ITEM\t%s\t%s\t%s\t%s\n' \
            "$source_label" \
            "$cert_name" \
            "$protected" \
            "$(extract_certificate_payload "$cert_path" | print_stdin_base64)"
    done
}

# Copy one entry from a system store into the removal set. Same-name copies of
# the same certificate may exist across both stores; copying either is enough,
# so an existing entry is left untouched instead of overwritten.
do_add() {
    source_dir=
    case "$2" in
        system)
            source_dir=$SYSTEM_CERT_DIR
            ;;
        apex)
            source_dir=$APEX_CERT_DIR
            ;;
        *)
            print_error 'Unknown source directory'
            ;;
    esac

    sanitize_name "$3" || print_error 'Unsafe certificate name'
    is_removal_entry_name "$3" || print_error 'Not a certificate store entry name'

    if is_fixed_removed_name "$3"; then
        print_error 'The fixed compromised set is always part of the removal set'
    fi

    case "$3" in
        "$ADGUARD_HASH".*)
            print_error 'The AdGuard entry is dropped from the stores without a removal-set entry'
            ;;
    esac

    cert_path=$source_dir/$3
    [ -f "$cert_path" ] || print_error 'Certificate not found'

    if [ ! -d "$REMOVED_DIR" ]; then
        [ -d /data/misc/user/0 ] || print_error 'User data directory missing'
        mkdir -p "$REMOVED_DIR"
    fi

    final_path=$REMOVED_DIR/$3
    if [ ! -e "$final_path" ]; then
        cp -f "$cert_path" "$final_path" || print_error 'Add failed'
        apply_file_owner "$REMOVED_DIR" "$final_path"
        apply_file_context "$REMOVED_DIR" "$final_path"
    fi
    printf 'OK\t%s\t%s\n' "$2" "$3"
}

do_list() {
    printf 'OK\tbusybox\n'
    print_list_bucket custom
    print_list_bucket added
    print_list_bucket removed
}

# Surface the popup source for adding removal-set entries.
do_system_list() {
    printf 'OK\tbusybox\n'
    print_system_entries system "$SYSTEM_CERT_DIR"
    print_system_entries apex "$APEX_CERT_DIR"
}

do_read() {
    resolve_bucket_dir "$2" || print_error 'Unknown certificate bucket'
    cleanup_temp_artifacts "$RESOLVED_DIR"
    sanitize_name "$3" || print_error 'Unsafe certificate name'

    cert_path=$RESOLVED_DIR/$3
    [ -f "$cert_path" ] || print_error 'Certificate not found'

    printf 'OK\t%s\n' "$(extract_certificate_payload "$cert_path" | print_stdin_base64)"
}

do_download() {
    [ -n "$2" ] || print_error 'Missing URL'
    payload=$(download "$2" | print_stdin_base64) || print_error 'Download failed'
    [ -n "$payload" ] || print_error 'Downloaded content is empty'
    printf 'OK\t%s\n' "$payload"
}

do_move() {
    resolve_bucket_dir "$2" || print_error 'Unknown source bucket'
    source_dir=$RESOLVED_DIR
    cleanup_temp_artifacts "$source_dir"

    resolve_bucket_dir "$3" || print_error 'Unknown target bucket'
    target_dir=$RESOLVED_DIR
    cleanup_temp_artifacts "$target_dir"

    sanitize_name "$4" || print_error 'Unsafe certificate name'
    [ "$2" != "$3" ] || print_error 'Source and target are the same'
    if [ "$2" = "removed" ] || [ "$3" = "removed" ]; then
        print_error 'The removal store is managed through add and delete'
    fi

    source_path=$source_dir/$4
    target_path=$target_dir/$4

    [ -f "$source_path" ] || print_error 'Certificate not found'
    [ ! -e "$target_path" ] || print_error 'Target already contains the same filename'

    if [ "$3" = "custom" ] && is_protected_name "$4"; then
        print_error 'AdGuard Personal Intermediate must stay in cacerts-added'
    fi

    mkdir -p "$target_dir"
    mv "$source_path" "$target_path" || print_error 'Move failed'
    apply_file_owner "$target_dir" "$target_path"
    apply_file_context "$target_dir" "$target_path"
    printf 'OK\t%s\t%s\n' "$3" "$4"
}

do_save() {
    resolve_bucket_dir "$2" || print_error 'Unknown target bucket'
    if [ "$2" = "removed" ]; then
        print_error 'The removal store is managed through add and delete'
    fi
    target_dir=$RESOLVED_DIR
    cleanup_temp_artifacts "$target_dir"
    sanitize_name "$3" || print_error 'Unsafe filename'
    overwrite_mode=$5
    if [ -e "$target_dir/$3" ] && [ "$overwrite_mode" != "overwrite" ]; then
        print_error 'Target already contains the same filename'
    fi

    if [ "$2" = "custom" ] && is_protected_name "$3"; then
        print_error 'AdGuard Personal Intermediate must stay in cacerts-added'
    fi

    mkdir -p "$target_dir"
    final_path=$target_dir/$3
    tmp_path=$target_dir/.tmp-save.$$.$3
    printf '%s' "$4" | base64 -d >"$tmp_path" 2>/dev/null || {
        rm -f "$tmp_path"
        print_error 'Base64 decode failed'
    }
    mv -f "$tmp_path" "$final_path" 2>/dev/null || {
        rm -f "$tmp_path"
        print_error 'Save failed'
    }

    apply_file_owner "$target_dir" "$final_path"
    apply_file_context "$target_dir" "$final_path"
    printf 'OK\t%s\t%s\n' "$2" "$3"
}

do_delete() {
    resolve_bucket_dir "$2" || print_error 'Unknown target bucket'
    target_dir=$RESOLVED_DIR
    cleanup_temp_artifacts "$target_dir"
    sanitize_name "$3" || print_error 'Unsafe certificate name'

    if [ "$2" = "removed" ] && is_fixed_removed_name "$3"; then
        print_error 'The fixed compromised certificates always stay in the removal set'
    fi

    cert_path=$target_dir/$3
    [ -f "$cert_path" ] || print_error 'Certificate not found'
    rm -f "$cert_path" || print_error 'Delete failed'
    printf 'OK\t%s\t%s\n' "$2" "$3"
}

case "$1" in
    list)
        do_list
        ;;
    system)
        do_system_list
        ;;
    add)
        do_add "$@"
        ;;
    read)
        do_read "$@"
        ;;
    download)
        do_download "$@"
        ;;
    move)
        do_move "$@"
        ;;
    save)
        do_save "$@"
        ;;
    delete)
        do_delete "$@"
        ;;
    *)
        print_error 'Unknown command'
        ;;
esac
