#!/system/bin/sh

umask 022

CUSTOM_DIR=/data/misc/user/0/cacerts-custom
ADDED_DIR=/data/misc/user/0/cacerts-added
ADGUARD_HASH=47ec1af8
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
            .tmp-pem.*|.tmp-cert.*|.tmp-save.*)
                continue
                ;;
        esac

        if [ "$1" = "added" ] && is_protected_name "$cert_name"; then
            protected=1
        fi

        printf 'ITEM\t%s\t%s\t%s\n' \
            "$1" \
            "$cert_name" \
            "$protected"
    done
}

do_list() {
    printf 'OK\tbusybox\n'
    print_list_bucket custom
    print_list_bucket added
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

    cert_path=$target_dir/$3
    [ -f "$cert_path" ] || print_error 'Certificate not found'
    rm -f "$cert_path" || print_error 'Delete failed'
    printf 'OK\t%s\t%s\n' "$2" "$3"
}

case "$1" in
    list)
        do_list
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
