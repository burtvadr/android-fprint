#!/usr/bin/env bash
# Install or roll back the phone authenticator in the GNOME/gdm-password stack.
#
# This is intentionally scoped to gdm-password. It does not touch system-auth,
# sshd, su or gdm-fingerprint. gdm-password is used by both the GDM password
# login and the GNOME screen lock, so it is the smallest end-to-end test.
#
# Run with sudo. Keep a root TTY open while testing.
set -euo pipefail

VENDOR="/usr/lib/pam.d/gdm-password"
TARGET="/etc/pam.d/gdm-password"
RECORD="/etc/pam.d/.gdm-password.phone.rollback"
LINE="auth        sufficient    pam_phone_auth.so purpose=gdm timeout_ms=15000"

usage() {
    cat <<EOF
Usage: sudo $0 [--dry-run] [--rollback]

  --dry-run    show the proposed change and exit
  --rollback   restore the file saved by the last install

The change is a local /etc/pam.d/gdm-password override. It adds one
sufficient line before the existing auth stack and preserves everything else.
It does not modify /etc/pam.d/system-auth.
EOF
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "Run this with sudo/root." >&2
        exit 1
    fi
}

rollback() {
    require_root
    if [ ! -f "$RECORD" ]; then
        echo "No rollback record at $RECORD." >&2
        echo "Restore your own gdm-password backup manually." >&2
        exit 1
    fi
    # shellcheck disable=SC1090
    . "$RECORD"
    if [ "${PHONE_BACKUP:-absent}" = "absent" ]; then
        rm -f "$TARGET"
        echo "Removed $TARGET (it did not exist before install)."
    else
        cp -a "$PHONE_BACKUP" "$TARGET"
        echo "Restored $TARGET from $PHONE_BACKUP."
    fi
    rm -f "$RECORD"
    echo "GNOME will use the restored PAM stack on the next authentication."
}

main() {
    local dry_run=0
    case "${1:-}" in
        "") ;;
        --dry-run) dry_run=1 ;;
        --rollback) rollback; return ;;
        -h|--help) usage; return ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac

    require_root

    if [ -f "$TARGET" ] && grep -q 'pam_phone_auth\.so' "$TARGET"; then
        echo "$TARGET already contains a phone-auth line; nothing to do."
        exit 0
    fi

    if [ ! -f "$VENDOR" ]; then
        echo "Missing vendor file $VENDOR." >&2
        exit 1
    fi

    local base="$VENDOR"
    [ -f "$TARGET" ] && base="$TARGET"

    local tmp
    tmp="$(mktemp)"
    trap 'rm -f "$tmp"' EXIT

    if ! awk -v line="$LINE" '
        BEGIN { inserted = 0 }
        /^[[:space:]]*auth[[:space:]]+include[[:space:]]+system-local-login[[:space:]]*$/ && !inserted {
            print line
            inserted = 1
        }
        { print }
        END { if (!inserted) exit 42 }
    ' "$base" > "$tmp"; then
        echo "Could not find 'auth include system-local-login' in $base." >&2
        echo "No change made. Inspect the file before trying a manual edit." >&2
        exit 1
    fi

    echo "==> proposed change"
    diff -u "$base" "$tmp" || true

    if [ "$dry_run" -eq 1 ]; then
        echo
        echo "Dry run only; no files changed."
        exit 0
    fi

    local backup="absent"
    if [ -f "$TARGET" ]; then
        backup="$TARGET.bak.$(date +%Y%m%d-%H%M%S)"
        cp -a "$TARGET" "$backup"
    fi

    install -m 0644 -o root -g root "$tmp" "$TARGET"
    {
        echo "PHONE_BACKUP=$backup"
    } > "$RECORD"
    chmod 0600 "$RECORD"

    echo
    echo "Installed the phone line in $TARGET."
    if [ "$backup" != "absent" ]; then
        echo "Backup: $backup"
    else
        echo "There was no local override before; rollback will remove $TARGET."
    fi
    echo "Rollback: sudo $0 --rollback"
    echo
    echo "Keep a root TTY open. Then test:"
    echo "  1. Lock the screen with Super+L."
    echo "  2. Press Enter or submit the password form."
    echo "  3. Approve the phone prompt."
    echo "  4. If it fails, switch to a TTY and run: sudo $0 --rollback"
}

main "${1:-}"
