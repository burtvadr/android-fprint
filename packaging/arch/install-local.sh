#!/usr/bin/env bash
# Install the local Android authenticator for Arch Linux.
#
# Run as root:
#   sudo ./packaging/arch/install-local.sh \
#       --state-from /tmp/alp-live/state
#
# The optional --state-from preserves an existing pairing (host key and
# certificate pin). Without it the daemon starts fresh and the phone must pair
# again.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATE_FROM=""
PAM_FILE="/etc/pam.d/sudo"
PAM_LINE="auth        sufficient    pam_phone_auth.so purpose=sudo"

usage() {
    cat <<EOF
Usage: sudo $0 [--state-from DIR]

  --state-from DIR   copy host.id, host.key, host.crt, host-tls.key and
                     registry.json from DIR into /var/lib/phone-authd
                     (only when the target state directory is empty)

This installs:
  /usr/libexec/phone-authd
  /usr/local/bin/phone-authctl
  /usr/lib/security/pam_phone_auth.so
  /etc/systemd/system/phone-authd.service
  one PAM line in $PAM_FILE

It does not touch /etc/pam.d/system-auth.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --state-from)
            [ "$#" -ge 2 ] || { echo "--state-from needs a directory" >&2; exit 2; }
            STATE_FROM="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this with sudo/root." >&2
    exit 1
fi

for f in \
    "$ROOT/linux/target/release/phone-authd" \
    "$ROOT/linux/target/release/phone-authctl" \
    "$ROOT/linux/target/release/libpam_phone_auth.so"; do
    [ -x "$f" ] || {
        echo "missing $f" >&2
        echo "Build it first as your normal user: make release" >&2
        exit 1
    }
done

if [ -n "$STATE_FROM" ] && [ ! -d "$STATE_FROM" ]; then
    echo "state directory does not exist: $STATE_FROM" >&2
    exit 1
fi

echo "==> creating the phone-auth account"
if ! getent group phone-auth >/dev/null; then
    groupadd --system phone-auth
fi
if ! id -u phone-auth >/dev/null 2>&1; then
    useradd --system \
        --gid phone-auth \
        --home-dir /var/lib/phone-authd \
        --no-create-home \
        --shell /usr/bin/nologin \
        phone-auth
fi

echo "==> installing binaries"
install -Dm0755 "$ROOT/linux/target/release/phone-authd" /usr/libexec/phone-authd
install -Dm0755 "$ROOT/linux/target/release/phone-authctl" /usr/local/bin/phone-authctl
install -Dm0755 "$ROOT/linux/target/release/libpam_phone_auth.so" \
    /usr/lib/security/pam_phone_auth.so

echo "==> installing the service"
install -Dm0644 "$ROOT/linux/systemd/phone-authd.service" \
    /etc/systemd/system/phone-authd.service

echo "==> preparing state and log directories"
install -d -o phone-auth -g phone-auth -m 0700 /var/lib/phone-authd
install -d -o phone-auth -g phone-auth -m 0750 /var/log/phone-authd

if [ -n "$STATE_FROM" ]; then
    if find /var/lib/phone-authd -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
        echo "state directory is not empty; refusing to overwrite it with $STATE_FROM" >&2
        echo "remove /var/lib/phone-authd manually if you really want to replace it" >&2
        exit 1
    fi
    echo "==> migrating the existing pairing from $STATE_FROM"
    for f in host.id host.key host.crt host-tls.key registry.json; do
        if [ -f "$STATE_FROM/$f" ]; then
            install -o phone-auth -g phone-auth -m 0600 "$STATE_FROM/$f" \
                "/var/lib/phone-authd/$f"
        fi
    done
fi

if ss -ltn 'sport = :47123' 2>/dev/null | grep -q LISTEN; then
    # An upgrade runs while the old service is still listening. Stop our own
    # service first; refuse only if some other process owns the port.
    if systemctl is-active --quiet phone-authd 2>/dev/null; then
        echo "==> stopping the existing phone-authd service"
        systemctl stop phone-authd
    fi
fi

if ss -ltn 'sport = :47123' 2>/dev/null | grep -q LISTEN; then
    echo "port 47123 is already in use by another process; stop it first:" >&2
    ss -ltnp 'sport = :47123' >&2 || true
    exit 1
fi

echo "==> enabling and starting phone-authd"
systemctl daemon-reload
systemctl enable phone-authd
systemctl restart phone-authd

for _ in $(seq 1 40); do
    if [ -S /run/phone-authd/control.sock ]; then
        break
    fi
    sleep 0.25
done
if [ ! -S /run/phone-authd/control.sock ]; then
    echo "phone-authd did not create /run/phone-authd/control.sock" >&2
    systemctl --no-pager --full status phone-authd >&2 || true
    exit 1
fi

echo "==> allowing the desktop user to use the control socket"
if ! id -nG desktop | tr ' ' '\n' | grep -qx phone-auth; then
    usermod -aG phone-auth desktop
    echo "added desktop to the phone-auth group; a new login is needed for"
    echo "unprivileged phone-authctl access. Root/PAM can already connect."
fi

echo "==> adding the PAM hook to $PAM_FILE"
if grep -q 'pam_phone_auth\.so' "$PAM_FILE"; then
    echo "PAM hook already present; leaving it alone"
else
    backup="$PAM_FILE.bak.$(date +%Y%m%d-%H%M%S)"
    cp -a "$PAM_FILE" "$backup"
    tmp="$(mktemp)"
    if ! awk -v line="$PAM_LINE" '
        BEGIN { inserted = 0 }
        /^[[:space:]]*auth[[:space:]]+include[[:space:]]+system-auth[[:space:]]*$/ && !inserted {
            print line
            inserted = 1
        }
        { print }
        END { if (!inserted) exit 42 }
    ' "$PAM_FILE" > "$tmp"; then
        rm -f "$tmp"
        echo "could not find 'auth include system-auth' in $PAM_FILE" >&2
        echo "restore is available at $backup" >&2
        exit 1
    fi
    install -m 0644 -o root -g root "$tmp" "$PAM_FILE"
    rm -f "$tmp"
    echo "backup: $backup"
fi

echo
echo "==> installed"
systemctl --no-pager --full status phone-authd | sed -n '1,12p'
echo
echo "Pair from the phone if this is a fresh state:"
echo "  phone-authctl pair"
echo
echo "Then test (the phone should prompt):"
echo "  sudo -k && sudo -v"
