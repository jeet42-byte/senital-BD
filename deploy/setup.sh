#!/usr/bin/env bash
# Sentinel-BD sensor: Cowrie honeypot + live phishing hunter on one Ubuntu VM.
#
#   sudo bash setup.sh            stage 1: install everything. Your SSH login
#                                 works on BOTH port 22 and port 22222; the
#                                 honeypot listens on 2222 (SSH) and 2323 (Telnet).
#   sudo bash setup.sh finalize   stage 2, only after logging in on 22222 works:
#                                 your login moves to 22222 only, the honeypot
#                                 takes over ports 22 and 23.
#   sudo bash setup.sh status     what is running, and the last shipments.
#   sudo bash setup.sh update     pull the latest code and restart services.
#   sudo bash setup.sh set-db     enter a new DATABASE_URL (e.g. after a password reset).
#
# Before stage 1, allow the new ports in the Azure firewall (Cloud Shell):
#   az vm open-port -g sentinel-bd -n sentinel-sensor-1 --port 23,2222,2323,22222 --priority 1010
#
# Tested on Ubuntu 24.04 LTS. Safe to run again.

set -euo pipefail

REPO_URL="https://github.com/jeet42-byte/senital-BD.git"
APP=/opt/sentinel-bd
DATA=/var/lib/sentinel-bd
ENV_DIR=/etc/sentinel-bd
ENV_FILE=$ENV_DIR/env
ADMIN_PORT=22222
SSHD_CONF=/etc/ssh/sshd_config.d/10-sentinel.conf
COWRIE_UID=999   # the "cowrie" user inside the cowrie/cowrie image

say()  { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\n\033[1;33m!!\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run with sudo: sudo bash $0 ${1:-}"
. /etc/os-release
[ "${ID:-}" = "ubuntu" ] || warn "Written for Ubuntu; continuing on ${PRETTY_NAME:-unknown}."

compose() { docker compose -f "$APP/deploy/docker-compose.yml" --env-file "$APP/deploy/.env" "$@"; }

write_sshd_conf() {
  # $1 = "both" (22 and ADMIN_PORT) or "admin" (ADMIN_PORT only)
  {
    echo "# Managed by Sentinel-BD setup.sh"
    [ "$1" = "both" ] && echo "Port 22"
    echo "Port $ADMIN_PORT"
    echo "PasswordAuthentication no"
    echo "KbdInteractiveAuthentication no"
    echo "PermitRootLogin no"
    echo "MaxAuthTries 3"
  } > "$SSHD_CONF"
  sshd -t || die "sshd config test failed; your current session is untouched. Fix $SSHD_CONF."
  # Ubuntu 24.04 starts sshd from ssh.socket, which ignores Port lines.
  # Run it as a normal service so both ports are honoured. Existing
  # sessions stay connected while this happens.
  if systemctl is-enabled ssh.socket >/dev/null 2>&1; then
    systemctl disable --now ssh.socket
  fi
  systemctl enable ssh.service >/dev/null 2>&1 || true
  systemctl restart ssh.service
}

# Ask for DATABASE_URL, check its shape, and prove it connects. On any
# failure the file is removed, so the next run asks again. The URL (which
# contains the password) is never printed.
configure_database() {
  mkdir -p "$ENV_DIR"
  id sentinel >/dev/null 2>&1 || useradd --system --home "$DATA" --shell /usr/sbin/nologin sentinel
  if [ ! -s "$ENV_FILE" ]; then
    echo "Paste your Neon DATABASE_URL (starts with postgresql://), then press Enter."
    echo "Nothing is shown while you paste. Paste it once only."
    read -rsp "DATABASE_URL: " db_url < /dev/tty; echo
    db_url="${db_url//$'\r'/}"
    local schemes
    schemes=$(grep -o '://' <<<"$db_url" | wc -l)
    if [[ "$db_url" != postgres* || "$schemes" -ne 1 || "$db_url" =~ [[:space:]] || "$db_url" == *"'"* ]]; then
      die "That doesn't look like one PostgreSQL URL (was it pasted twice?). Run the same command again."
    fi
    umask 077
    # Quoted: Neon URLs contain '&', which a shell would otherwise act on.
    printf "DATABASE_URL='%s'\n" "$db_url" > "$ENV_FILE"
    umask 022
  fi
  chown root:sentinel "$ENV_FILE" && chmod 640 "$ENV_FILE"
  if ! sudo -u sentinel bash -c "set -a; . '$ENV_FILE'; cd '$APP' && exec .venv/bin/python -c '
import re, sys
try:
    from sentinel.db import init_db
    init_db()
except Exception as exc:
    text = re.sub(r\"://[^@/\\s]+@\", \"://***@\", str(exc).splitlines()[0])
    text = re.sub(r\"npg_[A-Za-z0-9]+\", \"***\", text)
    sys.exit(f\"{type(exc).__name__}: {text[:300]}\")
print(\"database reachable\")
'"; then
    rm -f "$ENV_FILE"
    die "Could not connect with that URL (details above, password hidden). Run the same command again to re-enter it."
  fi
}

stage_install() {
  say "Swap (the VM has 1 GB of RAM)"
  if ! swapon --show | grep -q .; then
    fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
    grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  fi

  say "Packages and automatic security updates"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq git python3-venv python3-pip docker.io docker-compose-v2 ufw unattended-upgrades >/dev/null
  dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null
  systemctl enable --now docker >/dev/null

  say "Admin SSH on ports 22 and $ADMIN_PORT (keys only, no root)"
  write_sshd_conf both

  say "Host firewall"
  ufw default deny incoming >/dev/null
  ufw default allow outgoing >/dev/null
  for port in 22 23 2222 2323 "$ADMIN_PORT"; do ufw allow "$port/tcp" >/dev/null; done
  ufw --force enable >/dev/null

  say "Sentinel-BD code in $APP"
  id sentinel >/dev/null 2>&1 || useradd --system --home "$DATA" --shell /usr/sbin/nologin sentinel
  if [ -d "$APP/.git" ]; then
    git -C "$APP" pull -q --ff-only
  else
    git clone -q "$REPO_URL" "$APP"
  fi
  python3 -m venv "$APP/.venv"
  "$APP/.venv/bin/pip" install -q --upgrade pip
  "$APP/.venv/bin/pip" install -q -r "$APP/requirements.txt"

  say "Database connection"
  configure_database
  # Mark that stage 1 got this far (used by `set-db`).
  touch "$ENV_DIR/.installed"

  say "Data folders"
  mkdir -p "$DATA/cowrie/log" "$DATA/cowrie/downloads" "$DATA/state"
  chown -R "$COWRIE_UID:$COWRIE_UID" "$DATA/cowrie"
  chmod 755 "$DATA" "$DATA/cowrie" "$DATA/cowrie/log"
  chown sentinel:sentinel "$DATA/state"

  say "Honeypot and certificate stream containers"
  [ -f "$APP/deploy/.env" ] || printf 'COWRIE_SSH_PORT=2222\nCOWRIE_TELNET_PORT=2323\n' > "$APP/deploy/.env"
  compose pull -q
  compose up -d

  say "Services: live phishing hunter, honeypot shipper every 5 minutes"
  cp "$APP"/deploy/systemd/sentinel-* /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now sentinel-hunter.service sentinel-ship.timer >/dev/null

  say "Daily clean-up of old logs and captured files"
  cat > /etc/cron.daily/sentinel-cleanup <<'CRON'
#!/bin/sh
find /var/lib/sentinel-bd/cowrie/log -name 'cowrie.*.20*' -mtime +14 -delete
find /var/lib/sentinel-bd/cowrie/downloads -type f -mtime +7 -delete
CRON
  chmod 755 /etc/cron.daily/sentinel-cleanup

  # The VM's public IP, from Azure's own metadata service (never leaves Azure).
  ip=$(curl -fsS -m 3 -H Metadata:true \
    "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2021-02-01&format=text" \
    2>/dev/null || true)
  ip=${ip:-<your-vm-ip>}
  say "Stage 1 done."
  cat <<EOF

  Now, in a NEW terminal (keep this one open), check you can log in on the admin port:

      ssh -p $ADMIN_PORT azureuser@$ip

  If that works, finish with:

      sudo bash $APP/deploy/setup.sh finalize

  If it does not, the Azure firewall is probably closed; run in Cloud Shell:
      az vm open-port -g sentinel-bd -n sentinel-sensor-1 --port 23,2222,2323,22222 --priority 1010
EOF
}

stage_finalize() {
  [ -f "$APP/deploy/.env" ] || die "Run stage 1 first: sudo bash $0"
  warn "After this, port 22 belongs to the honeypot and you can only log in on port $ADMIN_PORT."
  read -rp "Have you confirmed 'ssh -p $ADMIN_PORT azureuser@<ip>' works from another terminal? Type yes: " ok < /dev/tty
  [ "$ok" = "yes" ] || die "Stopped. Nothing changed."

  say "Admin SSH on port $ADMIN_PORT only"
  write_sshd_conf admin

  say "Honeypot takes over ports 22 (SSH) and 23 (Telnet)"
  printf 'COWRIE_SSH_PORT=22\nCOWRIE_TELNET_PORT=23\n' > "$APP/deploy/.env"
  compose up -d
  ufw delete allow 2222/tcp >/dev/null || true
  ufw delete allow 2323/tcp >/dev/null || true

  say "Done. From now on, log in with:  ssh -p $ADMIN_PORT azureuser@<vm-ip>"
  echo "Port 22 is the honeypot. Attackers usually arrive within minutes."
}

stage_status() {
  say "Containers";      compose ps || true
  say "Services";        systemctl --no-pager --lines=0 status sentinel-hunter.service sentinel-ship.timer || true
  say "Last shipments";  journalctl -u sentinel-ship.service -n 8 --no-pager -o cat || true
  say "Hunter log";      journalctl -u sentinel-hunter.service -n 8 --no-pager -o cat || true
  say "Honeypot log";    ls -la "$DATA/cowrie/log" 2>/dev/null || true
  say "Listening ports"; ss -tlnp | awk 'NR==1 || /:(22|23|2222|2323|22222|8080) /'
}

stage_update() {
  git -C "$APP" pull --ff-only
  "$APP/.venv/bin/pip" install -q -r "$APP/requirements.txt"
  cp "$APP"/deploy/systemd/sentinel-* /etc/systemd/system/
  systemctl daemon-reload
  compose pull -q && compose up -d
  systemctl restart sentinel-hunter.service
  say "Updated."
}

case "${1:-install}" in
  install)  stage_install ;;
  finalize) stage_finalize ;;
  status)   stage_status ;;
  update)   stage_update ;;
  set-db)   rm -f "$ENV_FILE"; configure_database
            systemctl restart sentinel-hunter.service 2>/dev/null || true
            say "Database updated." ;;
  *) die "Unknown command '$1'. Use: install | finalize | status | update | set-db" ;;
esac
