#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Install the health-check report generator on Ubuntu 22.04 / 24.04.
#
#   git clone https://github.com/Bogan1011/automated-report.git
#   cd automated-report
#   ./deploy/install.sh              # OCR reader, watch folder, upload website, services
#   ./deploy/install.sh --port=8090  # website port (default 8090; next free port if taken)
#   ./deploy/install.sh --no-web     # no website, watch folder only
#   ./deploy/install.sh --samba      # + Windows share  \\<vm-ip>\healthcheck
#   ./deploy/install.sh --with-ai    # + local AI model (Ollama, qwen2.5vl:3b) for what OCR misses
#
# Run as root or as a normal user with sudo:
#   * as root   - services run as a locked-down system user 'tmhc' (or --user=NAME),
#                 program in /opt/tmhc, data in /var/lib/tmhc/healthcheck
#   * as a user - services run as that user, data in ~/healthcheck
# Safe to run again (e.g. after `git pull`) - it updates the program and keeps
# your settings, logins and client folders.
# Nothing is sent anywhere: the only downloads are Ubuntu/Python packages
# (and the Ollama model with --with-ai).
# ---------------------------------------------------------------------------
set -euo pipefail

SAMBA=0; WITH_AI=0; NONINTERACTIVE=0; NO_SERVICE=0; WEB=1; PORT=8090; PORT_SET=0
INBOX_ROOT=""; AI_MODEL="qwen2.5vl:3b"; RUN_USER=""
for arg in "$@"; do
  case "$arg" in
    --samba) SAMBA=1 ;;
    --with-ai) WITH_AI=1 ;;
    --yes|-y) NONINTERACTIVE=1 ;;
    --no-service) NO_SERVICE=1 ;;
    --no-web) WEB=0 ;;
    --port=*) PORT="${arg#*=}"; PORT_SET=1 ;;
    --root=*) INBOX_ROOT="${arg#*=}" ;;
    --user=*) RUN_USER="${arg#*=}" ;;
    --model=*) AI_MODEL="${arg#*=}" ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg"; exit 2 ;;
  esac
done

say()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mxx\033[0m %s\n' "$*"; exit 1; }

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE=/etc/systemd/system/tmhc-watch.service
WEB_SERVICE=/etc/systemd/system/tmhc-web.service

if [ "$(id -u)" -eq 0 ]; then
  # ------------------------------------------------------------ system mode
  MODE=system
  SUDO=""
  RUN_USER="${RUN_USER:-tmhc}"
  APP_DIR=/opt/tmhc
  VENV="$APP_DIR/venv"
  if ! id "$RUN_USER" >/dev/null 2>&1; then
    [ "$RUN_USER" = tmhc ] || die "user $RUN_USER does not exist"
    useradd --system --home-dir /var/lib/tmhc --create-home --shell /usr/sbin/nologin tmhc
  fi
  RUN_HOME="$(getent passwd "$RUN_USER" | cut -d: -f6)"
  INBOX_ROOT="${INBOX_ROOT:-$RUN_HOME/healthcheck}"
  WORKDIR="$INBOX_ROOT"
  AS() { runuser -u "$RUN_USER" -- "$@"; }
else
  # ------------------------------------------------------------ user mode
  MODE=user
  command -v sudo >/dev/null || die "run as root, or install sudo"
  SUDO=sudo
  [ -z "$RUN_USER" ] || [ "$RUN_USER" = "$(id -un)" ] || die "--user is only for root installs"
  RUN_USER="$(id -un)"
  RUN_HOME="$HOME"
  VENV="$REPO/.venv"
  INBOX_ROOT="${INBOX_ROOT:-$HOME/healthcheck}"
  WORKDIR="$REPO"
  AS() { "$@"; }
fi
PY="$VENV/bin/python"
CONFIG="$INBOX_ROOT/config.yaml"
# run python as the service user, from a directory it can read
RUNPY() { ( cd "$WORKDIR" && AS "$PY" "$@" ); }

. /etc/os-release 2>/dev/null || true
[ "${ID:-}" = "ubuntu" ] || warn "tested on Ubuntu 22.04/24.04; you are on ${PRETTY_NAME:-unknown} - continuing"
MEM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
say "Machine: $(nproc) vCPU, ${MEM_MB} MB RAM.  Install mode: $MODE (services run as '$RUN_USER')"
if [ "$WITH_AI" = 1 ] && [ "$MEM_MB" -lt 7000 ]; then
  warn "less than 7 GB RAM: the local AI model may not fit. OCR alone works fine."
fi

# ---------------------------------------------------------------- packages
say "Installing Ubuntu packages (Python, Tesseract OCR$( [ "$SAMBA" = 1 ] && echo ', Samba'))"
PKGS="python3 python3-venv python3-pip tesseract-ocr tesseract-ocr-eng git curl"
[ "$SAMBA" = 1 ] && PKGS="$PKGS samba"
$SUDO apt-get update -qq
$SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $PKGS >/dev/null
tesseract --version | head -1

# ---------------------------------------------------------------- python env
say "Python environment in $VENV"
[ "$MODE" = system ] && mkdir -p "$APP_DIR" && chmod 755 "$APP_DIR"
[ -x "$PY" ] || python3 -m venv "$VENV"
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q -r "$REPO/requirements.txt"
if [ "$MODE" = system ]; then
  # the program is installed into the venv, so the services never read /root
  "$VENV/bin/pip" install -q --no-deps --force-reinstall "$REPO"
fi

say "Self-test"
( cd "$REPO" && "$PY" -m pytest -q -p no:cacheprovider 2>&1 | tail -1 )

# ---------------------------------------------------------------- data folder + config
mkdir -p "$INBOX_ROOT/inbox"
[ "$MODE" = system ] && chown -R "$RUN_USER:" "$INBOX_ROOT" && chmod 750 "$INBOX_ROOT"
if [ ! -f "$CONFIG" ]; then
  say "Creating $CONFIG"
  RUNPY -c "import sys; from pathlib import Path; from tmhc.watch import load_config; load_config(Path(sys.argv[1]))" "$CONFIG"
  if [ "$NONINTERACTIVE" = 0 ] && [ -t 0 ]; then
    echo "Names printed in every report (you can change them later on the website, Settings):"
    read -r -p "  Prepared by: " PREP
    read -r -p "  Approved by: " APPR
    read -r -p "  Account owner: " OWNER
    read -r -s -p "  Password of the logs zip (same for every client; blank if none): " ZIPPW; echo
    ( cd "$WORKDIR" && AS env PREP="$PREP" APPR="$APPR" OWNER="$OWNER" ZIPPW="$ZIPPW" "$PY" - "$CONFIG" <<'PYCFG'
import os, sys, yaml
p = sys.argv[1]
cfg = yaml.safe_load(open(p))
d = cfg.setdefault("defaults", {})
for env, key in (("PREP", "prepared_by"), ("APPR", "approved_by"), ("OWNER", "account_owner"), ("ZIPPW", "zip_password")):
    v = os.environ.get(env, "").strip()
    if v or key == "zip_password":
        d[key] = v
if d.get("prepared_by"):
    d["trend_attendance"] = d["prepared_by"]
cfg["inbox"] = str(cfg["inbox"])
open(p, "w").write("# Health-check settings (the website edits this file)\n" +
                   yaml.safe_dump(cfg, sort_keys=False, allow_unicode=True))
PYCFG
    )
  fi
else
  say "Keeping existing $CONFIG"
fi
chmod 600 "$CONFIG"   # holds the zip password and login hashes

# ---------------------------------------------------------------- `tmhc` command
say "Installing the 'tmhc' command"
if [ "$MODE" = system ]; then
  $SUDO tee /usr/local/bin/tmhc >/dev/null <<EOF
#!/bin/sh
# runs the health-check tool as the service user, e.g.  tmhc web --set-password alice
cd "$WORKDIR" || exit 1
exec runuser -u "$RUN_USER" -- "$PY" -m tmhc "\$@"
EOF
else
  $SUDO tee /usr/local/bin/tmhc >/dev/null <<EOF
#!/bin/sh
cd "$REPO" || exit 1
exec "$PY" -m tmhc "\$@"
EOF
fi
$SUDO chmod 755 /usr/local/bin/tmhc

# ---------------------------------------------------------------- local AI (optional)
if [ "$WITH_AI" = 1 ]; then
  say "Local AI: Ollama + $AI_MODEL (runs on this VM only, listens on 127.0.0.1)"
  SWAP_MB=$(awk '/SwapTotal/ {print int($2/1024)}' /proc/meminfo)
  if [ "$SWAP_MB" -lt 2000 ] && [ ! -f /swapfile ]; then
    say "Adding a 4 GB swap file (the model and OCR together are tight in 8 GB)"
    $SUDO fallocate -l 4G /swapfile && $SUDO chmod 600 /swapfile && $SUDO mkswap /swapfile >/dev/null && $SUDO swapon /swapfile
    grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' | $SUDO tee -a /etc/fstab >/dev/null
  fi
  command -v ollama >/dev/null || curl -fsSL https://ollama.com/install.sh | sh
  $SUDO mkdir -p /etc/systemd/system/ollama.service.d
  $SUDO tee /etc/systemd/system/ollama.service.d/tmhc.conf >/dev/null <<'EOF'
[Service]
# keep Ollama on this machine only, one model and one request at a time (8 GB / 2 vCPU)
Environment=OLLAMA_HOST=127.0.0.1:11434
Environment=OLLAMA_NUM_PARALLEL=1
Environment=OLLAMA_MAX_LOADED_MODELS=1
Environment=OLLAMA_KEEP_ALIVE=10m
EOF
  if pidof systemd >/dev/null; then $SUDO systemctl daemon-reload; $SUDO systemctl restart ollama; sleep 3; fi
  ollama pull "$AI_MODEL"
  ( cd "$WORKDIR" && AS env MODEL="$AI_MODEL" "$PY" - "$CONFIG" <<'PYAI'
import os, sys, yaml
p = sys.argv[1]
text = open(p).read(); cfg = yaml.safe_load(text)
o = cfg.setdefault("options", {})
o["reader"] = "ocr+local"; o["local_model"] = os.environ["MODEL"]; o["local_timeout"] = 1800
header = "".join(l for l in text.splitlines(True) if l.startswith("#"))
open(p, "w").write(header + yaml.safe_dump(cfg, sort_keys=False, allow_unicode=True))
PYAI
  )
fi

# ---------------------------------------------------------------- services
# hardening shared by both services
if [ "$MODE" = system ]; then
  HARDEN="NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$INBOX_ROOT"
else
  HARDEN="NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full"
fi

start_service() {
  local name="$1"
  if pidof systemd >/dev/null; then
    $SUDO systemctl daemon-reload
    $SUDO systemctl enable "$name" >/dev/null 2>&1
    $SUDO systemctl restart "$name"
    sleep 2
    systemctl is-active --quiet "$name" && echo "$name is running" || warn "$name did not start: journalctl -u $name -n 50"
  else
    warn "systemd is not running here; start it by hand: tmhc ${name#tmhc-} --config $CONFIG"
  fi
}

if [ "$NO_SERVICE" = 0 ]; then
  say "Background service tmhc-watch (builds the reports)"
  $SUDO tee "$SERVICE" >/dev/null <<EOF
[Unit]
Description=Trend Micro health-check report watcher
After=network.target$( [ "$WITH_AI" = 1 ] && echo " ollama.service" )

[Service]
Type=simple
User=$RUN_USER
WorkingDirectory=$WORKDIR
ExecStart=$PY -m tmhc watch --config $CONFIG
Restart=always
RestartSec=10
Nice=10
# never leaves the machine: the watcher needs no network at all
IPAddressDeny=any
IPAddressAllow=localhost
$HARDEN

[Install]
WantedBy=multi-user.target
EOF
  start_service tmhc-watch
fi

# ---------------------------------------------------------------- website
if [ "$WEB" = 1 ]; then
  CUR_PORT=$(RUNPY -c "import yaml,sys; c=yaml.safe_load(open(sys.argv[1])) or {}; print((c.get('web') or {}).get('port',''))" "$CONFIG")
  port_busy() {   # something already answers on this port (e.g. the existing site on 8000)
    "$PY" -c "import socket,sys; s=socket.socket(); s.settimeout(1); sys.exit(0 if s.connect_ex(('127.0.0.1', int(sys.argv[1])))==0 else 1)" "$1"
  }
  [ "$PORT_SET" = 0 ] && [ -n "$CUR_PORT" ] && PORT="$CUR_PORT"     # keep the saved port on re-runs
  if pidof systemd >/dev/null && systemctl is-active --quiet tmhc-web 2>/dev/null; then
    $SUDO systemctl stop tmhc-web                      # free our own port before checking it
  fi
  while port_busy "$PORT"; do warn "port $PORT is in use"; PORT=$((PORT+1)); done
  say "Upload website on port $PORT"
  RUNPY - "$CONFIG" "$PORT" <<'PYWEB'
import sys, yaml, secrets
p, port = sys.argv[1], int(sys.argv[2])
text = open(p).read(); cfg = yaml.safe_load(text)
web = cfg.setdefault("web", {}); web["port"] = port; web.setdefault("host", "0.0.0.0")
web.setdefault("secret", secrets.token_hex(32)); web.setdefault("users", {})
cfg["inbox"] = str(cfg["inbox"])
header = "".join(l for l in text.splitlines(True) if l.startswith("#"))
open(p, "w").write(header + yaml.safe_dump(cfg, sort_keys=False, allow_unicode=True))
PYWEB
  chmod 600 "$CONFIG"
  HAS_USER=$(RUNPY -c "import yaml,sys; print(len((yaml.safe_load(open(sys.argv[1])).get('web') or {}).get('users') or {}))" "$CONFIG")
  if [ "$HAS_USER" = 0 ]; then
    DEFAULT_LOGIN="$( [ "$MODE" = system ] && echo admin || echo "$RUN_USER" )"
    if [ -n "${TMHC_WEB_PASSWORD:-}" ]; then
      ( cd "$WORKDIR" && AS env TMHC_WEB_PASSWORD="$TMHC_WEB_PASSWORD" "$PY" -m tmhc web --config "$CONFIG" \
          --set-password "${TMHC_WEB_USER:-$DEFAULT_LOGIN}" )
    elif [ "$NONINTERACTIVE" = 0 ] && [ -t 0 ]; then
      read -r -p "  Website login name [$DEFAULT_LOGIN]: " WEBUSER; WEBUSER=${WEBUSER:-$DEFAULT_LOGIN}
      RUNPY -m tmhc web --config "$CONFIG" --set-password "$WEBUSER"
    else
      warn "create a website login with:  tmhc web --set-password <name>"
    fi
  fi
  if [ "$NO_SERVICE" = 0 ]; then
    $SUDO tee "$WEB_SERVICE" >/dev/null <<EOF
[Unit]
Description=Health-check upload website
After=network.target

[Service]
Type=simple
User=$RUN_USER
WorkingDirectory=$WORKDIR
ExecStart=$PY -m tmhc web --config $CONFIG
Restart=always
RestartSec=5
# answers the office network only and can never reach the internet
IPAddressDeny=any
IPAddressAllow=localhost 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
$HARDEN

[Install]
WantedBy=multi-user.target
EOF
    start_service tmhc-web
  fi
  if command -v ufw >/dev/null && $SUDO ufw status | grep -q "Status: active"; then
    $SUDO ufw allow from 192.168.0.0/16 to any port "$PORT" proto tcp >/dev/null
    $SUDO ufw allow from 10.0.0.0/8 to any port "$PORT" proto tcp >/dev/null
  fi
fi

# ---------------------------------------------------------------- samba (optional)
if [ "$SAMBA" = 1 ]; then
  say "Sharing $INBOX_ROOT with Windows as \\\\<this-vm>\\healthcheck (login: $RUN_USER)"
  if ! grep -q '^\[healthcheck\]' /etc/samba/smb.conf; then
    $SUDO tee -a /etc/samba/smb.conf >/dev/null <<EOF

[healthcheck]
   path = $INBOX_ROOT
   valid users = $RUN_USER
   read only = no
   browseable = yes
   create mask = 0640
   directory mask = 0750
   veto files = /.tmhc_state.json/
EOF
  fi
  if ! $SUDO pdbedit -L 2>/dev/null | grep -q "^$RUN_USER:"; then
    if [ "$NONINTERACTIVE" = 1 ] || [ ! -t 0 ]; then
      warn "set the Windows share password with:  sudo smbpasswd -a $RUN_USER"
    else
      echo "Choose a password for the Windows share (user: $RUN_USER):"
      $SUDO smbpasswd -a "$RUN_USER"
    fi
  fi
  if command -v ufw >/dev/null && $SUDO ufw status | grep -q "Status: active"; then $SUDO ufw allow samba >/dev/null; fi
  if pidof systemd >/dev/null; then $SUDO systemctl enable --now smbd >/dev/null && $SUDO systemctl restart smbd; fi
fi

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
cat <<EOF

------------------------------------------------------------------
 Installed ($MODE mode, services run as '$RUN_USER').
$( [ "$WEB" = 1 ] && printf '\n Website:  http://%s:%s\n' "${IP:-<vm-ip>}" "$PORT" )

 Client folders:  $INBOX_ROOT/inbox/<Client Name>/   (output/ holds the report)
$( [ "$SAMBA" = 1 ] && echo " From Windows:    \\\\${IP:-<vm-ip>}\\healthcheck\\inbox\\" )
 Settings:        $CONFIG
 Add a login:     tmhc web --set-password <name>
 Live log:        journalctl -u tmhc-web -u tmhc-watch -f
 Update:          cd $REPO && git pull && ./deploy/install.sh
------------------------------------------------------------------
EOF
