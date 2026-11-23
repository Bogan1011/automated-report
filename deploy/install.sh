#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Install the health-check report generator on Ubuntu 22.04 / 24.04.
#
#   git clone https://github.com/Bogan1011/automated-report.git
#   cd automated-report
#   ./deploy/install.sh              # OCR reader, watch folder, background service
#   ./deploy/install.sh --samba      # + Windows share  \\<vm-ip>\healthcheck
#   ./deploy/install.sh --with-ai    # + local AI model (Ollama, qwen2.5vl:3b) for what OCR misses
#
# Run as your normal user (not root); it asks for sudo where needed.
# Safe to run again (e.g. after `git pull`) - it only adds what is missing.
# Nothing is sent anywhere: the only downloads are Ubuntu/Python packages
# (and the Ollama model with --with-ai).
# ---------------------------------------------------------------------------
set -euo pipefail

SAMBA=0; WITH_AI=0; NONINTERACTIVE=0; NO_SERVICE=0
INBOX_ROOT="$HOME/healthcheck"
AI_MODEL="qwen2.5vl:3b"
for arg in "$@"; do
  case "$arg" in
    --samba) SAMBA=1 ;;
    --with-ai) WITH_AI=1 ;;
    --yes|-y) NONINTERACTIVE=1 ;;
    --no-service) NO_SERVICE=1 ;;
    --root=*) INBOX_ROOT="${arg#*=}" ;;
    --model=*) AI_MODEL="${arg#*=}" ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg"; exit 2 ;;
  esac
done

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$REPO/.venv"
CONFIG="$INBOX_ROOT/config.yaml"
SERVICE=/etc/systemd/system/tmhc-watch.service
USER_NAME="$(id -un)"

say()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mxx\033[0m %s\n' "$*"; exit 1; }

[ "$(id -u)" -ne 0 ] || die "run this as your normal user, not root (it uses sudo when needed)"
command -v sudo >/dev/null || die "sudo is required"
. /etc/os-release 2>/dev/null || true
[ "${ID:-}" = "ubuntu" ] || warn "tested on Ubuntu 22.04/24.04; you are on ${PRETTY_NAME:-unknown} - continuing"

MEM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
CPUS=$(nproc)
say "Machine: ${CPUS} vCPU, ${MEM_MB} MB RAM"
if [ "$WITH_AI" = 1 ] && [ "$MEM_MB" -lt 7000 ]; then
  warn "less than 7 GB RAM: the local AI model may not fit. OCR alone works fine."
fi

# ---------------------------------------------------------------- packages
say "Installing Ubuntu packages (Python, Tesseract OCR${SAMBA:+, Samba})"
PKGS="python3 python3-venv python3-pip tesseract-ocr tesseract-ocr-eng git curl"
[ "$SAMBA" = 1 ] && PKGS="$PKGS samba"
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $PKGS >/dev/null
tesseract --version | head -1

# ---------------------------------------------------------------- python env
say "Creating Python environment in $VENV"
[ -x "$VENV/bin/python" ] || python3 -m venv "$VENV"
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q -r "$REPO/requirements.txt"

say "Self-test"
( cd "$REPO" && "$VENV/bin/python" -m pytest -q 2>&1 | tail -2 )

# ---------------------------------------------------------------- config
mkdir -p "$INBOX_ROOT/inbox"
if [ ! -f "$CONFIG" ]; then
  say "Creating $CONFIG"
  ( cd "$REPO" && "$VENV/bin/python" - "$CONFIG" <<'PY'
import sys
from pathlib import Path
from tmhc.watch import load_config
load_config(Path(sys.argv[1]))
PY
  )
  if [ "$NONINTERACTIVE" = 0 ] && [ -t 0 ]; then
    echo "Names printed in every report (you can change them later in $CONFIG):"
    read -r -p "  Prepared by: " PREP
    read -r -p "  Approved by: " APPR
    read -r -p "  Account owner: " OWNER
    read -r -p "  Usual password of the logs zip (blank if none): " ZIPPW
    ( cd "$REPO" && PREP="$PREP" APPR="$APPR" OWNER="$OWNER" ZIPPW="$ZIPPW" "$VENV/bin/python" - "$CONFIG" <<'PY'
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
header = "# Health-check watcher settings - see README 'Ubuntu server'\n"
open(p, "w").write(header + yaml.safe_dump(cfg, sort_keys=False, allow_unicode=True))
PY
    )
  fi
else
  say "Keeping existing $CONFIG"
fi
chmod 600 "$CONFIG"   # may hold the zip password

# ---------------------------------------------------------------- local AI (optional)
if [ "$WITH_AI" = 1 ]; then
  say "Local AI: Ollama + $AI_MODEL (runs on this VM only, listens on 127.0.0.1)"
  SWAP_MB=$(awk '/SwapTotal/ {print int($2/1024)}' /proc/meminfo)
  if [ "$SWAP_MB" -lt 2000 ] && [ ! -f /swapfile ]; then
    say "Adding a 4 GB swap file (the model and OCR together are tight in 8 GB)"
    sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile >/dev/null && sudo swapon /swapfile
    grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab >/dev/null
  fi
  command -v ollama >/dev/null || curl -fsSL https://ollama.com/install.sh | sh
  sudo mkdir -p /etc/systemd/system/ollama.service.d
  sudo tee /etc/systemd/system/ollama.service.d/tmhc.conf >/dev/null <<'EOF'
[Service]
# keep Ollama on this machine only, one model and one request at a time (8 GB / 2 vCPU)
Environment=OLLAMA_HOST=127.0.0.1:11434
Environment=OLLAMA_NUM_PARALLEL=1
Environment=OLLAMA_MAX_LOADED_MODELS=1
Environment=OLLAMA_KEEP_ALIVE=10m
EOF
  if pidof systemd >/dev/null; then sudo systemctl daemon-reload; sudo systemctl restart ollama; sleep 3; fi
  ollama pull "$AI_MODEL"
  ( cd "$REPO" && MODEL="$AI_MODEL" "$VENV/bin/python" - "$CONFIG" <<'PY'
import os, sys, yaml
p = sys.argv[1]
text = open(p).read()
cfg = yaml.safe_load(text)
o = cfg.setdefault("options", {})
o["reader"] = "ocr+local"
o["local_model"] = os.environ["MODEL"]
o["local_timeout"] = 1800
header = "".join(l for l in text.splitlines(True) if l.startswith("#"))
open(p, "w").write(header + yaml.safe_dump(cfg, sort_keys=False, allow_unicode=True))
PY
  )
fi

# ---------------------------------------------------------------- service
if [ "$NO_SERVICE" = 0 ]; then
  say "Installing background service tmhc-watch"
  sudo tee "$SERVICE" >/dev/null <<EOF
[Unit]
Description=Trend Micro health-check report watcher
After=network.target$( [ "$WITH_AI" = 1 ] && echo " ollama.service" )

[Service]
Type=simple
User=$USER_NAME
WorkingDirectory=$REPO
ExecStart=$VENV/bin/python -m tmhc watch --config $CONFIG
Restart=always
RestartSec=10
Nice=10
# never leave the machine: the watcher needs no network at all
IPAddressDeny=any
IPAddressAllow=localhost

[Install]
WantedBy=multi-user.target
EOF
  if pidof systemd >/dev/null; then
    sudo systemctl daemon-reload
    sudo systemctl enable --now tmhc-watch >/dev/null
    sudo systemctl restart tmhc-watch
    sleep 2
    systemctl is-active --quiet tmhc-watch && echo "tmhc-watch is running" || warn "service did not start: journalctl -u tmhc-watch -n 50"
  else
    warn "systemd is not running here; start the watcher with: $VENV/bin/python -m tmhc watch --config $CONFIG"
  fi
fi

# ---------------------------------------------------------------- samba (optional)
if [ "$SAMBA" = 1 ]; then
  say "Sharing $INBOX_ROOT with Windows as \\\\<this-vm>\\healthcheck"
  if ! grep -q '^\[healthcheck\]' /etc/samba/smb.conf; then
    sudo tee -a /etc/samba/smb.conf >/dev/null <<EOF

[healthcheck]
   path = $INBOX_ROOT
   valid users = $USER_NAME
   read only = no
   browseable = yes
   create mask = 0640
   directory mask = 0750
   veto files = /.tmhc_state.json/
EOF
  fi
  if ! sudo pdbedit -L 2>/dev/null | grep -q "^$USER_NAME:"; then
    if [ "$NONINTERACTIVE" = 1 ] || [ ! -t 0 ]; then
      warn "set the Windows share password with:  sudo smbpasswd -a $USER_NAME"
    else
      echo "Choose a password for the Windows share (user: $USER_NAME):"
      sudo smbpasswd -a "$USER_NAME"
    fi
  fi
  if command -v ufw >/dev/null && sudo ufw status | grep -q "Status: active"; then sudo ufw allow samba >/dev/null; fi
  if pidof systemd >/dev/null; then sudo systemctl enable --now smbd >/dev/null && sudo systemctl restart smbd; fi
fi

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
cat <<EOF

------------------------------------------------------------------
 Installed.

 Drop each client in its own folder:
     $INBOX_ROOT/inbox/<Client Name>/   <- screenshots .docx + logs .zip
$( [ "$SAMBA" = 1 ] && echo "     from Windows:  \\\\${IP:-<vm-ip>}\\healthcheck\\inbox\\<Client Name>\\" )
 The report appears in <Client Name>/output/ and STATUS.txt says what
 happened. Fill blanks in checklist.xlsx and save to rebuild.

 Settings:     $CONFIG
 Live log:     journalctl -u tmhc-watch -f
 Update:       cd $REPO && git pull && ./deploy/install.sh
------------------------------------------------------------------
EOF
