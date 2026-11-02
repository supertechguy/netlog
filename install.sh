#!/usr/bin/env bash
# Installs netlog as 'netlog' somewhere on PATH so it can be run from
# any directory. See README.md "Installation" for details.
set -euo pipefail

SCRIPT_SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYSTEM_INSTALL=0
PREFIX=""

usage() {
    cat <<EOF
Usage: $(basename "$0") [--system] [--prefix DIR]

Installs netlog as an executable named 'netlog' so it can be run from
anywhere.

  --system      Install to /usr/local/bin instead of the default
                 ~/.local/bin. Requires write access to /usr/local/bin
                 (re-run with sudo if needed).
  --prefix DIR   Install into DIR/bin instead of the default location.
                 Overrides --system.
  -h, --help     Show this help and exit.

Per-user data (the OUI vendor database, MAC color map, and GeoIP
credentials/database) always lives under \$XDG_DATA_HOME/netlog, or
~/.local/share/netlog if that isn't set — regardless of where the
executable itself is installed.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --system) SYSTEM_INSTALL=1 ;;
        --prefix)
            [ $# -ge 2 ] || { echo "--prefix requires an argument" >&2; exit 1; }
            PREFIX="$2"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
    esac
    shift
done

if [ -n "$PREFIX" ]; then
    BIN_DIR="$PREFIX/bin"
elif [ "$SYSTEM_INSTALL" -eq 1 ]; then
    BIN_DIR="/usr/local/bin"
else
    BIN_DIR="$HOME/.local/bin"
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 not found on PATH; netlog requires Python 3.8+." >&2
    exit 1
fi

mkdir -p "$BIN_DIR" 2>/dev/null || true
if [ ! -d "$BIN_DIR" ] || [ ! -w "$BIN_DIR" ]; then
    echo "Cannot write to $BIN_DIR." >&2
    if [ "$BIN_DIR" = "/usr/local/bin" ]; then
        echo "Try: sudo $0 --system" >&2
    fi
    exit 1
fi

install -m 755 "$SCRIPT_SRC_DIR/netlog" "$BIN_DIR/netlog"

# Per-user data dir, matching netlog's own resolution for an installed
# (non-dev-checkout) copy.
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/netlog"
mkdir -p "$DATA_DIR"

# Pre-seed the OUI vendor database if this checkout already downloaded one,
# so the first real run doesn't need to hit the network for it.
if [ -f "$SCRIPT_SRC_DIR/oui.txt" ] && [ ! -f "$DATA_DIR/oui.txt" ]; then
    cp "$SCRIPT_SRC_DIR/oui.txt" "$DATA_DIR/oui.txt"
fi

echo "Installed: $BIN_DIR/netlog"
echo "Data dir:  $DATA_DIR"

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
        echo
        echo "$BIN_DIR is not on your PATH. Add this to your shell profile"
        echo "(~/.bashrc, ~/.zshrc, etc.) and open a new shell:"
        echo
        echo "  export PATH=\"$BIN_DIR:\$PATH\""
        ;;
esac

echo
echo "Run 'netlog --setup-geoip' if you want IP geolocation lookups (optional)."
