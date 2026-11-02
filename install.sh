#!/usr/bin/env bash
# Installs (or uninstalls) netlog so it can be run from any directory.
# See README.md "Installation" for details.
set -euo pipefail

SCRIPT_SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_BIN="$HOME/.local/bin"
SYSTEM_BIN="/usr/local/bin"

MODE=""        # user | system | prefix   (empty = ask)
PREFIX=""
UNINSTALL=0
PURGE=""       # 1 = delete data, 0 = keep, empty = ask

# Files netlog keeps in its data dir. --purge deletes only these, never the
# whole directory, so a mistaken NETLOG_DATA_DIR can't wipe unrelated files.
DATA_FILES=(oui.txt mac_colors.json netlog_config.json
            GeoLite2-City.mmdb GeoLite2-Country.mmdb)

usage() {
    cat <<EOF
Usage: $(basename "$0") [--user | --system | --prefix DIR]
       $(basename "$0") --uninstall [--user | --system | --prefix DIR] [--purge | --keep-data]

Installs netlog as an executable named 'netlog' so it can be run from
anywhere. With no location option, asks whether to do a user or system
install (non-interactive runs default to a user install).

  --user         Install to ~/.local/bin (just you, no sudo needed).
  --system       Install to /usr/local/bin (all users). Uses sudo for the
                 copy if you can't write there yourself.
  --prefix DIR   Install into DIR/bin.
  --uninstall    Remove netlog instead of installing it. With no location
                 option, removes it from both ~/.local/bin and
                 /usr/local/bin wherever it's found.
  --purge        With --uninstall: also delete your netlog data (MAC
                 colors, column settings, GeoIP credentials and databases,
                 OUI database) without asking.
  --keep-data    With --uninstall: keep your netlog data without asking.
  -h, --help     Show this help and exit.

Per-user data lives in \$NETLOG_DATA_DIR if set, otherwise
\$XDG_DATA_HOME/netlog (default ~/.local/share/netlog), regardless of
where the executable itself is installed.
EOF
}

die() { echo "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --user)   MODE=user ;;
        --system) MODE=system ;;
        --prefix)
            [ $# -ge 2 ] || die "--prefix requires an argument"
            MODE=prefix; PREFIX="$2"; shift ;;
        --uninstall) UNINSTALL=1 ;;
        --purge)     PURGE=1 ;;
        --keep-data) PURGE=0 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
    esac
    shift
done

if [ "$UNINSTALL" -eq 0 ] && [ -n "$PURGE" ]; then
    die "--purge / --keep-data only make sense with --uninstall"
fi

is_tty() { [ -t 0 ] && [ -t 1 ]; }

# Same resolution netlog itself uses for an installed copy.
DATA_DIR="${NETLOG_DATA_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/netlog}"

# When run via sudo, $HOME is root's, so a "user" install would only be
# for root. Say so rather than surprising anyone.
RUNNING_UNDER_SUDO=0
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    RUNNING_UNDER_SUDO=1
fi

# Run a command, falling back to sudo if the target dir isn't writable.
run_priv() {
    local dir="$1"; shift
    if [ -w "$dir" ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        echo "Need elevated permissions for $dir; using sudo."
        sudo "$@"
    else
        die "Cannot write to $dir and sudo is not available. Re-run as root."
    fi
}

ask_mode() {
    local verb="$1" user_label="just you"
    [ "$RUNNING_UNDER_SUDO" -eq 1 ] && user_label="root only — you ran this with sudo"
    echo "Where should netlog be ${verb}?"
    echo "  1) User   — $USER_BIN ($user_label)"
    echo "  2) System — $SYSTEM_BIN (all users, may ask for your sudo password)"
    local choice
    while true; do
        read -r -p "Choose [1/2] (default 1): " choice || choice=""
        case "${choice:-1}" in
            1|u|user)   MODE=user;   return ;;
            2|s|system) MODE=system; return ;;
            *) echo "Please enter 1 or 2." ;;
        esac
    done
}

bin_dir_for_mode() {
    case "$MODE" in
        user)   echo "$USER_BIN" ;;
        system) echo "$SYSTEM_BIN" ;;
        prefix) echo "$PREFIX/bin" ;;
    esac
}

# ---------------------------------------------------------------- uninstall
if [ "$UNINSTALL" -eq 1 ]; then
    if [ -n "$MODE" ]; then
        targets=("$(bin_dir_for_mode)/netlog")
    else
        targets=("$USER_BIN/netlog" "$SYSTEM_BIN/netlog")
    fi

    removed=0
    for t in "${targets[@]}"; do
        if [ -e "$t" ] || [ -L "$t" ]; then
            run_priv "$(dirname "$t")" rm -f "$t"
            echo "Removed: $t"
            removed=1
        fi
    done
    [ "$removed" -eq 1 ] || echo "netlog executable not found in: ${targets[*]}"

    present=()
    for f in "${DATA_FILES[@]}"; do
        [ -e "$DATA_DIR/$f" ] && present+=("$f")
    done

    if [ "${#present[@]}" -eq 0 ]; then
        echo "No netlog data found in $DATA_DIR."
    else
        if [ -z "$PURGE" ]; then
            if is_tty; then
                echo
                echo "Your netlog data in $DATA_DIR:"
                printf '  %s\n' "${present[@]}"
                read -r -p "Delete it too? [y/N] " ans || ans=""
                case "$ans" in [yY]|[yY][eE][sS]) PURGE=1 ;; *) PURGE=0 ;; esac
            else
                PURGE=0
            fi
        fi
        if [ "$PURGE" -eq 1 ]; then
            for f in "${present[@]}"; do rm -f "$DATA_DIR/$f"; done
            rmdir "$DATA_DIR" 2>/dev/null \
                && echo "Deleted data dir: $DATA_DIR" \
                || echo "Deleted netlog data files (left $DATA_DIR in place; it has other files)."
        else
            echo "Kept data in $DATA_DIR (re-run with --uninstall --purge to delete it)."
        fi
    fi
    exit 0
fi

# ------------------------------------------------------------------ install
if [ -z "$MODE" ]; then
    if is_tty; then ask_mode installed; echo; else MODE=user; fi
fi
BIN_DIR="$(bin_dir_for_mode)"

if [ "$MODE" = user ] && [ "$RUNNING_UNDER_SUDO" -eq 1 ]; then
    echo "Note: running under sudo, so this installs for root only ($BIN_DIR)."
    echo "      For all users use --system; for just you, run without sudo."
fi

command -v python3 >/dev/null 2>&1 \
    || die "python3 not found on PATH; netlog requires Python 3.8+."

if [ "$MODE" = system ]; then
    [ -d "$BIN_DIR" ] || run_priv "$(dirname "$BIN_DIR")" mkdir -p "$BIN_DIR"
    run_priv "$BIN_DIR" install -m 755 "$SCRIPT_SRC_DIR/netlog" "$BIN_DIR/netlog"
else
    mkdir -p "$BIN_DIR" 2>/dev/null || true
    [ -d "$BIN_DIR" ] && [ -w "$BIN_DIR" ] || die "Cannot write to $BIN_DIR."
    install -m 755 "$SCRIPT_SRC_DIR/netlog" "$BIN_DIR/netlog"
fi

echo "Installed: $BIN_DIR/netlog"

# Pre-seed the invoking user's OUI vendor database if this checkout already
# downloaded one, so the first run doesn't need the network. Skipped when
# running as root via sudo, since it would land in root's data dir instead.
if [ "$RUNNING_UNDER_SUDO" -eq 0 ] || [ "$MODE" = user ]; then
    mkdir -p "$DATA_DIR"
    if [ -f "$SCRIPT_SRC_DIR/oui.txt" ] && [ ! -f "$DATA_DIR/oui.txt" ]; then
        cp "$SCRIPT_SRC_DIR/oui.txt" "$DATA_DIR/oui.txt"
    fi
    echo "Data dir:  $DATA_DIR"
fi

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
echo "To uninstall later: $SCRIPT_SRC_DIR/install.sh --uninstall"
