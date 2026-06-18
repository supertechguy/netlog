#!/usr/bin/env python3
"""netlog - terminal network log viewer with MAC/IP/syslog highlighting"""

import sys
import re
import json
import curses
import time
import glob
import tarfile
import hashlib
import ipaddress
import urllib.request
import urllib.parse
from collections import Counter
from pathlib import Path

try:
    import select, termios, tty
    HAS_TERMIOS = True
except ImportError:
    HAS_TERMIOS = False

try:
    import maxminddb
    HAS_GEOIP = True
except ImportError:
    HAS_GEOIP = False

SCRIPT_DIR   = Path(__file__).parent
OUI_FILE     = SCRIPT_DIR / 'oui.txt'
COLOR_FILE   = SCRIPT_DIR / 'mac_colors.json'
CONFIG_FILE  = SCRIPT_DIR / 'netlog_config.json'
GEOIP_DEST   = SCRIPT_DIR / 'GeoLite2-City.mmdb'

# ── Patterns ──────────────────────────────────────────────────────────────────

MAC_RE = re.compile(r'(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}')
IP4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
IP6_RE = re.compile(
    r'(?<![0-9A-Fa-f:])'
    r'(?:'
    r'(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}'
    r'|(?:[0-9A-Fa-f]{1,4}:){1,7}:'
    r'|::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}'
    r'|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}'
    r'|::1'
    r')'
    r'(?![0-9A-Fa-f:])'
)
SEV_RE = re.compile(
    r'\b(EMERG(?:ENCY)?|ALERT|CRIT(?:ICAL)?|ERR(?:OR)?|WARN(?:ING)?|NOTICE|INFO(?:RMATIONAL)?|DEBUG)\b',
    re.IGNORECASE,
)
PORT_RE = re.compile(
    r'\b(?:[SDsd][Pp][Tt]|[Ss]port|[Dd]port|port)\s*[=: ]\s*(\d{1,5})\b'
    r'|(?<!:):(\d{1,5})(?![\d.])',
    re.IGNORECASE,
)
IFACE_RE = re.compile(
    r'\b(lo'
    r'|eth\d+(?:\.\d+)?'
    r'|ens\d+'
    r'|enp\d+s\d+'
    r'|wlan\d+'
    r'|wlp\d+s\d+'
    r'|bond\d+'
    r'|br[\w-]+'
    r'|vlan\d+'
    r'|tun\d+'
    r'|tap\d+'
    r'|docker\d+'
    r'|virbr\d+'
    r'|veth\w+'
    r'|dummy\d*)\b'
)

WELL_KNOWN_PORTS = {
    20:'FTP-data', 21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP',
    53:'DNS', 67:'DHCP', 68:'DHCP', 69:'TFTP', 80:'HTTP',
    110:'POP3', 123:'NTP', 143:'IMAP', 161:'SNMP', 162:'SNMP-trap',
    179:'BGP', 389:'LDAP', 443:'HTTPS', 445:'SMB', 465:'SMTPS',
    514:'Syslog', 515:'LPD', 587:'SMTP-sub', 636:'LDAPS',
    993:'IMAPS', 995:'POP3S', 1194:'OpenVPN', 1433:'MSSQL',
    1723:'PPTP', 3306:'MySQL', 3389:'RDP', 5432:'Postgres',
    5900:'VNC', 6379:'Redis', 8080:'HTTP-alt', 8443:'HTTPS-alt',
    9200:'Elastic', 27017:'MongoDB',
}

SEV_LEVEL = {
    'EMERG':0,'EMERGENCY':0,'ALERT':1,'CRIT':2,'CRITICAL':2,
    'ERR':3,'ERROR':3,'WARN':4,'WARNING':4,
    'NOTICE':5,'INFO':6,'INFORMATIONAL':6,'DEBUG':7,
}

# ── Color constants ───────────────────────────────────────────────────────────

ANSI_MAC    = ['1;31','1;33','1;35','1;36','0;37','0;33','0;36','0;35']
ANSI_IP4    = '1;34'
ANSI_IP6    = '0;34'
ANSI_SEARCH = '1;30;43'
ANSI_PORT   = '0;33'
ANSI_IFACE  = '0;35'
ANSI_SEV    = {0:'1;37;41',1:'1;37;41',2:'1;31',3:'0;31',4:'1;33',5:'0;36',6:'0;32',7:'2;37'}

_P_MAC   = 1   # pairs 1-8
_P_IP4   = 9
_P_SRCH  = 10
_P_STAT  = 11
_P_KEYS  = 12
_P_IP6   = 13
_P_SEV   = 14  # pairs 14-21 (8 severity levels)
_P_PORT  = 22
_P_IFACE = 23
_P_DEDUP = 24

_MAC_CURSES = [
    curses.COLOR_RED, curses.COLOR_YELLOW, curses.COLOR_MAGENTA,
    curses.COLOR_CYAN, curses.COLOR_WHITE, curses.COLOR_YELLOW,
    curses.COLOR_CYAN, curses.COLOR_MAGENTA,
]
_MAC_BOLD = [True, True, True, True, False, False, False, False]

# ── OUI / color-map ───────────────────────────────────────────────────────────

def load_oui(path):
    if not path.exists():
        print("OUI file not found. Downloading from Wireshark...", file=sys.stderr)
        try:
            req = urllib.request.Request(
                "https://www.wireshark.org/download/automated/data/manuf",
                headers={"User-Agent": "Mozilla/5.0"}
            )
            with urllib.request.urlopen(req, timeout=30) as r:
                path.write_text(r.read().decode('utf-8', errors='replace'))
        except Exception as e:
            print(f"Failed to download OUI file: {e}", file=sys.stderr)
            return {}
    vendors = {}
    with open(path, errors='replace') as f:
        for line in f:
            if line.startswith('#') or not line.strip():
                continue
            # Wireshark manuf format: 00:11:22\tShortName\tFull Vendor Name
            parts = line.split('\t')
            if len(parts) >= 2:
                mac = parts[0].strip().replace(':', '').upper()
                if len(mac) == 6:  # 24-bit OUI only
                    name = parts[2].strip() if len(parts) >= 3 else parts[1].strip()
                    vendors[mac] = name
    return vendors

def load_color_map(path):
    if path.exists():
        try:
            d = json.loads(path.read_text())
            return d.get('map', {}), d.get('index', 0)
        except Exception:
            pass
    return {}, 0

def save_color_map(path, mac_map, idx):
    try:
        path.write_text(json.dumps({'map': mac_map, 'index': idx}, indent=2))
    except OSError:
        pass

def mac_color(norm, mac_map, ctr):
    if norm not in mac_map:
        mac_map[norm] = ctr[0] % 8
        ctr[0] += 1
    return mac_map[norm]

# ── Config ────────────────────────────────────────────────────────────────────

def load_config():
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return {}

def save_config(cfg):
    try:
        CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    except Exception as e:
        print(f"Warning: could not save config: {e}", file=sys.stderr)

# ── GeoIP ─────────────────────────────────────────────────────────────────────

GEOIP_PATHS = [
    GEOIP_DEST,
    SCRIPT_DIR / 'GeoLite2-Country.mmdb',
    Path('/usr/share/GeoIP/GeoLite2-City.mmdb'),
    Path('/usr/share/GeoIP/GeoLite2-Country.mmdb'),
    Path('/var/lib/GeoIP/GeoLite2-City.mmdb'),
    Path('/var/lib/GeoIP/GeoLite2-Country.mmdb'),
    Path.home() / '.local/share/GeoIP/GeoLite2-City.mmdb',
    Path.home() / '.local/share/GeoIP/GeoLite2-Country.mmdb',
]

_GEO_READER = None
_GEO_CACHE  = {}


def _geoip_fetch(account_id, license_key):
    import io
    base_url = "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz"
    sha_url  = base_url + ".sha256"
    mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    mgr.add_password(None, "https://download.maxmind.com/", account_id, license_key)
    opener = urllib.request.build_opener(urllib.request.HTTPBasicAuthHandler(mgr))
    print("Downloading GeoLite2-City.mmdb...", file=sys.stderr)
    with opener.open(base_url, timeout=60) as r:
        data = r.read()
    with opener.open(sha_url, timeout=15) as r:
        expected_sha = r.read().decode().split()[0].strip()
    actual_sha = hashlib.sha256(data).hexdigest()
    if actual_sha != expected_sha:
        raise ValueError(f"SHA256 mismatch (got {actual_sha}, expected {expected_sha})")
    print("SHA256 verified.", file=sys.stderr)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for member in tar.getmembers():
            if member.name.endswith("GeoLite2-City.mmdb"):
                GEOIP_DEST.write_bytes(tar.extractfile(member).read())
                print(f"Saved to {GEOIP_DEST}", file=sys.stderr)
                return True
    raise FileNotFoundError("GeoLite2-City.mmdb not found inside the downloaded archive.")


def update_geoip(cfg, prompt_if_missing=False):
    """Download or update GeoLite2-City.mmdb using stored or prompted credentials.
    Returns True if the file is ready, False otherwise."""
    import datetime
    today = datetime.date.today().isoformat()

    account_id  = cfg.get("maxmind_account_id", "")
    license_key = cfg.get("maxmind_license_key", "")

    if not account_id or not license_key:
        if not prompt_if_missing:
            return GEOIP_DEST.exists()
        print("GeoLite2-City.mmdb not found.", file=sys.stderr)
        print("For help obtaining credentials, see:", file=sys.stderr)
        print("  https://dev.maxmind.com/geoip/updating-databases/#directly-downloading-databases",
              file=sys.stderr)
        try:
            account_id  = input("MaxMind Account ID: ").strip()
            license_key = input("MaxMind License Key: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nSkipping GeoIP download.", file=sys.stderr)
            return False
        if not account_id or not license_key:
            print("No credentials provided, skipping GeoIP download.", file=sys.stderr)
            return False
        cfg["maxmind_account_id"]  = account_id
        cfg["maxmind_license_key"] = license_key

    if cfg.get("last_geoip_check") == today and GEOIP_DEST.exists():
        return True

    try:
        if _geoip_fetch(account_id, license_key):
            cfg["last_geoip_check"] = today
            save_config(cfg)
            return True
    except Exception as e:
        print(f"Failed to download GeoLite2-City.mmdb: {e}", file=sys.stderr)
    return GEOIP_DEST.exists()


def load_geoip(cfg):
    if not HAS_GEOIP:
        return None
    needs_download = not any(p.exists() for p in GEOIP_PATHS)
    update_geoip(cfg, prompt_if_missing=needs_download)
    for path in GEOIP_PATHS:
        if path.exists():
            try:
                return maxminddb.open_database(str(path))
            except Exception:
                pass
    return None


def geo_lookup(ip_str):
    if _GEO_READER is None:
        return None
    if ip_str in _GEO_CACHE:
        return _GEO_CACHE[ip_str]
    try:
        addr = ipaddress.ip_address(ip_str)
        if not addr.is_global:
            _GEO_CACHE[ip_str] = None
            return None
        rec = _GEO_READER.get(ip_str)
        if rec:
            city  = (rec.get('city') or {}).get('names', {}).get('en', '')
            subs  = rec.get('subdivisions') or []
            state = (subs[0] if subs else {}).get('iso_code', '')
            country = (rec.get('country') or {}).get('iso_code', '')
            result  = ', '.join(filter(None, [city, state, country])) or None
        else:
            result = None
    except Exception:
        result = None
    _GEO_CACHE[ip_str] = result
    return result


# ── Segment builder (shared by ANSI + curses) ─────────────────────────────────

def _a(text, code):
    return f'\033[{code}m{text}\033[0m'

def _collect_segments(line, vendors, mac_map, ctr, search_term=None, search_is_regex=False):
    """
    Returns sorted list of (src_start, src_end, display_text, ansi_code, pair_num, bold).
    No two segments overlap; priority order: MAC > IP4 > IP6 > SEV > PORT > IFACE > SEARCH.
    pair_num / bold are used by the curses renderer; curses.color_pair() is NOT called here
    so this function is safe to use before curses.initscr().
    """
    segs    = []
    covered = []

    def overlaps(s, e):
        return any(cs < e and s < ce for cs, ce in covered)

    def add(s, e, disp, ansi, pair, bold=True):
        if not overlaps(s, e):
            segs.append((s, e, disp, ansi, pair, bold))
            covered.append((s, e))

    # MACs
    for m in MAC_RE.finditer(line):
        norm   = m.group().upper().replace(':', '').replace('-', '')
        vendor = vendors.get(norm[:6], 'Unknown')
        idx    = mac_color(norm, mac_map, ctr)
        add(m.start(), m.end(), f'{m.group()} ({vendor})',
            ANSI_MAC[idx], _P_MAC + idx, _MAC_BOLD[idx])

    # IPv4
    for m in IP4_RE.finditer(line):
        geo  = geo_lookup(m.group())
        disp = f'{m.group()} ({geo})' if geo else m.group()
        add(m.start(), m.end(), disp, ANSI_IP4, _P_IP4)

    # IPv6
    for m in IP6_RE.finditer(line):
        geo  = geo_lookup(m.group())
        disp = f'{m.group()} ({geo})' if geo else m.group()
        add(m.start(), m.end(), disp, ANSI_IP6, _P_IP6)

    # Severity
    for m in SEV_RE.finditer(line):
        lvl = SEV_LEVEL.get(m.group().upper(), -1)
        if lvl >= 0:
            add(m.start(), m.end(), m.group(), ANSI_SEV[lvl],
                _P_SEV + lvl, lvl <= 4)

    # Ports
    for m in PORT_RE.finditer(line):
        if m.group(1) is not None:
            num = int(m.group(1))
        elif m.group(2) is not None:
            num = int(m.group(2))
            # Skip timestamp-like :NN where NN<=59 and preceded by a digit
            if num <= 59 and m.start() > 0 and line[m.start() - 1].isdigit():
                continue
        else:
            continue
        if 1 <= num <= 65535:
            svc  = WELL_KNOWN_PORTS.get(num)
            disp = f'{m.group()} ({svc})' if svc else m.group()
            add(m.start(), m.end(), disp, ANSI_PORT, _P_PORT, False)

    # Interfaces
    for m in IFACE_RE.finditer(line):
        add(m.start(), m.end(), m.group(), ANSI_IFACE, _P_IFACE, False)

    # Search (lowest priority)
    if search_term:
        try:
            pat = search_term if search_is_regex else re.escape(search_term)
            for m in re.finditer(pat, line, re.I):
                add(m.start(), m.end(), m.group(), ANSI_SEARCH, _P_SRCH, True)
        except re.error:
            pass

    segs.sort(key=lambda s: s[0])
    return segs

# ── ANSI rendering (piped / tail) ─────────────────────────────────────────────

def highlight_ansi(line, vendors, mac_map, ctr, search_term=None, search_is_regex=False):
    segs = _collect_segments(line, vendors, mac_map, ctr, search_term, search_is_regex)
    out  = []
    prev = 0
    for s, e, disp, ansi, _pair, _bold in segs:
        out.append(line[prev:s])
        out.append(_a(disp, ansi))
        prev = e
    out.append(line[prev:])
    return ''.join(out)

# ── Search ────────────────────────────────────────────────────────────────────

def find_matches(view, term, regex=False):
    out = []
    for i, (text, _) in enumerate(view):
        try:
            hit = bool(re.search(term, text, re.I)) if regex else term.lower() in text.lower()
            if hit:
                out.append(i)
        except re.error:
            pass
    return out

# ── Dedup / view helpers ──────────────────────────────────────────────────────

def dedup_lines(lines):
    if not lines:
        return []
    result = []
    cur, cnt = lines[0], 1
    for line in lines[1:]:
        if line == cur:
            cnt += 1
        else:
            result.append((cur, cnt))
            cur, cnt = line, 1
    result.append((cur, cnt))
    return result

def as_view(lines):
    return [(l, 1) for l in lines]

# ── Statistics ────────────────────────────────────────────────────────────────

def collect_stats(view, vendors):
    ip4, ip6, macs, ports, sevs = Counter(), Counter(), Counter(), Counter(), Counter()
    for text, count in view:
        for m in MAC_RE.finditer(text):
            norm   = m.group().upper().replace(':', '').replace('-', '')
            vendor = vendors.get(norm[:6], 'Unknown')
            macs[f'{m.group()} ({vendor})'] += count
        for m in IP4_RE.finditer(text):
            ip4[m.group()] += count
        for m in IP6_RE.finditer(text):
            ip6[m.group()] += count
        for m in PORT_RE.finditer(text):
            num_str = next((g for g in m.groups() if g is not None), None)
            if num_str:
                num = int(num_str)
                if 1 <= num <= 65535:
                    svc  = WELL_KNOWN_PORTS.get(num, '')
                    key  = f'{num} ({svc})' if svc else str(num)
                    ports[key] += count
        for m in SEV_RE.finditer(text):
            sevs[m.group().upper()] += count
    return ip4, ip6, macs, ports, sevs

# ── Curses setup ──────────────────────────────────────────────────────────────

def _init_colors():
    curses.start_color()
    curses.use_default_colors()
    for i, color in enumerate(_MAC_CURSES):
        curses.init_pair(_P_MAC + i, color, -1)
    curses.init_pair(_P_IP4,  curses.COLOR_BLUE,    -1)
    curses.init_pair(_P_SRCH, curses.COLOR_BLACK,   curses.COLOR_YELLOW)
    curses.init_pair(_P_STAT, curses.COLOR_WHITE,   -1)
    curses.init_pair(_P_KEYS, curses.COLOR_CYAN,    -1)
    curses.init_pair(_P_IP6,  curses.COLOR_BLUE,    -1)
    sev_pairs = [
        (curses.COLOR_WHITE,   curses.COLOR_RED),   # 0 EMERG
        (curses.COLOR_WHITE,   curses.COLOR_RED),   # 1 ALERT
        (curses.COLOR_RED,     -1),                 # 2 CRIT
        (curses.COLOR_RED,     -1),                 # 3 ERR
        (curses.COLOR_YELLOW,  -1),                 # 4 WARN
        (curses.COLOR_CYAN,    -1),                 # 5 NOTICE
        (curses.COLOR_GREEN,   -1),                 # 6 INFO
        (curses.COLOR_WHITE,   -1),                 # 7 DEBUG
    ]
    for i, (fg, bg) in enumerate(sev_pairs):
        curses.init_pair(_P_SEV + i, fg, bg)
    curses.init_pair(_P_PORT,  curses.COLOR_YELLOW,  -1)
    curses.init_pair(_P_IFACE, curses.COLOR_MAGENTA, -1)
    curses.init_pair(_P_DEDUP, curses.COLOR_BLACK,   curses.COLOR_WHITE)

# ── Curses line drawing ───────────────────────────────────────────────────────

def _draw_line(win, y, text, count, vendors, mac_map, ctr,
               search_term, search_is_regex, width, show_ln, linenum, dedup_on):
    x = 0
    if show_ln:
        prefix = f'{linenum+1:6} '
        try:
            win.addstr(y, 0, prefix[:width - 1], curses.A_DIM)
            x = len(prefix)
        except curses.error:
            return

    segs = _collect_segments(text, vendors, mac_map, ctr, search_term, search_is_regex)
    prev = 0
    for src_s, src_e, disp, _ansi, pair, bold in segs:
        cattr = curses.color_pair(pair) | (curses.A_BOLD if bold else 0)
        chunk = text[prev:src_s]
        if chunk and x < width - 1:
            try:
                cut = chunk[:width - 1 - x]
                win.addstr(y, x, cut)
                x += len(cut)
            except curses.error:
                return
        if x < width - 1:
            try:
                cut = disp[:width - 1 - x]
                win.addstr(y, x, cut, cattr)
                x += len(cut)
            except curses.error:
                return
        prev = src_e

    tail = text[prev:]
    if tail and x < width - 1:
        try:
            win.addstr(y, x, tail[:width - 1 - x])
            x += min(len(tail), width - 1 - x)
        except curses.error:
            pass

    if dedup_on and count > 1 and x < width - 1:
        badge = f' [×{count}]'
        try:
            win.addstr(y, x, badge[:width - 1 - x],
                       curses.color_pair(_P_DEDUP) | curses.A_BOLD)
        except curses.error:
            pass

# ── Curses status bar ─────────────────────────────────────────────────────────

def _draw_status(win, height, width, term, is_regex, filt, offset, total,
                 dedup_on, show_ln, alert_pat):
    mode  = "REGEX" if is_regex else "TEXT"
    parts = [f"[Search: {term or 'None'} ({mode})]"]
    if filt:      parts.append(f"Filter: {filt}")
    if dedup_on:  parts.append("DEDUP")
    if show_ln:   parts.append("#")
    if alert_pat: parts.append(f"ALERT:{alert_pat}")
    end   = min(offset + height - 2, total)
    line1 = "  ".join(parts) + f"  {offset+1}-{end}/{total}"
    line2 = ("↑↓/WS=scroll  PgUp/Dn/Space=page  g/G=top/bot  "
             "/=text  r=regex  n/p=match  f=filter  "
             "d=dedup  #=linenum  x=stats  e=export  c=clear  q=quit")
    try:
        win.addstr(height - 2, 0, line1[:width - 1], curses.color_pair(_P_STAT))
        win.clrtoeol()
        win.addstr(height - 1, 0, line2[:width - 1], curses.color_pair(_P_KEYS))
        win.clrtoeol()
    except curses.error:
        pass

# ── Curses full render ────────────────────────────────────────────────────────

def _render(win, view, offset, vendors, mac_map, ctr, term, is_regex, show_ln, dedup_on):
    height, width = win.getmaxyx()
    win.erase()
    for i in range(height - 2):
        idx = offset + i
        if idx >= len(view):
            break
        text, count = view[idx]
        _draw_line(win, i, text, count, vendors, mac_map, ctr,
                   term, is_regex, width, show_ln, idx, dedup_on)

# ── Stats popup ───────────────────────────────────────────────────────────────

def _draw_stats(stdscr, view, vendors):
    ip4, ip6, macs, ports, sevs = collect_stats(view, vendors)
    height, width = stdscr.getmaxyx()
    pw  = min(72, width - 4)
    ph  = min(38, height - 4)
    win = curses.newwin(ph, pw, (height - ph) // 2, (width - pw) // 2)
    win.box()
    win.addstr(0, 2, " Statistics — press any key to close ",
               curses.color_pair(_P_STAT) | curses.A_BOLD)

    row = 1
    def section(title, counter, limit=6):
        nonlocal row
        if row >= ph - 2:
            return
        try:
            win.addstr(row, 1, title, curses.color_pair(_P_STAT) | curses.A_BOLD)
        except curses.error:
            pass
        row += 1
        for key, cnt in counter.most_common(limit):
            if row >= ph - 2:
                return
            try:
                win.addstr(row, 2, f'{cnt:6}  {key}'[:pw - 3])
            except curses.error:
                pass
            row += 1

    section("Top IPv4 Addresses", ip4)
    section("Top IPv6 Addresses", ip6)
    section("Top MAC Addresses",  macs)
    section("Top Ports",          ports)
    section("Severity Counts",    sevs, limit=8)

    win.refresh()
    stdscr.getch()

# ── Input helper ──────────────────────────────────────────────────────────────

def _read_line(stdscr, prompt):
    height, width = stdscr.getmaxyx()
    curses.curs_set(1)
    buf, cx = [], len(prompt)
    stdscr.addstr(height - 2, 0, (prompt + ' ' * width)[:width - 1],
                  curses.color_pair(_P_STAT))
    stdscr.move(height - 2, cx)
    stdscr.refresh()
    while True:
        ch = stdscr.getch()
        if ch in (10, 13, curses.KEY_ENTER):
            break
        elif ch in (curses.KEY_BACKSPACE, 127, 8):
            if buf:
                buf.pop(); cx -= 1
                try:
                    stdscr.addch(height - 2, cx, ' ')
                    stdscr.move(height - 2, cx)
                except curses.error:
                    pass
        elif 32 <= ch < 127 and cx < width - 1:
            buf.append(chr(ch))
            try:
                stdscr.addch(height - 2, cx, chr(ch)); cx += 1
            except curses.error:
                pass
        stdscr.refresh()
    curses.curs_set(0)
    return ''.join(buf)

# ── Interactive TUI ───────────────────────────────────────────────────────────

def _tui(stdscr, lines, vendors, mac_map, ctr, alert_pat=None):
    _init_colors()
    curses.curs_set(0)
    stdscr.keypad(True)

    filtered = lines[:]
    dedup_on = False
    show_ln  = False
    offset   = 0
    term     = None
    is_regex = False
    matches  = []
    filt     = None

    def get_view():
        return dedup_lines(filtered) if dedup_on else as_view(filtered)

    view = get_view()

    while True:
        height, width = stdscr.getmaxyx()
        page = max(1, height - 2)

        _render(stdscr, view, offset, vendors, mac_map, ctr, term, is_regex, show_ln, dedup_on)
        _draw_status(stdscr, height, width, term, is_regex, filt, offset, len(view),
                     dedup_on, show_ln, alert_pat)
        stdscr.refresh()

        ch = stdscr.getch()

        if ch == curses.KEY_RESIZE:
            continue
        elif ch in (curses.KEY_UP, ord('w'), ord('W')):
            offset -= 1
        elif ch in (curses.KEY_DOWN, ord('s'), ord('S')):
            offset += 1
        elif ch == curses.KEY_PPAGE:
            offset -= page
        elif ch in (curses.KEY_NPAGE, ord(' ')):
            offset += page
        elif ch == ord('g'):
            offset = 0
        elif ch == ord('G'):
            offset = max(0, len(view) - page)

        elif ch == ord('/'):
            t = _read_line(stdscr, "Search (plain text): ")
            if t:
                term, is_regex = t, False
                matches = find_matches(view, term, False)
                if matches: offset = matches[0]

        elif ch == ord('r'):
            t = _read_line(stdscr, "Search (regex): ")
            if t:
                try:
                    re.compile(t, re.I)
                    term, is_regex = t, True
                    matches = find_matches(view, term, True)
                    if matches: offset = matches[0]
                except re.error as e:
                    h, w = stdscr.getmaxyx()
                    stdscr.addstr(h - 2, 0, f"Invalid regex: {e}  (press any key)"[:w-1],
                                  curses.color_pair(_P_STAT))
                    stdscr.clrtoeol(); stdscr.refresh(); stdscr.getch()

        elif ch == ord('n'):
            if term and matches:
                for ln in matches:
                    if ln > offset: offset = ln; break

        elif ch == ord('p'):
            if term and matches:
                for ln in reversed(matches):
                    if ln < offset: offset = ln; break

        elif ch == ord('f'):
            t = _read_line(stdscr, "Filter (prefix r: for regex): ")
            if t:
                filt = t
                if t.startswith('r:'):
                    pat = t[2:]
                    try:
                        filtered = [l for l in lines if re.search(pat, l, re.I)]
                    except re.error:
                        filtered = lines[:]
                        filt = None
                else:
                    tl = t.lower()
                    filtered = [l for l in lines if tl in l.lower()]
                view    = get_view()
                offset  = 0
                matches = find_matches(view, term, is_regex) if term else []

        elif ch == ord('d'):
            dedup_on = not dedup_on
            view    = get_view()
            offset  = max(0, min(offset, max(0, len(view) - 1)))
            matches = find_matches(view, term, is_regex) if term else []

        elif ch == ord('#'):
            show_ln = not show_ln

        elif ch == ord('x'):
            _draw_stats(stdscr, view, vendors)

        elif ch == ord('e'):
            export = 'logview_filtered_export.txt'
            try:
                Path(export).write_text('\n'.join(t for t, _ in view))
                msg = f"Exported {len(view)} lines to {export}  (press any key)"
            except OSError as e:
                msg = f"Export failed: {e}  (press any key)"
            h, w = stdscr.getmaxyx()
            stdscr.addstr(h - 2, 0, msg[:w-1], curses.color_pair(_P_STAT))
            stdscr.clrtoeol(); stdscr.refresh(); stdscr.getch()

        elif ch == ord('c'):
            filtered = lines[:]
            filt = term = None
            is_regex = dedup_on = False
            matches = []; offset = 0
            view = get_view()

        elif ch == ord('q'):
            break

        offset = max(0, min(offset, max(0, len(view) - page)))

    save_color_map(COLOR_FILE, mac_map, ctr[0])

# ── Run modes ─────────────────────────────────────────────────────────────────

def piped_mode(vendors, mac_map, ctr):
    try:
        for line in sys.stdin:
            print(highlight_ansi(line.rstrip('\n'), vendors, mac_map, ctr))
    finally:
        save_color_map(COLOR_FILE, mac_map, ctr[0])


def tail_mode(log_file, tail_lines_count, vendors, mac_map, ctr, alert_pat=None):
    all_lines = log_file.read_text(errors='replace').splitlines()
    for line in all_lines[-tail_lines_count:]:
        print(highlight_ansi(line, vendors, mac_map, ctr))

    last_size   = log_file.stat().st_size
    last_reload = time.time()
    buf         = list(all_lines)
    paused      = False
    alert_re    = re.compile(alert_pat, re.I) if alert_pat else None

    if not HAS_TERMIOS:
        # Fallback: no pause/keypress support
        try:
            while True:
                if time.time() - last_reload >= 5:
                    new_map, _ = load_color_map(COLOR_FILE)
                    mac_map.update(new_map)
                    last_reload = time.time()
                cur_size = log_file.stat().st_size
                if cur_size > last_size:
                    with open(log_file, errors='replace') as f:
                        f.seek(last_size)
                        for raw in f:
                            line = raw.rstrip('\n')
                            buf.append(line)
                            if len(buf) > 10000: buf.pop(0)
                            colored = highlight_ansi(line, vendors, mac_map, ctr)
                            if alert_re and alert_re.search(line):
                                sys.stdout.write('\a')
                                colored = _a('▶ ', '1;31') + colored
                            print(colored, flush=True)
                    last_size = cur_size
                time.sleep(0.2)
        except KeyboardInterrupt:
            pass
        finally:
            save_color_map(COLOR_FILE, mac_map, ctr[0])
        return

    # Raw-input mode: Space=pause, q=quit
    old = termios.tcgetattr(sys.stdin)
    new = termios.tcgetattr(sys.stdin)
    new[3] &= ~(termios.ICANON | termios.ECHO)
    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, new)

    try:
        while True:
            ready = select.select([sys.stdin], [], [], 0.2)[0]
            if ready:
                ch = sys.stdin.read(1)
                if ch == ' ':
                    paused = not paused
                    label  = "PAUSED (Space to resume)" if paused else "Resumed"
                    sys.stdout.write(f'\r\033[0;33m[{label}]\033[0m\r\n')
                    sys.stdout.flush()
                elif ch in ('q', 'Q', '\x03', '\x04'):
                    break

            if paused:
                continue

            if time.time() - last_reload >= 5:
                new_map, _ = load_color_map(COLOR_FILE)
                mac_map.update(new_map)
                last_reload = time.time()

            cur_size = log_file.stat().st_size
            if cur_size > last_size:
                with open(log_file, errors='replace') as f:
                    f.seek(last_size)
                    for raw in f:
                        line = raw.rstrip('\n')
                        buf.append(line)
                        if len(buf) > 10000: buf.pop(0)
                        colored = highlight_ansi(line, vendors, mac_map, ctr)
                        if alert_re and alert_re.search(line):
                            sys.stdout.write('\a')
                            colored = _a('▶ ', '1;31') + colored
                        print(colored, flush=True)
                last_size = cur_size

    except KeyboardInterrupt:
        pass
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old)
        save_color_map(COLOR_FILE, mac_map, ctr[0])


def interactive_mode(files, vendors, mac_map, ctr, alert_pat=None):
    all_lines = []
    for f in files:
        if len(files) > 1:
            all_lines.append(f'{"─"*4} {f} {"─"*4}')
        all_lines.extend(f.read_text(errors='replace').splitlines())
    curses.wrapper(_tui, all_lines, vendors, mac_map, ctr, alert_pat)

# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    follow     = False
    tail_lines = 10
    log_files  = []
    alert_pat  = None
    args       = sys.argv[1:]
    i = 0
    while i < len(args):
        a = args[i]
        if a == '-f':
            follow = True
        elif a == '-n' and i + 1 < len(args) and args[i+1].isdigit():
            tail_lines = int(args[i+1]); i += 1
        elif a == '--alert' and i + 1 < len(args):
            alert_pat = args[i+1]; i += 1
        elif not a.startswith('-'):
            matches = sorted(glob.glob(a))
            for p in (matches or [a]):
                log_files.append(Path(p))
        i += 1
    return follow, tail_lines, log_files, alert_pat


def main():
    global _GEO_READER
    follow, tail_lines, log_files, alert_pat = parse_args()
    vendors = load_oui(OUI_FILE)
    mac_map, idx = load_color_map(COLOR_FILE)
    ctr = [idx]

    cfg = load_config()
    _GEO_READER = load_geoip(cfg)
    if _GEO_READER is None and not HAS_GEOIP:
        print("GeoIP: install 'maxminddb' for IP location lookup  (pip install maxminddb)",
              file=sys.stderr)

    if not sys.stdin.isatty():
        piped_mode(vendors, mac_map, ctr)
    elif follow:
        if not log_files:
            sys.exit("Usage: netlog.py -f [-n N] [--alert PATTERN] <file>")
        lf = log_files[0]
        if not lf.exists():
            sys.exit(f"File not found: {lf}")
        tail_mode(lf, tail_lines, vendors, mac_map, ctr, alert_pat)
    elif log_files:
        missing = [f for f in log_files if not f.exists()]
        if missing:
            sys.exit(f"File not found: {missing[0]}")
        interactive_mode(log_files, vendors, mac_map, ctr, alert_pat)
    else:
        print("Usage: netlog.py [-f] [-n N] [--alert PATTERN] <file> [file2 ...]",
              file=sys.stderr)
        print("Or:    cat file.log | netlog.py", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
