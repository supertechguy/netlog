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
import array
import mmap
import gzip
import os
import tempfile
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

LARGE_FILE_THRESHOLD = 50 * 1024 * 1024   # bytes — above this, use mmap index

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

# ── Event-type patterns (priority order: deny > error > allow > start > end) ──

_EV_DENY  = re.compile(
    r'\b(?:den(?:y|ied)|drop(?:ped)?|block(?:ed)?|reject(?:ed)?|refus(?:e|ed)|discard(?:ed)?)\b', re.I)
_EV_ERROR = re.compile(
    r'\b(?:err(?:or)?|fail(?:ed|ure)?|invalid|corrupt(?:ed)?)\b', re.I)
_EV_ALLOW = re.compile(
    r'\b(?:allow(?:ed)?|permit(?:ted)?|accept(?:ed)?|pass(?:ed)?|forward(?:ed)?)\b', re.I)
_EV_START = re.compile(
    r'\b(?:built|start(?:ed)?|open(?:ed)?|established|connect(?:ed)?)\b', re.I)
_EV_END   = re.compile(
    r'\b(?:teardown|clos(?:e|ed)|expir(?:e|ed)|terminat(?:ed)?|reset)\b', re.I)

# ── Color constants ───────────────────────────────────────────────────────────

ANSI_MAC    = ['1;31','1;33','1;35','1;36','0;37','0;33','0;36','0;35']
ANSI_IP4    = '1;34'
ANSI_IP6    = '0;34'
ANSI_SEARCH = '1;30;43'
ANSI_PORT   = '0;33'
ANSI_IFACE  = '0;35'
ANSI_SEV    = {0:'1;37;41',1:'1;37;41',2:'1;31',3:'0;31',4:'1;33',5:'0;36',6:'0;32',7:'2;37'}

ANSI_EV_DENY  = '1;31'   # bold red
ANSI_EV_ERROR = '1;33'   # bold yellow
ANSI_EV_ALLOW = '1;32'   # bold green
ANSI_EV_START = '0;36'   # cyan
ANSI_EV_END   = '2;37'   # dim white
ANSI_GEO      = '0;32'   # green for geo annotations

_P_MAC      = 1    # pairs 1-8
_P_IP4      = 9
_P_SRCH     = 10
_P_STAT     = 11
_P_KEYS     = 12
_P_IP6      = 13
_P_SEV      = 14   # pairs 14-21 (8 severity levels)
_P_PORT     = 22
_P_IFACE    = 23
_P_DEDUP    = 24
_P_EV_DENY  = 25
_P_EV_ERROR = 26
_P_EV_ALLOW = 27
_P_EV_START = 28
_P_EV_END   = 29
_P_GEO      = 30

_MAC_CURSES = [
    curses.COLOR_RED, curses.COLOR_YELLOW, curses.COLOR_MAGENTA,
    curses.COLOR_CYAN, curses.COLOR_WHITE, curses.COLOR_YELLOW,
    curses.COLOR_CYAN, curses.COLOR_MAGENTA,
]
_MAC_BOLD = [True, True, True, True, False, False, False, False]

# (pattern, glyph, ansi_code, curses_pair, bold) — priority: deny > error > allow > start > end
_EV_TABLE = [
    (_EV_DENY,  '✗ ', ANSI_EV_DENY,  _P_EV_DENY,  True),
    (_EV_ERROR, '! ', ANSI_EV_ERROR, _P_EV_ERROR, True),
    (_EV_ALLOW, '✓ ', ANSI_EV_ALLOW, _P_EV_ALLOW, True),
    (_EV_START, '↑ ', ANSI_EV_START, _P_EV_START, False),
    (_EV_END,   '↓ ', ANSI_EV_END,   _P_EV_END,   False),
]

def _event_type(text):
    """Return (glyph, ansi, pair, bold) for the first matching event category, or None."""
    for pat, glyph, ansi, pair, bold in _EV_TABLE:
        if pat.search(text):
            return glyph, ansi, pair, bold
    return None

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
            return d.get('map', {}), d.get('index', 0), d.get('col_hidden', {})
        except Exception:
            pass
    return {}, 0, {}

def save_color_map(path, mac_map, idx, col_hidden=None):
    data = {'map': mac_map, 'index': idx}
    if col_hidden:
        data['col_hidden'] = col_hidden
    try:
        path.write_text(json.dumps(data, indent=2))
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

    def add(s, e, disp, ansi, pair, bold=True, geo=''):
        if not overlaps(s, e):
            segs.append((s, e, disp, ansi, pair, bold, geo))
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
        geo = geo_lookup(m.group())
        add(m.start(), m.end(), m.group(), ANSI_IP4, _P_IP4, geo=geo or '')

    # IPv6
    for m in IP6_RE.finditer(line):
        geo = geo_lookup(m.group())
        add(m.start(), m.end(), m.group(), ANSI_IP6, _P_IP6, geo=geo or '')

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
    ev   = _event_type(line)
    segs = _collect_segments(line, vendors, mac_map, ctr, search_term, search_is_regex)
    out  = [_a(ev[0], ev[1]) if ev else '  ']
    prev = 0
    for s, e, disp, ansi, _pair, _bold, geo in segs:
        out.append(line[prev:s])
        out.append(_a(disp, ansi))
        if geo:
            out.append(_a(f' ({geo})', ANSI_GEO))
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

# ── Column helpers ────────────────────────────────────────────────────────────

def _file_base(path):
    """Base name before the first dot: firewall.log.10.gz → firewall"""
    name = Path(path).name
    dot  = name.find('.')
    return name[:dot] if dot != -1 else name

def _strip_cols(text, n):
    """Remove the first n columns (delimited by runs of space/tab/comma)."""
    if n <= 0:
        return text
    pos = 0
    L   = len(text)
    for _ in range(n):
        while pos < L and text[pos] in ' \t,':
            pos += 1
        if pos >= L:
            return ''
        while pos < L and text[pos] not in ' \t,':
            pos += 1
    while pos < L and text[pos] in ' \t,':
        pos += 1
    return text[pos:]

# ── Large-file buffered access ────────────────────────────────────────────────

class LargeFile:
    """Wraps a huge file with a mmap + byte-offset index so only the visible
    window is ever held in memory.  Index cost: 8 bytes per line."""

    def __init__(self, path):
        self._f   = open(path, 'rb')
        self._mm  = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        size      = len(self._mm)
        offs      = array.array('Q', [0])
        pos       = 0
        while pos < size:
            nl = self._mm.find(b'\n', pos)
            if nl == -1:
                break
            offs.append(nl + 1)
            pos = nl + 1
        # Drop the phantom empty entry produced by a trailing newline
        if offs and offs[-1] >= size:
            offs.pop()
        self._offs = offs

    def __len__(self):
        return len(self._offs)

    def _line(self, i):
        start = self._offs[i]
        end   = self._offs[i + 1] if i + 1 < len(self._offs) else len(self._mm)
        return self._mm[start:end].rstrip(b'\r\n').decode('utf-8', errors='replace')

    def __getitem__(self, key):
        n = len(self._offs)
        if isinstance(key, slice):
            return [self._line(i) for i in range(*key.indices(n))]
        if key < 0:
            key += n
        return self._line(key)

    def __iter__(self):
        for i in range(len(self._offs)):
            yield self._line(i)

    def close(self):
        self._mm.close()
        self._f.close()


class LargeFileView:
    """Adapts a LargeFile to the (text, count) tuple interface used by
    _render and collect_stats, reading only requested lines from disk."""

    def __init__(self, lf):
        self._lf = lf

    def __len__(self):
        return len(self._lf)

    def __getitem__(self, key):
        if isinstance(key, slice):
            return [(t, 1) for t in self._lf[key]]
        return (self._lf[key], 1)

    def __iter__(self):
        for text in self._lf:
            yield (text, 1)


# ── Statistics ────────────────────────────────────────────────────────────────

def collect_stats(view, vendors, progress_cb=None):
    ip4, ip6, macs, ports, sevs = Counter(), Counter(), Counter(), Counter(), Counter()
    total = len(view)
    for i, (text, count) in enumerate(view):
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
        if progress_cb and i % 200 == 0:
            progress_cb(i, total)
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
    curses.init_pair(_P_PORT,     curses.COLOR_YELLOW,  -1)
    curses.init_pair(_P_IFACE,    curses.COLOR_MAGENTA, -1)
    curses.init_pair(_P_DEDUP,    curses.COLOR_BLACK,   curses.COLOR_WHITE)
    curses.init_pair(_P_EV_DENY,  curses.COLOR_RED,     -1)
    curses.init_pair(_P_EV_ERROR, curses.COLOR_YELLOW,  -1)
    curses.init_pair(_P_EV_ALLOW, curses.COLOR_GREEN,   -1)
    curses.init_pair(_P_EV_START, curses.COLOR_CYAN,    -1)
    curses.init_pair(_P_EV_END,   curses.COLOR_WHITE,   -1)
    curses.init_pair(_P_GEO,      curses.COLOR_GREEN,   -1)

# ── Curses line drawing ───────────────────────────────────────────────────────

def _draw_line(win, y, text, count, vendors, mac_map, ctr,
               search_term, search_is_regex, width, show_ln, linenum, dedup_on, hidden_cols=0):
    # Detect event type from original text BEFORE column stripping so the
    # glyph still reflects the event even when the keyword column is hidden.
    ev      = _event_type(text)
    glyph   = ev[0] if ev else '  '
    ev_attr = (curses.color_pair(ev[2]) | curses.A_BOLD) if (ev and ev[3]) else \
              (curses.color_pair(ev[2]) if ev else 0)
    try:
        win.addstr(y, 0, glyph, ev_attr)
    except curses.error:
        return
    x = 2  # glyph is always 2 display columns

    if hidden_cols:
        text = _strip_cols(text, hidden_cols)

    if show_ln:
        prefix = f'{linenum+1:6} '
        try:
            win.addstr(y, 0, prefix[:width - 1], curses.A_DIM)
            x = len(prefix)
        except curses.error:
            return

    segs = _collect_segments(text, vendors, mac_map, ctr, search_term, search_is_regex)
    prev = 0
    for src_s, src_e, disp, _ansi, pair, bold, geo in segs:
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
        if geo and x < width - 1:
            try:
                geo_text = f' ({geo})'
                cut = geo_text[:width - 1 - x]
                win.addstr(y, x, cut, curses.color_pair(_P_GEO))
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
                 dedup_on, show_ln, alert_pat, large_file=False, hidden_cols=0):
    mode  = "REGEX" if is_regex else "TEXT"
    parts = [f"[Search: {term or 'None'} ({mode})]"]
    if large_file:  parts.append("[LARGE FILE]")
    if hidden_cols: parts.append(f"[COLS HIDDEN: {hidden_cols}]")
    if filt:        parts.append(f"Filter: {filt}")
    if dedup_on:    parts.append("DEDUP")
    if show_ln:     parts.append("#")
    if alert_pat:   parts.append(f"ALERT:{alert_pat}")
    end   = min(offset + height - 2, total)
    line1 = "  ".join(parts) + f"  {offset+1}-{end}/{total}"
    if large_file:
        line2 = ("↑↓/WS=scroll  PgUp/Dn/Space=page  g/G=top/bot  "
                 "/=text  r=regex  h/u=hide-col  x=stats  c=clear  q=quit")
    else:
        line2 = ("↑↓/WS=scroll  PgUp/Dn/Space=page  g/G=top/bot  "
                 "/=text  r=regex  n/p=match  f=filter  "
                 "d=dedup  #=linenum  h/u=hide-col  x=stats  e=export  c=clear  q=quit")
    try:
        win.addstr(height - 2, 0, line1[:width - 1], curses.color_pair(_P_STAT))
        win.clrtoeol()
        win.addstr(height - 1, 0, line2[:width - 1], curses.color_pair(_P_KEYS))
        win.clrtoeol()
    except curses.error:
        pass

# ── Curses full render ────────────────────────────────────────────────────────

def _render(win, view, offset, vendors, mac_map, ctr, term, is_regex, show_ln, dedup_on, hidden_cols=0):
    height, width = win.getmaxyx()
    win.erase()
    for i in range(height - 2):
        idx = offset + i
        if idx >= len(view):
            break
        text, count = view[idx]
        _draw_line(win, i, text, count, vendors, mac_map, ctr,
                   term, is_regex, width, show_ln, idx, dedup_on, hidden_cols)

# ── Stats popup ───────────────────────────────────────────────────────────────

def _draw_stats(stdscr, view, vendors):
    height, width = stdscr.getmaxyx()
    total = len(view)

    if total > 200:
        bw   = min(50, width - 4)
        bh   = 5
        by_  = (height - bh) // 2
        bx_  = (width  - bw) // 2
        bwin = curses.newwin(bh, bw, by_, bx_)
        bar_w = bw - 4

        def _progress(done, tot):
            pct  = done / tot if tot else 1.0
            fill = int(pct * bar_w)
            bwin.erase()
            bwin.box()
            bwin.addstr(0, 2, " Computing Statistics ", curses.A_BOLD)
            bwin.addstr(2, 2, f"[{'#' * fill}{' ' * (bar_w - fill)}]")
            bwin.addstr(3, 2, f"{int(pct * 100):3d}%  {done:,} / {tot:,} lines")
            bwin.refresh()

        _progress(0, total)
        ip4, ip6, macs, ports, sevs = collect_stats(view, vendors, _progress)
        del bwin
    else:
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

def _tui(stdscr, lines, vendors, mac_map, ctr, alert_pat=None, col_hidden=None, file_base=None):
    _init_colors()
    curses.curs_set(0)
    stdscr.keypad(True)

    large_file  = isinstance(lines, LargeFile)
    filtered    = lines if large_file else lines[:]
    dedup_on    = False
    show_ln     = False
    offset      = 0
    term        = None
    is_regex    = False
    matches     = []
    filt        = None
    hidden_cols = (col_hidden or {}).get(file_base or '', 0)

    def get_view():
        if large_file:
            return LargeFileView(lines)
        return dedup_lines(filtered) if dedup_on else as_view(filtered)

    view = get_view()

    while True:
        height, width = stdscr.getmaxyx()
        page = max(1, height - 2)

        _render(stdscr, view, offset, vendors, mac_map, ctr, term, is_regex, show_ln, dedup_on, hidden_cols)
        _draw_status(stdscr, height, width, term, is_regex, filt, offset, len(view),
                     dedup_on, show_ln, alert_pat, large_file, hidden_cols)
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
                if not large_file:
                    matches = find_matches(view, term, False)
                    if matches: offset = matches[0]

        elif ch == ord('r'):
            t = _read_line(stdscr, "Search (regex): ")
            if t:
                try:
                    re.compile(t, re.I)
                    term, is_regex = t, True
                    if not large_file:
                        matches = find_matches(view, term, True)
                        if matches: offset = matches[0]
                except re.error as e:
                    h, w = stdscr.getmaxyx()
                    stdscr.addstr(h - 2, 0, f"Invalid regex: {e}  (press any key)"[:w-1],
                                  curses.color_pair(_P_STAT))
                    stdscr.clrtoeol(); stdscr.refresh(); stdscr.getch()

        elif ch == ord('n'):
            if not large_file and term and matches:
                for ln in matches:
                    if ln > offset: offset = ln; break

        elif ch == ord('p'):
            if not large_file and term and matches:
                for ln in reversed(matches):
                    if ln < offset: offset = ln; break

        elif ch == ord('f'):
            if large_file:
                h, w = stdscr.getmaxyx()
                stdscr.addstr(h - 2, 0, "Filter not available in large file mode  (press any key)"[:w-1],
                              curses.color_pair(_P_STAT))
                stdscr.clrtoeol(); stdscr.refresh(); stdscr.getch()
            else:
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
            if large_file:
                h, w = stdscr.getmaxyx()
                stdscr.addstr(h - 2, 0, "Dedup not available in large file mode  (press any key)"[:w-1],
                              curses.color_pair(_P_STAT))
                stdscr.clrtoeol(); stdscr.refresh(); stdscr.getch()
            else:
                dedup_on = not dedup_on
                view    = get_view()
                offset  = max(0, min(offset, max(0, len(view) - 1)))
                matches = find_matches(view, term, is_regex) if term else []

        elif ch == ord('#'):
            if not large_file:
                show_ln = not show_ln

        elif ch == ord('x'):
            _draw_stats(stdscr, view, vendors)

        elif ch == ord('e'):
            if large_file:
                h, w = stdscr.getmaxyx()
                stdscr.addstr(h - 2, 0, "Export not available in large file mode  (press any key)"[:w-1],
                              curses.color_pair(_P_STAT))
                stdscr.clrtoeol(); stdscr.refresh(); stdscr.getch()
            else:
                export = 'logview_filtered_export.txt'
                try:
                    Path(export).write_text('\n'.join(t for t, _ in view))
                    msg = f"Exported {len(view)} lines to {export}  (press any key)"
                except OSError as e:
                    msg = f"Export failed: {e}  (press any key)"
                h, w = stdscr.getmaxyx()
                stdscr.addstr(h - 2, 0, msg[:w-1], curses.color_pair(_P_STAT))
                stdscr.clrtoeol(); stdscr.refresh(); stdscr.getch()

        elif ch == ord('h'):
            hidden_cols += 1

        elif ch == ord('u'):
            hidden_cols = max(0, hidden_cols - 1)

        elif ch == ord('c'):
            if large_file:
                term = filt = None
                is_regex = False
                matches  = []
                offset   = 0
            else:
                filtered = lines[:]
                filt = term = None
                is_regex = dedup_on = False
                matches = []; offset = 0
                view = get_view()

        elif ch == ord('q'):
            break

        offset = max(0, min(offset, max(0, len(view) - page)))

    if col_hidden is not None and file_base:
        col_hidden[file_base] = hidden_cols
    save_color_map(COLOR_FILE, mac_map, ctr[0], col_hidden)

# ── Run modes ─────────────────────────────────────────────────────────────────

def piped_mode(vendors, mac_map, ctr):
    try:
        for line in sys.stdin:
            print(highlight_ansi(line.rstrip('\n'), vendors, mac_map, ctr))
    finally:
        save_color_map(COLOR_FILE, mac_map, ctr[0])


def _tail_lines(path, n, block=65536):
    """Read the last n lines of a file without loading it all into memory."""
    lines = []
    with open(path, 'rb') as f:
        f.seek(0, 2)
        remaining = f.tell()
        buf = b''
        while remaining > 0 and len(lines) <= n:
            read_size = min(block, remaining)
            remaining -= read_size
            f.seek(remaining)
            buf = f.read(read_size) + buf
            lines = buf.split(b'\n')
        if lines and lines[-1] == b'':
            lines.pop()
    return [l.decode('utf-8', errors='replace') for l in lines[-n:]]


def tail_mode(log_file, tail_lines_count, vendors, mac_map, ctr, alert_pat=None,
              col_hidden=None, file_base=None, egrep_pat=None):
    hidden_cols = (col_hidden or {}).get(file_base or '', 0)

    egrep_re = None
    if egrep_pat:
        try:
            egrep_re = re.compile(egrep_pat)
        except re.error as e:
            sys.exit(f"Invalid egrep pattern: {e}")
        print(_a(f'[filter: {egrep_pat}]', '0;36'), flush=True)

    if log_file.name.endswith('.gz'):
        with gzip.open(log_file, 'rt', errors='replace') as gz:
            all_lines = gz.read().splitlines()
        if egrep_re:
            all_lines = [l for l in all_lines if egrep_re.search(l)]
        for line in all_lines[-tail_lines_count:]:
            out = _strip_cols(line, hidden_cols) if hidden_cols else line
            print(highlight_ansi(out, vendors, mac_map, ctr))
        save_color_map(COLOR_FILE, mac_map, ctr[0])
        return   # can't follow a compressed file

    tail_lines = _tail_lines(log_file, tail_lines_count)
    if egrep_re:
        tail_lines = [l for l in tail_lines if egrep_re.search(l)]
    for line in tail_lines:
        out = _strip_cols(line, hidden_cols) if hidden_cols else line
        print(highlight_ansi(out, vendors, mac_map, ctr))

    last_size   = log_file.stat().st_size
    last_reload = time.time()
    buf         = list(tail_lines)
    paused      = False
    alert_re    = re.compile(alert_pat, re.I) if alert_pat else None

    if not HAS_TERMIOS:
        # Fallback: no pause/keypress support
        try:
            while True:
                if time.time() - last_reload >= 5:
                    new_map, _, _2 = load_color_map(COLOR_FILE)
                    mac_map.update(new_map)
                    last_reload = time.time()
                cur_size = log_file.stat().st_size
                if cur_size > last_size:
                    with open(log_file, errors='replace') as f:
                        f.seek(last_size)
                        for raw in f:
                            line = raw.rstrip('\n')
                            if egrep_re and not egrep_re.search(line):
                                continue
                            buf.append(line)
                            if len(buf) > 10000: buf.pop(0)
                            out = _strip_cols(line, hidden_cols) if hidden_cols else line
                            colored = highlight_ansi(out, vendors, mac_map, ctr)
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

    # Raw-input mode: Space=pause, h=hide col, u=unhide col, q=quit
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
                elif ch in ('h', 'H'):
                    hidden_cols += 1
                    sys.stdout.write(f'\r\033[0;33m[COLS HIDDEN: {hidden_cols}]\033[0m\r\n')
                    sys.stdout.flush()
                elif ch in ('u', 'U'):
                    hidden_cols = max(0, hidden_cols - 1)
                    label = f'COLS HIDDEN: {hidden_cols}' if hidden_cols else 'All cols shown'
                    sys.stdout.write(f'\r\033[0;33m[{label}]\033[0m\r\n')
                    sys.stdout.flush()
                elif ch in ('q', 'Q', '\x03', '\x04'):
                    break

            if paused:
                continue

            if time.time() - last_reload >= 5:
                new_map, _, _2 = load_color_map(COLOR_FILE)
                mac_map.update(new_map)
                last_reload = time.time()

            cur_size = log_file.stat().st_size
            if cur_size > last_size:
                with open(log_file, errors='replace') as f:
                    f.seek(last_size)
                    for raw in f:
                        line = raw.rstrip('\n')
                        if egrep_re and not egrep_re.search(line):
                            continue
                        buf.append(line)
                        if len(buf) > 10000: buf.pop(0)
                        out = _strip_cols(line, hidden_cols) if hidden_cols else line
                        colored = highlight_ansi(out, vendors, mac_map, ctr)
                        if alert_re and alert_re.search(line):
                            sys.stdout.write('\a')
                            colored = _a('▶ ', '1;31') + colored
                        print(colored, flush=True)
                last_size = cur_size

    except KeyboardInterrupt:
        pass
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old)
        if col_hidden is not None and file_base:
            col_hidden[file_base] = hidden_cols
        save_color_map(COLOR_FILE, mac_map, ctr[0], col_hidden)


def _decompress_gz(src):
    """Decompress a .gz file to a NamedTemporaryFile; caller must delete it."""
    print(f"Decompressing {src.name}...", file=sys.stderr)
    tf = tempfile.NamedTemporaryFile(delete=False, suffix='.log')
    try:
        with gzip.open(src, 'rb') as gz:
            while True:
                chunk = gz.read(8 * 1024 * 1024)
                if not chunk:
                    break
                tf.write(chunk)
    finally:
        tf.close()
    return Path(tf.name)


def interactive_mode(files, vendors, mac_map, ctr, alert_pat=None, col_hidden=None, file_base=None):
    # Decompress any .gz files to temp files first
    temps   = []   # temp paths to delete on exit
    actual  = []   # (real_path, display_path) pairs
    for f in files:
        if f.name.endswith('.gz'):
            tmp = _decompress_gz(f)
            temps.append(tmp)
            actual.append((tmp, f))
        else:
            actual.append((f, f))

    try:
        real_files = [r for r, _ in actual]
        total_size = sum(r.stat().st_size for r in real_files)

        if len(real_files) == 1 and total_size > LARGE_FILE_THRESHOLD:
            lf = LargeFile(real_files[0])
            try:
                curses.wrapper(_tui, lf, vendors, mac_map, ctr, alert_pat, col_hidden, file_base)
            finally:
                lf.close()
        else:
            all_lines = []
            for real, disp in actual:
                if len(actual) > 1:
                    all_lines.append(f'{"─"*4} {disp} {"─"*4}')
                all_lines.extend(real.read_text(errors='replace').splitlines())
            curses.wrapper(_tui, all_lines, vendors, mac_map, ctr, alert_pat, col_hidden, file_base)
    finally:
        for tmp in temps:
            try:
                os.unlink(tmp)
            except OSError:
                pass

# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    follow      = False
    tail_lines  = 10
    log_files   = []
    alert_pat   = None
    egrep_pat   = None
    args        = sys.argv[1:]
    positionals = []
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
            positionals.append(a)
        i += 1

    # In follow mode: if two or more positional args, first is egrep filter, rest are files
    if follow and len(positionals) >= 2:
        egrep_pat   = positionals[0]
        file_args   = positionals[1:]
    else:
        file_args   = positionals

    for a in file_args:
        matches = sorted(glob.glob(a))
        for p in (matches or [a]):
            log_files.append(Path(p))

    return follow, tail_lines, log_files, alert_pat, egrep_pat


def main():
    global _GEO_READER
    follow, tail_lines, log_files, alert_pat, egrep_pat = parse_args()
    vendors = load_oui(OUI_FILE)
    mac_map, idx, col_hidden = load_color_map(COLOR_FILE)
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
            sys.exit('Usage: netlog.py -f [-n N] [--alert PATTERN] ["egrep_pattern"] <file>')
        lf = log_files[0]
        if not lf.exists():
            sys.exit(f"File not found: {lf}")
        file_base = _file_base(lf)
        tail_mode(lf, tail_lines, vendors, mac_map, ctr, alert_pat, col_hidden, file_base, egrep_pat)
    elif log_files:
        missing = [f for f in log_files if not f.exists()]
        if missing:
            sys.exit(f"File not found: {missing[0]}")
        file_base = _file_base(log_files[0])
        interactive_mode(log_files, vendors, mac_map, ctr, alert_pat, col_hidden, file_base)
    else:
        print('Usage: netlog.py [-f] [-n N] [--alert PATTERN] ["egrep_pattern"] <file> [file2 ...]',
              file=sys.stderr)
        print("Or:    cat file.log | netlog.py", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
