# netlog

A terminal network log viewer written in Python. Designed for sysadmins and network engineers who live in the shell — it adds smart color highlighting, vendor identification, GeoIP lookup, and a full interactive TUI on top of any log file, with no external dependencies beyond the Python standard library.

---

## Features

- **Syntax highlighting** — MAC addresses (per-device color), IPv4, IPv6, ports with service names, syslog severity levels, and network interfaces are all colored automatically
- **Event-type prefix glyphs** — every line gets a 2-character indicator showing the nature of the event at a glance
- **MAC vendor lookup** — IEEE OUI database is auto-downloaded; each unique MAC gets a persistent color across sessions
- **GeoIP lookup** — optionally annotates IP addresses with city/country using MaxMind GeoLite2
- **Interactive TUI** — full-screen curses viewer with search, filter, dedup, stats, column hiding, and export
- **Large file support** — files over 50 MB are accessed via `mmap` + a byte-offset index so only the visible screen is ever in RAM
- **Automatic `.gz` decompression** — open compressed logs directly; follow mode handles them gracefully too
- **Follow mode** — `tail -f`-style real-time monitoring with optional egrep filter and audio/visual alerts
- **Piped input** — `cat file.log | netlog.py` works; all highlighting applies

---

## Requirements

- Python 3.8+ (standard library only for core functionality)
- `maxminddb` Python package — optional, enables GeoIP lookup (`pip install maxminddb`)

---

## Installation

```bash
git clone <repo>
cd netlog
chmod +x netlog.py
```

The OUI vendor database (`oui.txt`) is downloaded automatically from Wireshark on first run.

---

## Usage

```
netlog.py <file> [file2 ...]                   Interactive TUI viewer
netlog.py -f <file>                            Follow mode (like tail -f)
netlog.py -f -n 50 <file>                      Follow, showing last 50 lines first
netlog.py -f "pattern" <file>                  Follow, only showing lines matching pattern
netlog.py -f --alert PATTERN <file>            Follow with alert bell on pattern match
cat file.log | netlog.py                       Piped/ANSI mode
```

Multiple files and shell globs are supported:

```bash
netlog.py /var/log/syslog /var/log/kern.log
netlog.py /var/log/firewall.log*
netlog.py /var/log/firewall.log.10.gz
```

---

## Interactive TUI Keys

| Key | Action |
|-----|--------|
| `↑` `↓` `W` `S` | Scroll one line |
| `PgUp` `PgDn` `Space` | Scroll one page |
| `g` `G` | Jump to top / bottom |
| `/` | Search (plain text) |
| `r` | Search (regex) |
| `n` `p` | Next / previous match |
| `f` | Filter lines (plain or `r:regex`) |
| `d` | Toggle consecutive-duplicate dedup |
| `#` | Toggle line numbers |
| `h` `u` | Hide / unhide leftmost column |
| `x` | Show statistics popup |
| `e` | Export current view to file |
| `c` | Clear all filters and search |
| `q` | Quit |

---

## Event-Type Prefix Glyphs

Every line in the viewer (and in piped output) starts with a 2-character glyph showing the event category. Lines that don't match any category show two spaces so unmatched lines stay visually uncluttered.

| Glyph | Color | Matches |
|-------|-------|---------|
| `✗ ` | Red bold | deny, denied, drop, block, reject, refuse, discard |
| `! ` | Yellow bold | error, fail, failed, failure, invalid, corrupt |
| `✓ ` | Green bold | allow, permit, accept, pass, forward |
| `↑ ` | Cyan | built, start, open, established, connect |
| `↓ ` | Dim | teardown, close, expire, terminate, reset |
| `  ` | — | anything else |

Priority is deny → error → allow → start → end, so a line containing both "permit" and "failed" correctly shows `! `.

---

## Column Hiding

Large log formats often have timestamps, hostnames, or other fields at the left that you already know and don't need to see.

- `h` hides the next column from the left
- `u` unhides the rightmost hidden column
- Columns are delimited by any run of spaces, tabs, or commas

The hidden column count is saved per **file base name** (everything before the first `.`) in `mac_colors.json`. This means `firewall.log`, `firewall.log.1`, and `firewall.log.10.gz` all share the same column setting.

The event-type glyph is always detected from the full original line, so the indicator remains correct even when the keyword column is itself hidden.

---

## Statistics

Press `x` to open the statistics popup. On large files a progress bar shows the scan progress. The popup reports:

- Top IPv4 addresses (by occurrence)
- Top IPv6 addresses
- Top MAC addresses with vendor name
- Top ports with well-known service names
- Severity level counts (EMERG through DEBUG)

---

## Large File Support

Files larger than 50 MB are automatically opened in large-file mode:

- An `array`-backed byte-offset index (8 bytes per line) is built in one mmap pass
- Only the lines visible on screen are read from disk during scrolling
- A 1 GB file with 10 M lines uses ~80 MB for the index vs several GB for a full in-memory load

Features unavailable in large-file mode (noted in the status bar): filter, dedup, search navigation (n/p), line numbers, and export. Scrolling, search highlighting, stats, column hiding, and event glyphs all work normally.

---

## GeoIP Setup

GeoIP annotation requires a free MaxMind account and the `maxminddb` package.

```bash
pip install maxminddb
```

On first run with a MaxMind account ID and license key, `netlog.py` will offer to download `GeoLite2-City.mmdb` automatically. Credentials are saved to `netlog_config.json` for future updates.

The database is also found automatically if already installed system-wide (common paths under `/usr/share/GeoIP/` and `/var/lib/GeoIP/` are checked).

---

## Persistent State

`mac_colors.json` (stored next to `netlog.py`) persists:

- MAC address → color assignments (so the same device always gets the same color)
- Hidden column counts per file base name

`netlog_config.json` persists:

- MaxMind GeoIP credentials (account ID + license key)

---

## Follow Mode

```bash
netlog.py -f /var/log/firewall.log
netlog.py -f "deny|drop" /var/log/firewall.log
netlog.py -f -n 50 "WARN|ERR" /var/log/syslog
netlog.py -f --alert "DENY" /var/log/firewall.log
```

- Displays the last 10 lines (configurable with `-n N`) then streams new lines as they arrive
- An optional egrep-style filter pattern (extended regex, in quotes) placed **before the filename** limits output to matching lines only — both the initial tail and the live stream are filtered; a `[filter: ...]` header is printed at startup
- `Space` pauses/resumes the stream
- `q` quits
- `--alert PATTERN` triggers a terminal bell and highlights matching lines with `▶` when the pattern matches a new line
- `.gz` files are decompressed and displayed, then exit (compressed files cannot be followed)

---

## Piped Mode

```bash
cat /var/log/syslog | netlog.py
journalctl -f | netlog.py
ssh host 'tail -f /var/log/auth.log' | netlog.py
```

All ANSI highlighting — including event glyphs — is applied to stdout. Color map is updated and saved on exit.

---

## Files

| File | Purpose |
|------|---------|
| `netlog.py` | Main script |
| `oui.txt` | IEEE OUI vendor database (auto-downloaded) |
| `mac_colors.json` | Persistent MAC colors and column settings |
| `netlog_config.json` | GeoIP credentials and other config |
| `GeoLite2-City.mmdb` | MaxMind GeoIP database (optional, auto-downloaded) |

---

Copyright 2025 supertechguy.com — GPL
