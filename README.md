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
- **Piped input** — `cat file.log | netlog` works; all highlighting applies

---

## Requirements

- Python 3.8+ (standard library only for core functionality)
- `maxminddb` Python package — optional, enables GeoIP lookup (`pip install maxminddb`)

---

## Installation

### Run in place

```bash
git clone <repo>
cd netlog
chmod +x netlog
./netlog <file>
```

### Install so it runs from anywhere

```bash
git clone <repo>
cd netlog
./install.sh              # installs to ~/.local/bin/netlog (no sudo needed)
./install.sh --system     # installs to /usr/local/bin/netlog instead (may need sudo)
./install.sh --prefix DIR # installs to DIR/bin/netlog
```

After installing, make sure the target `bin` directory is on your `PATH` (the
script tells you if it isn't), then run it as `netlog` from anywhere:

```bash
netlog /var/log/syslog
```

The OUI vendor database (`oui.txt`) is downloaded automatically from Wireshark on first run
(`install.sh` pre-seeds it from this checkout if it's already been downloaded once).

---

## Usage

```
netlog <file> [file2 ...]                   Interactive TUI viewer
netlog -f <file>                            Follow mode (like tail -f)
netlog -f -n 50 <file>                      Follow, showing last 50 lines first
netlog -f "pattern" <file>                  Follow, only showing lines matching pattern
netlog -f --alert PATTERN <file>            Follow with alert bell on pattern match
cat file.log | netlog                       Piped/ANSI mode
netlog --setup-geoip                        Configure (or reconfigure) MaxMind GeoIP
netlog --version                            Print version and exit
netlog --help                               Full option reference
```

(From a git clone, run it as `./netlog`; once installed via `install.sh`, just `netlog` from any directory.)

Multiple files and shell globs are supported:

```bash
netlog /var/log/syslog /var/log/kern.log
netlog /var/log/firewall.log*
netlog /var/log/firewall.log.10.gz
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

The first time `netlog` runs interactively (a real terminal, not piped input) with no GeoIP database found anywhere, it asks:

```
Set up MaxMind GeoIP now? [y/N]
```

Answer `y` and it prints links to sign up and generate a license key, then prompts for your Account ID and license key and downloads `GeoLite2-City.mmdb`. Credentials are saved to `netlog_config.json` (mode `600`, since it holds a secret) for future updates.

Answer `n` (or just hit enter) and netlog remembers the decline — it won't ask again. Run `netlog --setup-geoip` any time afterward to configure it (or update stored credentials).

netlog never prompts when stdin isn't an interactive terminal (piped input, cron, CI, etc.) — it just runs without GeoIP in that case.

The database is also found automatically if already installed system-wide (common paths under `/usr/share/GeoIP/` and `/var/lib/GeoIP/` are checked).

---

## Persistent State

netlog's data files — `oui.txt`, `mac_colors.json`, `netlog_config.json`, and `GeoLite2-City.mmdb` — live in a per-user **data directory**, resolved in this order:

1. `$NETLOG_DATA_DIR`, if set
2. The script's own directory, if it's a dev checkout (i.e. has a `.git` next to it)
3. `$XDG_DATA_HOME/netlog`, or `~/.local/share/netlog` if `XDG_DATA_HOME` isn't set

Running `netlog` straight from a git clone (as in "Run in place" above) keeps everything next to the script, same as before. An `install.sh`-installed copy has no `.git` next to it, so it automatically uses `~/.local/share/netlog` instead — which also means the install location itself (`/usr/local/bin`, etc.) never needs to be writable after install.

`mac_colors.json` persists:

- MAC address → color assignments (so the same device always gets the same color)
- Hidden column counts per file base name

`netlog_config.json` (permissions `600`) persists:

- MaxMind GeoIP credentials (account ID + license key)
- Whether GeoIP setup was declined, so netlog doesn't ask again

---

## Follow Mode

```bash
netlog -f /var/log/firewall.log
netlog -f "deny|drop" /var/log/firewall.log
netlog -f -n 50 "WARN|ERR" /var/log/syslog
netlog -f --alert "DENY" /var/log/firewall.log
```

- Displays the last 10 lines (configurable with `-n N`) then streams new lines as they arrive
- An optional egrep-style filter pattern (extended regex, in quotes) placed **before the filename** limits output to matching lines only — both the initial tail and the live stream are filtered; a `[filter: ...]` header is printed at startup
- `Space` pauses/resumes the stream
- `q` quits
- `--alert PATTERN` triggers a terminal bell and highlights matching lines with `▶` when the pattern matches a new line
- `.gz` files are decompressed and displayed, then exit (compressed files cannot be followed)
- Log rotation is handled automatically: if the file is truncated or replaced (the usual `logrotate` pattern), netlog detects it and resumes streaming from the start of the new file, printing a `[Log rotated — resuming from new file]` notice

---

## Piped Mode

```bash
cat /var/log/syslog | netlog
journalctl -f | netlog
ssh host 'tail -f /var/log/auth.log' | netlog
```

All ANSI highlighting — including event glyphs — is applied to stdout. Color map is updated and saved on exit.

---

## Testing

A small `unittest` suite (stdlib only, no test framework dependency) covers the pure logic — highlighting/segment priority, dedup, column stripping, search, and CLI argument parsing:

```bash
python3 -m unittest discover -s tests -v
```

---

## Files

| File | Purpose |
|------|---------|
| `netlog` | Main script |
| `install.sh` | Installs `netlog` on PATH |
| `tests/` | Unit tests (`python3 -m unittest discover -s tests`) |
| `oui.txt` | IEEE OUI vendor database (auto-downloaded, in the data dir) |
| `mac_colors.json` | Persistent MAC colors and column settings (in the data dir) |
| `netlog_config.json` | GeoIP credentials and other config, mode `600` (in the data dir) |
| `GeoLite2-City.mmdb` | MaxMind GeoIP database (optional, auto-downloaded, in the data dir) |

See [Persistent State](#persistent-state) above for where "the data dir" resolves to.

---

Copyright 2025 supertechguy.com — [GPLv3](LICENSE)
