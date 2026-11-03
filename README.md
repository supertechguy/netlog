<p align="center">
  <img src="assets/netlog-logo.svg" alt="netlog — network log analyzer" width="560">
</p>

# netlog

A terminal network log viewer and analyzer written in Python. Designed for sysadmins and network engineers who live in the shell — it adds smart color highlighting, vendor identification, GeoIP lookup, and a full interactive TUI on top of any log file. It recognises the log formats of 28 vendor platforms (Cisco, Juniper, Aruba, Ruckus, Fortinet, Palo Alto, UniFi, Meraki, MikroTik, pfSense and more) across wireless, switching, routing and firewalls, plus any `key="value"` log. It correlates events per client, user, AP, interface and source IP to find failure loops, flapping links, login attacks, port scans and other problems. It produces a ranked security and error analytics report, health summaries and per-client timelines. You can filter logs down to the lines you care about as they load (`-g`). No external dependencies beyond the Python standard library.

---

## What's new

**1.5.0**
- `-g PATTERN` / `--grep PATTERN` loads only matching lines, in every mode. It replaces a `grep … > little.log` step (see [Load only the lines you need](#load-only-the-lines-you-need--g----grep)).
- New threshold options for the analytics: `--spray-accounts`, `--spray-sources`, `--spike-min`, `--spike-factor`, `--spike-window`.

**1.4.0**
- The statistics popup (`x`) became a full **analytics** report: ranked findings (critical → low) for brute force, password spraying, distributed login attacks, success after brute force, port/host scans, risky services exposed to the internet, internal hosts using risky services, spam bots, error spikes, noisy or silent devices and clock mismatches.
- 23 text detectors work on any log line: DHCP exhaustion, ARP spoofing, rogue APs, IP conflicts, storms, loops, crashes, memory/disk/table exhaustion, hardware, VPN, certificate, NTP and more (see [Findings](#findings)).
- New Linux / BSD format: OpenSSH `sshd`, `sudo` and PAM login failures and successes.
- The firewall statistics add top allowed ports, top talkers and protocols. Plain syslog gets top sending hosts and programs, and port counting no longer picks up MAC or timestamp fragments.
- `--summary` now starts with the same Findings list.

**1.3.0**
- 28 vendor log formats are detected and normalised (`netlog --formats`); see [Supported log formats](#supported-log-formats).
- Network and security findings: interface flapping, err-disabled ports, loops, routing neighbors, login attacks, scans, VPN, failover, hardware.
- `--flap-threshold`/`--flap-window`, `--brute-threshold`/`--brute-window` and `--scan-ports`/`--scan-hosts`/`--scan-window` options.
- TUI fixes and additions:
  - Search now highlights every match and `n`/`p` move between them, also in large-file mode.
  - The `f` filter works, including in large-file mode, and has `a|b`, `!exclude` and `r:regex` syntax.
  - New line wrapping, with indented continuation rows. Toggle it with `l` (remembered between runs) or `--wrap`/`--no-wrap`; wrapping also works in follow and piped output.

---

## Features

- **Syntax highlighting** — MAC addresses (per-device color), IPv4, IPv6, ports with service names, syslog severity levels, and network interfaces are all colored automatically
- **Event-type prefix glyphs** — every line gets a 2-character indicator showing the nature of the event at a glance
- **MAC vendor lookup** — IEEE OUI database is auto-downloaded; each unique MAC gets a persistent color across sessions
- **GeoIP lookup** — optionally annotates IP addresses with city/country using MaxMind GeoLite2
- **Interactive TUI** — full-screen curses viewer with search, filter, dedup, analytics, column hiding, line wrapping and export
- **Load-time filter (`-g`)** — load only the lines matching one or more patterns, in the viewer, analytics, summaries, follow mode and piped mode
- **Line wrapping** — long lines wrap at word boundaries with indented continuation rows, or are cut and panned sideways (`l`, `--wrap`/`--no-wrap`)
- **Large file support** — files over 50 MB are accessed via `mmap` + a byte-offset index so only the visible screen is ever in RAM
- **Automatic `.gz` decompression** — open compressed logs directly; follow mode handles them gracefully too
- **Follow mode** — `tail -f`-style real-time monitoring with optional egrep or `-g` filter and audio/visual alerts
- **Piped input** — `cat file.log | netlog` works; all highlighting applies
- **Structured log analysis** — parses `key="value"` fields (`clientMac=`, `userName=`, `apName=`, `apLocation=`, `ssid=`, `rssi=`, …), classifies events as error / warning / success, and tracks each client's session lifecycle
- **Health summary (`--summary`)** — a ranked list of findings (critical → low), then per-domain statistics: wireless clients/APs/locations, switching and routing, firewall traffic, authentication and infrastructure
- **Security and error analytics** — brute force, password spraying, success after failures, port/host scans, risky services exposed to the internet, internal hosts reaching risky services, error spikes, noisy or silent devices, and 23 text detectors (DHCP exhaustion, ARP spoofing, rogue APs, IP conflicts, storms, crashes, memory/disk exhaustion, conntrack full, certificate, VPN and NTP failures, …) that work on any log line
- **Client timeline (`--client`)** — a clean chronological narrative for one MAC or username, with its session path and findings
- **Failure-loop detection** — flags clients with N+ failures inside a rolling window, and groups those lines visually (banner + colored side bar) in the timeline, piped and follow modes
- **Diagnostic rules** — legacy SSID use, inconsistent username formats on one device, rapid roaming, low RSSI, and AP/location failure hotspots
- **Vendor format detection** — 28 wireless, switch, router, firewall and NAC log formats are detected per line and normalised to common fields and event kinds (`netlog --formats` lists them)
- **Network and security findings** — interface flapping, err-disabled ports, MAC flapping and loops, routing neighbor loss, login brute force (and success after failures), port and host scans, VPN, failover, hardware and service events
- **Configurable thresholds** — every detection rule's limits can be set on the command line (see [Diagnostic rules](#diagnostic-rules))

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
./install.sh              # asks: user install or system install
./install.sh --user       # installs to ~/.local/bin/netlog (just you, no sudo)
./install.sh --system     # installs to /usr/local/bin/netlog (all users; uses sudo if needed)
./install.sh --prefix DIR # installs to DIR/bin/netlog
```

Run `./install.sh` without `sudo`. If you choose a system install, the
script uses `sudo` only for the step that copies the program into
`/usr/local/bin`, so your own data folder still gets set up for you.
(Running the whole script with `sudo` and picking a user install
installs it for root only.)

After installing, make sure the target `bin` directory is on your `PATH` (the
script tells you if it isn't), then run it as `netlog` from anywhere:

```bash
netlog /var/log/syslog
```

The OUI vendor database (`oui.txt`) is downloaded automatically from Wireshark on first run
(`install.sh` pre-seeds it from this checkout if it's already been downloaded once).

### Uninstall

```bash
./install.sh --uninstall              # removes netlog from ~/.local/bin and/or /usr/local/bin
./install.sh --uninstall --system     # only from /usr/local/bin (likewise --user, --prefix DIR)
./install.sh --uninstall --purge      # also delete your netlog data without asking
./install.sh --uninstall --keep-data  # keep your netlog data without asking
```

Without `--purge` or `--keep-data`, it lists your netlog data files and asks
whether to delete them. Non-interactive runs keep the data. Only netlog's own files
(`oui.txt`, `mac_colors.json`, `netlog_config.json`, `GeoLite2-*.mmdb`) are
deleted, and the data folder is removed only if it's then empty.

---

## Usage

```
netlog <file> [file2 ...]                   Interactive TUI viewer
netlog -g PATTERN <file> ...                Load only lines matching PATTERN (any mode)
netlog -f <file>                            Follow mode (like tail -f)
netlog -f -n 50 <file>                      Follow, showing last 50 lines first
netlog -f "pattern" <file>                  Follow, only showing lines matching pattern
netlog -f --alert PATTERN <file>            Follow with alert bell on pattern match
cat file.log | netlog                       Piped/ANSI mode
netlog --summary <file> [file2 ...]         Health summary of structured events
netlog --client <MAC|user> <file> ...       Timeline for one client or user
netlog --summary --brute-threshold 10 ...   Tune a detection rule (see Diagnostic rules)
netlog --summary --top 25 <file>            More rows per section and per kind of finding
netlog --formats                            List recognised vendor log formats
netlog --no-wrap <file>                     Cut long lines instead of wrapping (--wrap to force on)
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

### Load only the lines you need (`-g` / `--grep`)

`-g PATTERN` filters the logs as they are read, so the viewer, analytics, `--summary`, `--client`, follow mode and piped mode only see matching lines. It replaces a `grep … > little.log` step:

```bash
netlog -g 10.146. schools.log                  # only lines containing 10.146.
netlog -g '10.146.|10.147.' schools.log        # either subnet
netlog -g 10.146. -g '!dhcp' schools.log       # repeat -g: every pattern must match
netlog -g 'r:\b10\.146\.2\.7\b' schools.log    # regex: exactly this address
netlog --summary -g 10.146. schools.log        # analytics on just those lines
```

The syntax is the same as the `f` filter in the viewer: plain text is a case-insensitive substring (a `.` is a literal dot, unlike in `grep`), `a|b` matches either, a leading `!` excludes, and `r:REGEX` is a case-insensitive regex. Plain text matches anywhere, so `10.146.2.7` also matches `10.146.2.70`; use `r:\b…\b` for an exact address. Before the viewer opens, matching lines are copied to a temporary file (deleted on exit). Big results still use large-file mode. The status bar shows `[N of M lines loaded]` and `[Grep: …]`. You can still use `f` to narrow the view further. If nothing matches, netlog says so and exits.

---

## Interactive TUI Keys

| Key | Action |
|-----|--------|
| `↑` `↓` `W` `S` | Scroll one line |
| `PgUp` `PgDn` `Space` | Scroll one page |
| `g` `G` | Jump to top / bottom |
| `/` | Search (plain text, case-insensitive) from the current screen position |
| `r` | Search (regex) |
| `n` `p` | Next / previous match, wrapping round the ends (also in large-file mode) |
| `Esc` | Cancel a search or filter prompt |
| `f` | Filter lines (see below); empty input removes the filter. Works in large-file mode too |
| `l` | Toggle wrapping of long lines (remembered between runs) |
| `←` `→` `Home` | Scroll sideways when not wrapping |
| `d` | Toggle consecutive-duplicate dedup |
| `#` | Toggle line numbers |
| `h` `u` | Hide / unhide leftmost column |
| `x` | Analytics popup: ranked findings and statistics for the current view |
| `e` | Export the current view (after filter/dedup) to `logview_filtered_export.txt` in the current directory |
| `c` | Clear all filters and search |
| `q` | Quit |

Filter syntax: plain text is case-insensitive; `deny|drop` keeps lines containing any of the terms; `!text` keeps lines that do *not* match (`!kernel|dhcp` hides both); `r:REGEX` is a case-insensitive regex (`!r:REGEX` to exclude). The status bar shows how many lines matched; if none do, the filter isn't applied.

Wrapped lines continue on the following rows indented four columns past the start of the text, breaking between words where possible. With wrapping off, long lines are cut at the screen edge and `←`/`→` scroll sideways; the event glyph stays in place.

Matches are highlighted in yellow (even inside IPs, MACs and other colored tokens), the current match in cyan, and the status bar shows `match 3/17` or `No matches`.

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

Structured `key="value"` events (see [Structured Log Analysis](#structured-log-analysis)) are classified by event name instead, which also catches camelCase names like `clientJoinFailure` that the keyword table can't:

| Glyph | Color | Structured event |
|-------|-------|------------------|
| `✗ ` | Red bold | Error: a failure (`clientJoinFailure`, `authTimeout`, or any event with `result="failure"`) |
| `! ` | Yellow bold | Warning: legacy SSID or low RSSI |
| `✓ ` | Green bold | Success: join / association / authorization |
| `↔ ` | Cyan | Roaming |
| `↓ ` | Dim | Disconnect / deauth / idle timeout / logout / session end |
| `↓ ` | Yellow bold | Interface link down |
| `↑ ` | Green bold | Interface link up |
| `↑ ` | Cyan | Firewall session start |

Recognised vendor events (see [Supported log formats](#supported-log-formats)) use the same table: anything at error severity shows `✗ `, firewall denies `✗ ` and allows `✓ `, then the kinds above, then `! ` / `✓ ` for other warnings and successes.

---

## Column Hiding

Large log formats often have timestamps, hostnames, or other fields at the left that you already know and don't need to see.

- `h` hides the next column from the left
- `u` unhides the rightmost hidden column
- Columns are delimited by any run of spaces, tabs, or commas

The hidden column count is saved per **file base name** (everything before the first `.`) in `mac_colors.json`. This means `firewall.log`, `firewall.log.1`, and `firewall.log.10.gz` all share the same column setting.

The event-type glyph is always detected from the full original line, so the indicator remains correct even when the keyword column is itself hidden.

---

## Analytics

Press `x` to open the analytics popup for the current view, so after filtering (`f`) it covers only the filtered lines. It's the same report as `--summary` (see [Findings](#findings)), followed by counts that are useful for any log:

- Top sending hosts and programs / message tags
- Top IPv4, IPv6 and MAC addresses (with vendor)
- Top destination / service ports (named port fields, or a port right after an IP; source ports and timestamps aren't counted)
- Syslog severity words

Scroll with `↑`/`↓`, `PgUp`/`PgDn`, `g`/`G`; pan with `←`/`→`; close with `q` or `Esc`. A progress bar shows on larger views (`Esc` cancels; a 300,000-line view takes about 30 s), and the result is cached until the view changes.

---

## Large File Support

Files larger than 50 MB are automatically opened in large-file mode:

- An `array`-backed byte-offset index (8 bytes per line) is built in one mmap pass
- Only the lines visible on screen are read from disk during scrolling
- A 1 GB file with 10 M lines uses ~80 MB for the index vs several GB for a full in-memory load

Features unavailable in large-file mode (noted in the status bar): dedup, line numbers and export. Scrolling, search and `n`/`p`, filtering, wrapping, analytics, column hiding and event glyphs all work normally. Filtering a large file scans it once, showing progress (`Esc` cancels).

With `-g`, only the matching lines are loaded, so a large log often becomes a small one. If the matches are still over 50 MB, they open in large-file mode.

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
- Whether long lines wrap (toggled with `l`)

---

## Structured Log Analysis

Wireless controllers and many other appliances log an event name followed by `key="value"` fields:

```
May  1 08:01:00 ctrl1 wlc: clientJoinFailure apName="AP-Gym-2" apMac="aa:bb:cc:00:00:02" apLocation="Gym" clientMac="f4:f5:d8:de:73:50" userName="alice" ssid="WCSDaccess-old" reason="802.1X timeout"
```

netlog parses these automatically: in every mode for the glyphs, and in `--summary` / `--client` for full analysis. Both modes read the given files (`.gz` included) or stdin:

```bash
netlog --summary /var/log/wlc.log*
netlog --client alice /var/log/wlc.log            # username: alice, alice@corp.org and CORP\alice all match
netlog --client F4F5.D8DE.7350 /var/log/wlc.log   # MAC in any notation
ssh ctrl1 'cat /var/log/wlc.log' | netlog --summary
```

### Supported log formats

Each line is checked against the vendor formats below (most specific first, with the format that matched the previous line tried first), and falls back to the generic `key=value` parser. Every format is normalised to the same fields (`host`, `client_mac`, `user`, `ap`, `ssid`, `src_ip`/`dst_ip`, `src_port`/`dst_port`, `proto`, `iface`, `rule`, …) and an event *kind*. `netlog --formats` prints this list with an example line for each.

| Vendor | Product | Class | Recognised by | Confidence |
|--------|---------|-------|---------------|------------|
| Ruckus | SmartZone / vSZ | wifi | `Core: @@<code>,<eventType>,"k"="v"` (codes 201–211 client events, AP events) | documented |
| CEF | UniFi Network and any CEF source | wifi, firewall | `CEF:Version\|Vendor\|Product\|…` | documented |
| LEEF | IBM LEEF 1.0/2.0 sources | firewall | `LEEF:` header | documented |
| Fortinet | FortiGate (incl. FortiAP/FortiSwitch) | firewall, wifi | `logid=` with `type=`/`subtype=`/`action=` | documented |
| Palo Alto Networks | PAN-OS CSV syslog | firewall | positional CSV: `TRAFFIC`, `THREAT`, `SYSTEM`, `CONFIG`, `GLOBALPROTECT`, … | documented |
| Cisco | ASA / Firepower FTD | firewall | `%ASA-n-NNNNNN:` / `%FTD-` message IDs | well known |
| Dell | OS10 | switch | `%Dell EMC (OS10)` | lower |
| Cisco / Arista / Dell | IOS, IOS-XE, NX-OS, 9800 & AireOS WLC, EOS | switch, router, wifi | `%FACILITY-SEV-MNEMONIC:` | documented |
| Sophos | Firewall (XG / SFOS) | firewall | `log_component=` key=value | lower |
| SonicWall | SonicOS | firewall | `id=firewall … m=<id>` | lower |
| Check Point | Quantum / Gaia syslog export | firewall | `product:"…"` / `origin:"…"` | lower |
| Cisco | ISE | NAC | `CISE_` categories | lower |
| FreeRADIUS | radiusd | NAC | `Auth: (n) Login OK/incorrect` | lower |
| Cisco Meraki | MR / MS / MX | wifi, switch, firewall | RFC 5424 version `1` + epoch time, `events`/`flows`/`urls`/`ids-alerts` categories | documented |
| Aruba (HPE) | ArubaOS controller / Instant AP | wifi | `<6-digit ID> <LEVEL>` (522xxx authmgr, 501xxx stm) | documented |
| Aruba (HPE) | AOS-CX switch | switch | `Event\|<id>\|LOG_<LEVEL>\|…` | lower |
| Juniper | Junos (EX, QFX, MX, SRX) | switch, router, firewall | uppercase tags (`RT_FLOW_*`, `RPD_*`, `UI_*`, `SNMP_TRAP_*`…), plain or `[junos@2636…]` | well known |
| HPE Comware / Huawei | FlexNetwork (H3C), VRP | switch, router | `MODULE/SEV/MNEMONIC:` | lower |
| Netgate / Deciso | pfSense / OPNsense | firewall | `filterlog:` CSV | well known |
| Linux | iptables / nftables / UFW, UniFi & EdgeOS gateways | firewall | `IN= OUT= SRC= DST= PROTO=` | well known |
| Linux / BSD | OpenSSH sshd, sudo, PAM | server | `sshd: Failed password … from IP`, `Accepted …`, `sudo: … incorrect password attempts` | well known |
| Ubiquiti | UniFi AP station tracker | wifi | `stahtd … STA-TRACKER` JSON | documented |
| hostapd | UniFi, OpenWrt and other Linux APs | wifi | `hostapd: <iface>: STA <mac> …` | well known |
| MikroTik | RouterOS | router, firewall, wifi | comma topics with a level (`system,error,critical`) | lower |
| Extreme Networks | EXOS | switch | `<Sev:Component.Event>` | lower |
| Ruckus / Brocade | ICX / FastIron | switch | known text prefixes (`Interface`, `Security:`, `STP:`, `DOT1X:`, …) | lower |
| Ruckus | ZoneDirector / Unleashed | wifi | `User[…]` / `AP[…]` text events | lower |
| Aruba / HP | AOS-S (ProCurve) | switch | `<5-digit ID> <subsystem>:` | lower |

*documented*: field layout checked against the vendor's published reference or vendor-community samples. *well known*: widely used, stable formats. *lower*: built from general knowledge of the format; message wording varies by firmware, so some events may only be recognised generically. Sample lines from your devices that are missed or misclassified are welcome as issues.

Event kinds and their default severity:

| Severity | Kinds |
|----------|-------|
| Error | client failure, AP down, threat, err-disabled port, loop / MAC flap, routing neighbor down, VPN down, service/server down |
| Warning | firewall deny, login failure, link down, STP change, port-security violation, port error, PoE, failover, hardware, reboot |
| Success | join, auth, AP up, login, link up, neighbor up, VPN up, service up |
| Info | roam, disconnect, allow, session, logout, config change |

For hardware, STP, PoE, reboot, failover and port-error events the device's own syslog level decides instead (a `crit` fan failure is an error, a `notice` STP change is info), and a threat's own severity (`critical`/`high` vs lower) decides between error and warning. Events of unknown kind use the syslog level. An info or success event with a diagnostic finding (legacy SSID, low RSSI) becomes a warning.

### What it extracts

Field names are matched case-insensitively, with common aliases:

| Meaning | Field names |
|---------|-------------|
| Client MAC | `clientMac`, `client_mac`, `staMac`, `stationMac`, `callingStationId` |
| User | `userName`, `user_name`, `user`, `identity`, `login` |
| AP | `apName`, `ap_name`, `ap`, `apMac`, `ap_mac`, `apEthMac` |
| Location | `apLocation`, `ap_location`, `location` |
| Other | `ssid`, `rssi`, `reason`, `result`/`status`, `event`/`eventType`, `timestamp` |

The event name comes from an `event=`/`eventType=` field, or else the camelCase word before the fields (`clientJoinFailure`). Its lifecycle kind is inferred from the name: *failure* (fail, error, timeout, reject, denied…), *join*, *auth*, *roam* or *disconnect*. A `result`/`status` of failure turns any event into a failure. Timestamps are read from ISO-8601 or BSD syslog prefixes, or a numeric `timestamp=` field.

For the generic parser, a line counts as a structured event when it has at least one `key=value` pair and either an event name or a client/user/AP field. Lines that match no format are left to the normal highlighter.

### Diagnostic rules

| Rule | Default | Option |
|------|---------|--------|
| **Failure loop**: a client with N failures inside a rolling window (a successful join/auth ends the run) | 3 in 5 min | `--loop-threshold N`, `--loop-window 5m` |
| **Legacy SSID**: SSID matches a regex | names ending `-old` / `_legacy` | `--legacy-ssid REGEX` |
| **Low signal**: RSSI below a level | -75 dBm | `--low-rssi DBM` |
| **Identity inconsistency**: one MAC seen as `bob` and `bob@corp.org` (or with different users) | — | — |
| **Rapid roaming**: 3+ roams within 60 s | — | — |
| **AP / location hotspot**: 3+ failures and a failure rate (failures ÷ failures + joins) at least 2× the overall rate (min 20%, capped at 90%) | — | — |
| **Interface flapping**: link downs on one device + interface | 3 in 10 min | `--flap-threshold N`, `--flap-window 10m` |
| **Login attack**: login failures from one source IP (or user, if no IP); also flags a successful login from that source after failures | 5 in 5 min | `--brute-threshold N`, `--brute-window 5m` |
| **Port / host scan**: distinct destination ports, or distinct hosts, denied for one source | 15 ports or 15 hosts in 5 min | `--scan-ports N`, `--scan-hosts N`, `--scan-window 5m` |
| **Password spraying**: login failures from one source against N distinct accounts | 5 accounts | `--spray-accounts N` |
| **Distributed login attack**: login failures against one account from N distinct sources | 5 sources | `--spray-sources N` |
| **Error spike**: errors + warnings in one window, at least N and X × the median window | 20 and 5× per 5 min | `--spike-min N`, `--spike-factor X`, `--spike-window 5m` |
| **Err-disable, loop / MAC flap, routing neighbor down, VPN down, service down**: reported per device/interface/peer, noting whether it recovered | — | — |

Events without an `apLocation` field are attributed to the location their AP reports elsewhere in the log. For logs with no timestamps, a failure loop means N failures in a row with no success between them.

### `--summary`

A report with a header (counts, time span, sources by format, severity totals, a per-device table and errors/warnings by event type), then a section for each kind of data present:

- **Wireless** — failures by event type, top failing clients (with users, vendor, loops, main AP), top failing users, APs and locations ranked by failure rate (hotspots marked `⚠`)
- **Switching & routing** — interfaces with link-down events (flapping marked `⚠`), routing neighbors, err-disable / loop / port-security events
- **Firewall & security** — deny/allow totals, top denied sources (scans marked), destination ports with service names, deny rules/policies, threats, VPN tunnels
- **Authentication & administration** — login failures by source and account, successful logins after failures, config changes
- **Infrastructure** — AP up/down, reboots, failover, hardware, PoE and service events

It starts with the ranked **Findings** list (below). `--top N` sets the rows per section and per kind of finding. Firewall allow/deny lines are aggregated rather than stored, so large firewall logs use little memory.

### Findings

Every detector's results, most serious first, up to `--top` rows per kind (`… and N more` for the rest):

| Level | Findings |
|-------|----------|
| Critical | Successful login from a source after a brute-force run · risky service (RDP, SMB, Telnet, databases, VNC, WinRM, SNMP, …) allowed in from an internet address · emergency/alert syslog messages · malware / intrusion text |
| High | Login attack (brute force) · password spraying (one source, 5+ accounts; `--spray-accounts`) · distributed login attack (one account, 5+ sources; `--spray-sources`) · port scan / host sweep from an internal host · internal host reaching risky services on the internet · spike in errors/warnings (5-minute window ≥ 20 and ≥ 5× the median; `--spike-min`, `--spike-factor`, `--spike-window`) · interface flapping · err-disabled port · layer-2 loop / MAC flap · routing neighbor down · threat signatures · VPN tunnel / server / AP down · hardware faults · critical syslog messages · DoS/flood, ARP spoofing, IP conflict, rogue AP/DHCP, wireless attack, DHCP pool exhausted, broadcast storm, conntrack/session table full, memory exhaustion, crash/panic, disk full, AAA/RADIUS unreachable |
| Medium | Port scan / host sweep from the internet · possible spam bot (SMTP to 10+ mail servers) · device with a high error rate (≥ 30%) · high overall error rate (≥ 25%) · device stopped logging · spanning-tree instability · interface errors · port-security violations · failover · reboots · wireless failure loops · AP / location failure hotspots · VPN/IPsec, high CPU, certificate/TLS, spoofed/martian packets |
| Low | Legacy SSID · identity inconsistency · rapid roaming · low signal · PoE faults · device clock / timestamp mismatch · NTP problems |

Internal means RFC 1918, CGNAT (100.64/10), loopback, link-local and IPv6 ULA addresses; anything else is treated as the internet. The text detectors run on lines that no format classified, so a recognised event isn't reported twice; they look for a few keywords first, so they add little time.

### `--client`

Header (users, APs, SSIDs, event counts), the compressed session path and the client's findings, then every event in order. Failure loops are grouped:

```
Path:   Join Failure ×4 (retry loop) → Join → Authorization
Findings:
  ⚠ failure loop: 4 failures in 1m50s
  ⚠ legacy SSID WCSDaccess-old (4 events, 4 failed)

  ┏━ ⚠ FAILURE LOOP: 4 failures in 1m50s @ AP-Gym-2
  ┃ May 01 08:01:00  ✗ clientJoinFailure      AP-Gym-2 [Gym] · ssid WCSDaccess-old · reason 802.1X timeout
  ┃ May 01 08:01:40  ✗ clientJoinFailure      AP-Gym-2 [Gym] · ssid WCSDaccess-old · reason 802.1X timeout
  ┃ May 01 08:02:10  · dhcpd: DHCPDISCOVER from f4:f5:d8:de:73:50 via eth0
  ┃ ...
  ┗━ recovered via clientJoin at 08:03:30 after 2m30s
  May 01 08:03:30  ! clientJoin             AP-Gym-2 [Gym] · ssid WCSDaccess · rssi -81  ⚠ low RSSI -81 dBm
```

When you look up a MAC, other log lines mentioning it (DHCP, RADIUS, etc.) are shown too, dimmed. A username with several devices gets one section per device.

### Live grouping (piped and follow modes)

As lines stream past, netlog tracks clients (failure loops), login sources (`LOGIN ATTACK`, using the login-attack rule) and interfaces (`INTERFACE FLAPPING`, using the flapping rule). When one reaches its threshold it prints a banner, and its following lines get a side bar until it recovers (or the window passes quietly). A successful login from an attacking source is marked `⚠ login succeeded after N failures`:

```
┏━ ⚠ FAILURE LOOP: f4:f5:d8:de:73:50 (alice) — 3 failures in 1m20s @ AP-Gym-2
┃ ✗ May  1 08:02:20 ctrl1 wlc: clientJoinFailure apName="AP-Gym-2" ...
┗━! May  1 08:03:30 ctrl1 wlc: clientJoin apName="AP-Gym-2" ...  ✓ recovered after 4 failures (2m30s)
```

Output for logs without structured events is unchanged.

---

## Follow Mode

```bash
netlog -f /var/log/firewall.log
netlog -f "deny|drop" /var/log/firewall.log
netlog -f -n 50 "WARN|ERR" /var/log/syslog
netlog -f --alert "DENY" /var/log/firewall.log
netlog -f -g 10.146. -g '!dhcp' /var/log/syslog
```

- Displays the last 10 lines (configurable with `-n N`) then streams new lines as they arrive
- An optional egrep-style filter pattern (extended regex, in quotes) placed **before the filename** limits output to matching lines only — both the initial tail and the live stream are filtered; a `[filter: ...]` header is printed at startup
- `-g PATTERN` filters the same way, using the viewer's filter syntax; a `[grep: ...]` header is printed. Both kinds of filter can be combined
- `Space` pauses/resumes the stream
- `l` toggles wrapping of long lines: wrapped rows are indented, or with wrapping off lines are cut at the screen edge
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
journalctl -f | netlog -g sshd -g '!session opened'
```

All ANSI highlighting — including event glyphs — is applied to stdout. When stdout is a terminal, long lines are wrapped with indented continuation rows (or cut with `--no-wrap`); output redirected to a file or another program is left unwrapped. Color map is updated and saved on exit.

---

## Testing

A `unittest` suite (stdlib only, no test framework dependency) covers the pure logic:

- Viewer: highlighting/segment priority, dedup, column stripping, search and match navigation, the filter and `-g` syntax, line wrapping
- CLI argument parsing, including every threshold option
- Vendor format detection
- Structured analysis: field parsing, timestamps, failure loops, diagnostic rules, network and security findings, the analytics alerts and text detectors, report and timeline output, live loop grouping

```bash
python3 -m unittest discover -s tests -v
```

---

## Files

| File | Purpose |
|------|---------|
| `netlog` | Main script |
| `install.sh` | Installs/uninstalls `netlog` on PATH |
| `tests/` | Unit tests (`python3 -m unittest discover -s tests`) |
| `assets/` | Logo (`netlog-logo.svg`) and square icon (`netlog-icon.svg`) |
| `oui.txt` | IEEE OUI vendor database (auto-downloaded, in the data dir) |
| `mac_colors.json` | Persistent MAC colors and column settings (in the data dir) |
| `netlog_config.json` | GeoIP credentials and other config, mode `600` (in the data dir) |
| `GeoLite2-City.mmdb` | MaxMind GeoIP database (optional, auto-downloaded, in the data dir) |

See [Persistent State](#persistent-state) above for where "the data dir" resolves to.

---

Copyright 2025 supertechguy.com — [GPLv3](LICENSE)
