# NETLOG

**NETLOG** is a powerful terminal-based network log viewer built in PHP, designed for analyzing logs with features tailored for sysadmins, network engineers, and log nerds.

Unlike `tail` or `less`, NETLOG adds smart, readable **color highlighting**, **MAC vendor identification**, **real-time log following**, and interactive **search and filter** capabilities — all from the command line.

---

## ✨ Features

- ✅ Real-time log monitoring (`-f` mode, like `tail -f`)
- 🎨 MAC address highlighting with persistent **color mapping**
- 🏷️ Automatic **vendor lookup** via IEEE OUI database
- 🔍 Interactive search (`/` for plain text, `r` for regex)
- ⏩ Navigate search matches with `n` (next)
- 🔁 Apply live filters (plain or regex-based)
- 🧵 Supports piped input (`cat file.log | ./netlog`)
- 📦 Export filtered output (`e` key)
- 🚫 Minimalist non-interactive mode for `tail -f`-style viewing
- 💾 Auto-saves and reloads color map between sessions
- 🔒 Memory management (auto-truncates old lines during follow mode)

---

## 📦 Requirements

Install dependencies (Debian/Ubuntu):

```bash
sudo apt install php-cli php-mbstring





Copyright @2025, supertechguy.com, GPL.
