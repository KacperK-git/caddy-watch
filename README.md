# caddy-watch

A lightweight, rule‑driven Caddy log watcher that bans malicious IPs using nftables.  
It was born out of frustration while trying to get CrowdSec working reliably on a Debian 12 system - caddy‑watch is the simpler alternative that does exactly what it's supposed to without a million moving parts and things to configure.

Features:

- **Rule‑based detection** - regex on Caddy JSON access log fields *and* plain‑text log lines (TLS errors, etc.)
- **Rate‑limiting** - configurable thresholds and sliding time windows
- **Automatic ban/unban** - uses nftables chains for both IPv4 and IPv6
- **State persistence** - SQLite databases survive restarts, with optional inode/offset checkpointing
- **Dry‑run mode** - test rules safely without touching the firewall
- **Audit history** - optional separate database logging every ban/unban decision
- **Easy to extend** - rules are simple JSON files
- **Management companion** - `caddy‑manage.py` for inspecting, testing, syncing, and manually unbanning IPs

---

## Configuration

The tool looks for `config.json` in the current directory (or the path given with `--config`).  
All keys are optional - defaults are tuned for a typical setup.

    {
      "poll_interval": 5,
      "unban_check_interval": 3600,
      "container_name": "caddy",
      "log_path": null,
      "history_db_enable": true,
      "resume_progress": true,
      "rules_file": "rules.json",
      "db_path": "caddy-watch.db",
      "history_db_path": "caddy-watch-history.db"
    }

- `log_path` - set to `null` and the script auto‑detects the Caddy container log via `docker inspect`.
- `resume_progress` - when `true`, caddy‑watch remembers the last file offset and inode so it never re‑reads old log entries.

---

## Rules

Detection rules are defined in a JSON file (`rules.json` by default). The repository ships with two ready‑to‑use files:

- **`rules.json`** - a set of “universal” rules that work well for most public web servers: TLS handshake errors, common vulnerability probes, known scanner user‑agents, etc.
- **`rules.extended.json`** - additional rules, tailored to my specific traffic patterns (e.g. blocking certain `Accept-Language` headers, aggressive bot user‑agents, and less common probes). Use these as inspiration or modify them for your own needs.

You can point caddy‑watch to either file by changing `rules_file` in `config.json`, or merge them together as you like.


### Rule types

There are two kinds of rules:

1. **JSON access‑log rules** (`"type": "json_access"`) - look at a specific Caddy log field (like `request.uri`, `request.headers.User-Agent`, etc.). If the regex matches, a hit is counted for the remote IP.

2. **Plain‑text rules** (`"type": "plaintext"`) - work on raw log lines (e.g. Caddy’s standard error log). The regex **must** include a named capture group `(?P<ip>…)` so the offending address can be extracted.

Every rule defines a `threshold`, a time `window` (in seconds), and a `ban_duration` (0 = permanent). When a single IP reaches the threshold within the window, it gets blocked via nftables.


### Rule examples

    // JSON access‑log: ban any IP whose User‑Agent string is just a URL
    {
      "type": "json_access",
      "field": "request.headers.User-Agent",
      "pattern": "(?i)^https?://",
      "threshold": 1,
      "window": 60,
      "ban_duration": 7776000,
      "description": "User-Agent is a URL (likely scanner)"
    }

    // Plain‑text: catch SSLv2 handshake attempts
    {
      "type": "plaintext",
      "pattern": "TLS handshake error from (?P<ip>\\S+):\\d+: tls: unsupported SSLv2 handshake received",
      "threshold": 1,
      "window": 60,
      "ban_duration": 604800,
      "description": "TLS - SSLv2 handshake attempt"
    }

Browse the provided `rules.json` and `rules.extended.json` for many more real‑world examples.

---

## Running as a systemd service (recommended)

The best way to run caddy‑watch in production is as a systemd service. This ensures it starts at boot, restarts if it crashes, and runs with the root privileges required to modify nftables.

1. Copy the script to a permanent location, for example `/usr/local/bin/caddy-watch`, and make it executable:
   
       sudo cp caddy-watch /usr/local/bin/
       sudo chmod +x /usr/local/bin/caddy-watch

   (If you prefer to keep the `.py` extension, adjust the paths accordingly.)

2. Create the service file `/etc/systemd/system/caddy-watch.service`:

       [Unit]
       Description=Caddy Watch - log parser and nftables ban manager
       After=network.target docker.service
       Wants=network.target docker.service

       [Service]
       Type=simple
       ExecStart=/usr/local/bin/caddy-watch --silent
       Restart=always
       RestartSec=15
       User=root

       # No restrictive namespaces - needed for nftables & docker access

       [Install]
       WantedBy=multi-user.target

   Make sure the `ExecStart` path matches where you placed the script. Add any other options you need (e.g. `--config /etc/caddy-watch/config.json` if your config lives elsewhere).

3. Enable and start the service:

       sudo systemctl daemon-reload
       sudo systemctl enable --now caddy-watch.service

   Check its status with `systemctl status caddy-watch`.

---

## Command‑line usage

When running manually (for example during testing), you can still launch caddy‑watch directly from the terminal:

    sudo ./caddy-watch [OPTIONS]

Options:
- `--dry-run` - simulate everything; no firewall changes, no database writes.
- `--silent`   - suppress informational output (errors still go to stderr).
- `--config CONFIG` - path to a JSON configuration file (default: `config.json`).

Stop the process with `SIGINT` (Ctrl+C) or `SIGTERM`. It will shut down gracefully, saving its log position and closing databases.

---

## How It Works

1. caddy‑watch locates the Caddy container log file using `docker inspect`.
2. It reads new lines as they appear. Each line is first tried as JSON (Caddy access log); if that fails, plain‑text rules are checked.
3. Hits are stored in an SQLite database with sliding windows. When an IP crosses a threshold, it is immediately banned via `nftables`.
4. A background thread periodically scans for expired bans and removes the corresponding firewall rules.
5. Optionally, every ban/unban event is logged to a history database for auditing.

---

## Management tool (`caddy‑manage.py`)

caddy‑watch ships with a companion script for day‑to‑day administration of the ban list.  
It reads the same SQLite databases and talks directly to nftables, so it needs root privileges  
(for commands that touch the firewall, prefix with `sudo`).

| Command               | Description                                                      |
|-----------------------|------------------------------------------------------------------|
| `list`                | Show all active bans (oldest first) with reason and time remaining |
| `stats`               | Display total bans, dropped packets/bytes per IP                 |
| `test <IP>`           | Check if an IP is currently blocked (database + nftables)        |
| `unban <IP>`          | Immediately remove a ban from both database and firewall         |
| `sync [--repair]`     | Compare database and nftables, list inconsistencies. With `--repair` fix them automatically |
| `history [--limit N]` | Show the last `N` rule hit events (default 20)                   |

**Examples:**

    sudo ./caddy-manage.py list
    sudo ./caddy-manage.py test 45.33.32.156
    sudo ./caddy-manage.py unban 45.33.32.156
    sudo ./caddy-manage.py sync --repair
    ./caddy-manage.py history --limit 50

`list`, `stats`, `test` and `history` are safe to run without `sudo` *if* you only need database info,  
but `stats` and `test` read live nftables counters which require root. When in doubt, use `sudo`.

Note: `caddy‑manage.py` currently looks for `caddy-watch.db` in the same directory and reads `rules.json` to show rule descriptions in the `history` command. If you use a custom config, put the scripts and database in the same directory or symlink appropriately.

---

## Database Schema

### Main state database (`caddy-watch.db`)
- `bans` - currently active bans with expiration timestamps.
- `rule_hits` - recent hits used for rate‑limiting.

### History database (`caddy-watch-history.db`)
- `decisions` - audit log of bans and unbans.
- `checkpoint` - last file offset and inode so the tool can resume after a restart.

---

## Contributing

Issues, suggestions and pull requests are welcome. If you add new rules that might be useful to others, feel free to contribute them to the `rules.json` set.

---

## License

MIT - see the [LICENSE](LICENSE) file.
