#!/usr/bin/env python3
"""
caddy-watch - Tail Caddy Docker JSON logs, apply rules, and ban IPs with nftables.
"""

import os
import sys
import json
import time
import re
import sqlite3
import subprocess
import threading
import argparse
from datetime import datetime, timezone
import queue
import signal


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def load_config(config_path: str) -> dict:
    """Load configuration from a JSON file, returning a dict with defaults."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_config = {
        "poll_interval": 5,
        "unban_check_interval": 3600,
        "container_name": "caddy",
        "log_path": None,                # None - auto-detect from Docker
        "history_db_enable": True,
        "resume_progress": True,         # inode checkpointing
        "rules_file": os.path.join(script_dir, "rules.json"),
        "db_path": os.path.join(script_dir, "caddy-watch.db"),
        "history_db_path": os.path.join(script_dir, "caddy-watch-history.db"),
    }

    if not os.path.isfile(config_path):
        print(f"[{timestamp()}] Config file '{config_path}' not found, using defaults.")
        return default_config

    try:
        with open(config_path, "r") as f:
            user_config = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"[{timestamp()}] ERROR reading config: {e}, using defaults.", file=sys.stderr)
        return default_config

    # Merge: user values override defaults
    merged = {**default_config, **user_config}
    return merged


class NoopDecisionLogger:
    """Replacement that does nothing (history DB disabled)."""
    def log_ban(self, ip, rule_desc, duration, timestamp):
        pass
    def log_unban(self, ip, timestamp):
        pass
    def shutdown(self):
        pass


class DecisionLogger:
    """Thread‑safe async logger that writes ban/unban events to a separate history DB."""
    def __init__(self, db_path: str, dry_run: bool = False):
        self.db_path = db_path
        self.dry_run = dry_run
        self.queue: queue.Queue = queue.Queue()
        self._stop = False

        # Start a background thread to consume the queue.
        self._worker = threading.Thread(target=self._writer_loop, daemon=True)
        self._worker.start()

    def _init_db(self):
        """Create the schema if it doesn't exist (called inside the worker thread)."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                action TEXT CHECK(action IN ('ban', 'unban')) NOT NULL,
                rule_desc TEXT NOT NULL,
                duration INTEGER NOT NULL,   -- seconds, 0 = permanent
                timestamp REAL NOT NULL      -- Unix time (UTC)
            )
        """)
        conn.commit()
        return conn

    def _writer_loop(self):
        """Continuously drain the queue and write to the history DB."""
        if not self.dry_run:
            conn = self._init_db()
        while not self._stop:
            try:
                event = self.queue.get(timeout=1)
                if event is None:      # poison pill to stop
                    break
                action, ip, rule_desc, duration, ts = event
                if self.dry_run:
                    dt_str = datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
                    print(f"[SIMULATE History] {action.upper()} {ip} - {rule_desc} "
                          f"({duration}s) at {dt_str}")
                else:
                    try:
                        conn.execute(
                            "INSERT INTO decisions (ip, action, rule_desc, duration, timestamp) "
                            "VALUES (?, ?, ?, ?, ?)",
                            (ip, action, rule_desc, duration, ts)
                        )
                        conn.commit()
                    except Exception as e:
                        print(f"[{timestamp()}] ERROR: Failed to write decision log: {e}",
                              file=sys.stderr)
            except queue.Empty:
                continue
        if not self.dry_run:
            conn.close()

    def log_ban(self, ip: str, rule_desc: str, duration: int, timestamp: float):
        """Schedule a ban event for writing."""
        self.queue.put(("ban", ip, rule_desc, duration, timestamp))

    def log_unban(self, ip: str, timestamp: float):
        """Schedule an unban event for writing."""
        # Duration for an unban is irrelevant; store 0.
        self.queue.put(("unban", ip, "ban expired", 0, timestamp))

    def shutdown(self):
        """Gracefully stop the writer thread."""
        self.queue.put(None)       # poison pill
        self._worker.join(timeout=5)


class NftablesManager:
    """Create/manage a dedicated 'ban' chain in nftables for IPv4 and IPv6."""
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run

    def init_ban_chain(self):
        """Ensure that ip/ip6 filter ban chain exists and is jumped to."""
        self._ensure_chain_for_family("ip")
        self._ensure_chain_for_family("ip6")

    def _ensure_chain_for_family(self, family: str):
        if self.dry_run:
            print(f"[SIMULATE] Setup nftables ban chain for {family}")
            return

        # create filter table if missing
        subprocess.run(
            ["nft", "add", "table", family, "filter"],
            capture_output=True, text=True,
        )
        # create input/forward base chains with hooks if missing
        for chain, hook, prio in [("input", "input", "0"), ("forward", "forward", "0")]:
            check = subprocess.run(
                ["nft", "list", "chain", family, "filter", chain],
                capture_output=True, text=True,
            )
            if check.returncode != 0:
                subprocess.run(
                    ["nft", "add", "chain", family, "filter", chain,
                     "{", "type", "filter", "hook", hook, "priority", f"{prio};",
                     "policy", "accept;", "}"],
                    capture_output=True, text=True,
                )

        # Check if ban chain already exists (locale-independent)
        list_result = subprocess.run(
            ["nft", "list", "chain", family, "filter", "ban"],
            capture_output=True, text=True,
        )
        if list_result.returncode != 0:
            # Chain does not exist - create it
            create_result = subprocess.run(
                ["nft", "add", "chain", family, "filter", "ban"],
                capture_output=True, text=True,
            )
            if create_result.returncode != 0:
                print(f"[{timestamp()}] ERROR: nft create ban chain failed ({family}): "
                      f"{create_result.stderr.strip()}", file=sys.stderr)
                return

        # flush existing rules (clean slate after reboot)
        subprocess.run(
            ["nft", "flush", "chain", family, "filter", "ban"],
            capture_output=True, text=True,
        )

        # ensure jump from input and forward chains
        for base_chain in ("input", "forward"):
            chain_check = subprocess.run(
                ["nft", "list", "chain", family, "filter", base_chain],
                capture_output=True, text=True,
            )
            if "jump ban" in chain_check.stdout:
                continue
            insert = subprocess.run(
                ["nft", "insert", "rule", family, "filter", base_chain,
                 "position", "1", "jump", "ban"],
                capture_output=True, text=True,
            )
            if insert.returncode != 0:
                subprocess.run(
                    ["nft", "add", "rule", family, "filter", base_chain, "jump", "ban"],
                    capture_output=True, text=True,
                )

    def ban_ip(self, ip: str, duration: int = 0):
        """Add a drop rule for *ip* to the appropriate ban chain."""
        family = "ip6" if ":" in ip else "ip"
        if self.dry_run:
            addr = "ip6 saddr" if family == "ip6" else "ip saddr"
            print(f"[SIMULATE] nft add rule {family} filter ban {addr} {ip} counter drop")
            return
        print(f"[{timestamp()}] Banning IP {ip} (nftables {family} filter ban)")
        try:
            subprocess.run(
                ["nft", "add", "rule", family, "filter", "ban",
                 "ip" if family == "ip" else "ip6", "saddr", ip, "counter", "drop"],
                check=True, capture_output=True, text=True,
            )
        except subprocess.CalledProcessError as e:
            print(f"[{timestamp()}] ERROR: nft ban failed: {e.stderr.strip()}", file=sys.stderr)

    def unban_ip(self, ip: str):
        """Remove the drop rule for *ip* from the appropriate ban chain."""
        family = "ip6" if ":" in ip else "ip"
        if self.dry_run:
            print(f"[SIMULATE] remove nft ban rule for IP {ip} ({family})")
            return
        print(f"[{timestamp()}] Unbanning IP {ip} from nftables {family} filter ban")
        try:
            result = subprocess.run(
                ["nft", "-a", "list", "chain", family, "filter", "ban"],
                capture_output=True, text=True, check=True,
            )
            addr_key = "ip6 saddr" if family == "ip6" else "ip saddr"

            # Regex: matches the addr_key, spaces, exact IP, and then either whitespace or line end
            pattern = re.compile(rf"{addr_key}\s+{re.escape(ip)}(?:\s|$)")

            for line in result.stdout.splitlines():
                if pattern.search(line) and "drop" in line:
                    handle = line.split("handle")[-1].strip()
                    if handle.isdigit():
                        subprocess.run(
                            ["nft", "delete", "rule", family, "filter", "ban", "handle", handle],
                            check=True, capture_output=True, text=True,
                        )
                        print(f"[{timestamp()}] Removed ban rule for {ip} (handle {handle})")
        except subprocess.CalledProcessError as e:
            print(f"[{timestamp()}] ERROR: nft unban failed: {e.stderr.strip()}", file=sys.stderr)


class Database:
    """Wraps SQLite operations. In dry‑run mode uses an in‑memory DB, never touches disk."""
    def __init__(self, db_path: str, dry_run: bool = False):
        self.dry_run = dry_run
        if dry_run:
            self.conn = sqlite3.connect(":memory:")
        else:
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            self.conn = sqlite3.connect(db_path)
        self._init_schema()

    def _init_schema(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS bans (
                ip TEXT PRIMARY KEY,
                unban_time REAL,
                rule_desc TEXT
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS rule_hits (
                ip TEXT,
                rule_id INTEGER,
                timestamp REAL
            )
        """)
        # Index for efficient cleanup queries
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_rule_hits_cleanup ON rule_hits (timestamp)
        """)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.commit()

    def close(self):
        self.conn.close()

    def cleanup_old_hits(self, window: float):
        now = time.time()
        self.conn.execute("DELETE FROM rule_hits WHERE timestamp < ?", (now - window,))
        self.conn.commit()

    def add_hit(self, ip: str, rule_id: int, ts: float = None):
        hit_time = ts if ts is not None else time.time()
        self.conn.execute(
            "INSERT INTO rule_hits (ip, rule_id, timestamp) VALUES (?, ?, ?)",
            (ip, rule_id, hit_time),
        )
        self.conn.commit()

    def count_recent_hits(self, ip: str, rule_id: int, window: float) -> int:
        now = time.time()
        cur = self.conn.execute(
            "SELECT COUNT(*) FROM rule_hits WHERE ip = ? AND rule_id = ? AND timestamp > ?",
            (ip, rule_id, now - window),
        )
        return cur.fetchone()[0]

    def get_ban(self, ip: str):
        cur = self.conn.execute("SELECT unban_time, rule_desc FROM bans WHERE ip = ?", (ip,))
        return cur.fetchone()

    def add_ban(self, ip: str, unban_time: float, rule_desc: str):
        self.conn.execute(
            "INSERT OR REPLACE INTO bans (ip, unban_time, rule_desc) VALUES (?, ?, ?)",
            (ip, unban_time, rule_desc),
        )
        self.conn.commit()

    def try_remove_expired_ban(self, ip: str, expired_unban_time: float) -> bool:
        """Delete a ban only if its unban_time matches the expired value."""
        cur = self.conn.execute(
            "DELETE FROM bans WHERE ip = ? AND unban_time = ?",
            (ip, expired_unban_time),
        )
        self.conn.commit()
        return cur.rowcount > 0

    def remove_ban(self, ip: str):
        self.conn.execute("DELETE FROM bans WHERE ip = ?", (ip,))
        self.conn.commit()

    def get_expired_bans(self, now: float):
        cur = self.conn.execute("SELECT ip, unban_time FROM bans WHERE unban_time <= ?", (now,))
        return cur.fetchall()

    def get_active_bans(self):
        now = time.time()
        cur = self.conn.execute("SELECT ip, unban_time FROM bans WHERE unban_time > ?", (now,))
        return cur.fetchall()


class RuleEngine:
    """Loads, stores, and applies detection rules."""
    SUPPORTED_FIELDS = (
        "request.uri",
        "request.headers.User-Agent",
        "request.headers.Accept-Language",
        "status",
        "resp_headers.Content-Type"
    )

    def __init__(self, rules_file: str):
        self.rules_file = rules_file
        self.rules = []

    def load(self):
        if not os.path.isfile(self.rules_file):
            print(f"[{timestamp()}] rules.json not found - using built‑in minimal rule.")
            self.rules = [
                {
                    "type": "json_access",
                    "field": "request.uri",
                    "pattern": "/search\\?q=",
                    "threshold": 10,
                    "window": 300,
                    "ban_duration": 1800,
                    "description": "Excessive search queries",
                    "tags": ["search"],
                }
            ]
        else:
            with open(self.rules_file, "r") as f:
                rules = json.load(f)

            required_base = {"pattern", "threshold", "window", "ban_duration", "description"}
            for i, rule in enumerate(rules):
                # Set defaults
                rule.setdefault("type", "json_access")
                rule.setdefault("tags", [])

                # Validate common keys
                missing = required_base - set(rule.keys())
                if missing:
                    raise ValueError(f"Rule {i} missing keys: {missing}")

                # Type-specific validation
                if rule["type"] == "json_access":
                    if "field" not in rule:
                        raise ValueError(f"Rule {i} (json_access): missing 'field'")
                    if rule["field"] not in self.SUPPORTED_FIELDS:
                        raise ValueError(f"Rule {i}: unsupported field '{rule['field']}'")
                    try:
                        rule["_compiled"] = re.compile(rule["pattern"])
                    except re.error as e:
                        raise ValueError(f"Rule {i}: invalid regex '{rule['pattern']}': {e}")

                elif rule["type"] == "plaintext":
                    try:
                        compiled = re.compile(rule["pattern"])
                    except re.error as e:
                        raise ValueError(f"Rule {i}: invalid regex '{rule['pattern']}': {e}")
                    if "ip" not in compiled.groupindex:
                        raise ValueError(
                            f"Rule {i} (plaintext): pattern must contain a named capture group 'ip' "
                            f"(e.g. (?P<ip>\\\\S+)) to extract the offending IP address"
                        )
                    rule["_compiled"] = compiled

                else:
                    raise ValueError(f"Rule {i}: unknown type '{rule['type']}'. "
                                     f"Must be 'json_access' or 'plaintext'")

            self.rules = rules

        # Compile built-in rule if used
        if len(self.rules) == 1 and "_compiled" not in self.rules[0]:
            self.rules[0]["_compiled"] = re.compile(self.rules[0]["pattern"])

        return len(self.rules)

    def extract_field(self, parsed_log: dict, field: str) -> str | None:
        """Dotted path access, e.g. 'request.headers.User-Agent'."""
        parts = field.split(".")
        obj = parsed_log
        try:
            for p in parts:
                obj = obj[p]
            if isinstance(obj, list):
                return ", ".join(obj)
            return str(obj)
        except (KeyError, TypeError):
            return None

    def evaluate(self, parsed_log: dict) -> list[tuple[int, dict]]:
        """Return (rule_index, rule_dict) for every matching JSON access rule."""
        matches = []
        for idx, rule in enumerate(self.rules):
            if rule.get("type") != "json_access":
                continue
            value = self.extract_field(parsed_log, rule["field"])
            if value is None:
                continue
            if rule["_compiled"].search(value):
                matches.append((idx, rule))
        return matches

    def evaluate_plaintext(self, line: str) -> list[tuple[int, dict, str]]:
        """
        Return (rule_index, rule_dict, ip_address) for every matching plaintext rule.
        The IP is extracted from the named group 'ip' in the regex.
        """
        hits = []
        for idx, rule in enumerate(self.rules):
            if rule.get("type") != "plaintext":
                continue
            m = rule["_compiled"].search(line)
            if m:
                ip = m.group("ip")
                hits.append((idx, rule, ip))
        return hits

    def max_window(self) -> int:
        """Return the largest window across all rules (JSON + plaintext)."""
        if not self.rules:
            return 3600
        return max(r["window"] for r in self.rules)


class LogDetector:
    @staticmethod
    def find_log_path(container_name: str) -> str:
        try:
            inspect = subprocess.check_output(
                ["docker", "inspect", container_name],
                stderr=subprocess.DEVNULL, text=True,
            )
            data = json.loads(inspect)
            if not data:
                raise RuntimeError(f"Container '{container_name}' not found")
            log_path = data[0].get("LogPath")
            if not log_path or not os.path.isfile(log_path):
                raise RuntimeError(f"No LogPath for container '{container_name}'")
            return log_path
        except subprocess.CalledProcessError as e:
            print(f"[{timestamp()}] ERROR: docker inspect failed: {e}", file=sys.stderr)
            sys.exit(1)


class CaddyWatch:
    def __init__(self, args: argparse.Namespace):
        self.dry_run = args.dry_run
        self.silent = args.silent
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self._shutdown_event = threading.Event()

        # Load configuration from JSON
        config = load_config(args.config)
        self.poll_interval = config["poll_interval"]
        self.unban_check_interval = config["unban_check_interval"]
        self.container_name = config["container_name"]
        self.log_path = config["log_path"]           # None = auto-detect
        self.resume_progress = config["resume_progress"]

        # Paths
        self.rules_file = config["rules_file"]
        self.db_path = config["db_path"]
        self.history_db_path = config["history_db_path"]

        # Decision history logger (enable/disable)
        if config["history_db_enable"] and not self.dry_run:
            self.decision_log = DecisionLogger(self.history_db_path, dry_run=False)
        else:
            self.decision_log = NoopDecisionLogger()

        # Components
        self.nft = NftablesManager(dry_run=self.dry_run)
        self.db = Database(self.db_path, dry_run=self.dry_run)
        self.rules_engine = RuleEngine(self.rules_file)

        # State for log tailing
        self.last_inode = None
        self.last_offset = 0

    def _ensure_checkpoint_table(self):
        """Create the checkpoint table (single row) in the history DB."""
        conn = sqlite3.connect(self.history_db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS checkpoint (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                inode INTEGER NOT NULL,
                offset INTEGER NOT NULL,
                log_path TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    def _save_checkpoint(self):
        """Upsert the current inode/offset into the checkpoint table."""
        if not self.resume_progress or self.dry_run:
            return
        conn = sqlite3.connect(self.history_db_path)
        conn.execute(
            "INSERT OR REPLACE INTO checkpoint (id, inode, offset, log_path) "
            "VALUES (1, ?, ?, ?)",
            (self.last_inode, self.last_offset, self.log_path)
        )
        conn.commit()
        conn.close()

    def _log(self, msg: str, force: bool = False):
        if not self.silent or force:
            print(f"[{timestamp()}] {msg}")

    def _log_error(self, msg: str):
        print(f"[{timestamp()}] ERROR: {msg}", file=sys.stderr)

    def _handle_matches(self, ip: str, matched: list[tuple[int, dict]],
                        event_time: float = None):
        """
        Process rule matches for a given IP - ban if threshold exceeded.
        event_time: Unix timestamp of the log line (or None to use current time).
        """
        now = event_time if event_time is not None else time.time()

        for rule_idx, rule in matched:
            self.db.add_hit(ip, rule_idx, now)  # use actual event time
            count = self.db.count_recent_hits(ip, rule_idx, rule["window"])
            if count >= rule["threshold"]:
                existing = self.db.get_ban(ip)
                if existing:
                    self._log(f"IP {ip} already banned, skipping new hit.")
                    continue

                ban_duration = rule["ban_duration"]
                unban_time = now + ban_duration if ban_duration > 0 else float("inf")
                self.db.add_ban(ip, unban_time, rule["description"])
                self.nft.ban_ip(ip, ban_duration)
                self.decision_log.log_ban(ip, rule["description"], ban_duration, now)

    def _process_line(self, line: str):
        line = line.strip()
        if not line:
            return

        # Try JSON access-log parsing first
        parsed = None
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            pass
        else:
            if isinstance(raw, dict) and "log" in raw and isinstance(raw["log"], str):
                try:
                    parsed = json.loads(raw["log"])
                except json.JSONDecodeError:
                    pass
            else:
                parsed = raw

        if parsed is not None:
            # JSON access log path
            logger = parsed.get("logger", "")
            if not logger.startswith("http.log.access"):
                return
            remote = parsed.get("request", {}).get("remote_addr", "")
            if not remote:
                return
            ip_match = re.match(r"^(\S+?)(?::\d+)?$", remote)
            if not ip_match:
                return
            ip = ip_match.group(1)
            ip = ip.strip("[]")

            # Extract event time from Caddy JSON (ts is a Unix float)
            event_time = parsed.get("ts")
            if event_time is None:
                event_time = time.time()

            matched = self.rules_engine.evaluate(parsed)
            if matched:
                self._handle_matches(ip, matched, event_time)
            return

        # Not JSON - try plaintext rules
        plain_matches = self.rules_engine.evaluate_plaintext(line)
        if not plain_matches:
            return

        now = time.time()
        for rule_idx, rule, ip in plain_matches:
            ip = ip.strip("[]")
            self.db.add_hit(ip, rule_idx)
            count = self.db.count_recent_hits(ip, rule_idx, rule["window"])
            if count >= rule["threshold"]:
                if self.db.get_ban(ip):
                    self._log(f"IP {ip} already banned, skipping new hit.")
                    continue
                ban_duration = rule["ban_duration"]
                unban_time = now + ban_duration if ban_duration > 0 else float("inf")
                self.db.add_ban(ip, unban_time, rule["description"])
                self.nft.ban_ip(ip, ban_duration)
                self.decision_log.log_ban(ip, rule["description"], ban_duration, now)

    def _unban_loop(self):
        unban_db = Database(self.db_path, dry_run=self.dry_run)
        try:
            while not self._shutdown_event.is_set():
                self._shutdown_event.wait(self.unban_check_interval)
                if self._shutdown_event.is_set():
                    break
                if self.dry_run:
                    continue
                now = time.time()
                expired = unban_db.get_expired_bans(now)  # (ip, unban_time)
                for ip, expired_time in expired:
                    if unban_db.try_remove_expired_ban(ip, expired_time):
                        # The ban was still in its expired state - safe to clean up
                        self.nft.unban_ip(ip)
                        self.decision_log.log_unban(ip, time.time())
        finally:
            unban_db.close()

    def run(self):
        # Root check (unless dry-run)
        if not self.dry_run and os.geteuid() != 0:
            print("caddy-watch must be run as root. Use --dry-run to test.", file=sys.stderr)
            sys.exit(1)

        # Detect log path
        if not self.log_path:
            self.log_path = LogDetector.find_log_path(self.container_name)
        self._log(f"Log file: {self.log_path}")

        # Load rules
        num = self.rules_engine.load()
        self._log(f"Loaded {num} rule(s).")

        # Init nftables and re-apply existing bans
        if not self.dry_run:
            self.nft.init_ban_chain()
            for ip, _ in self.db.get_active_bans():
                self.nft.ban_ip(ip, duration=0)

        # Start unban thread
        unban_thread = threading.Thread(target=self._unban_loop, daemon=True)
        unban_thread.start()

        # Signal handlers
        def handle_shutdown(signum, frame):
            self._log("Shutdown signal received. Stopping gracefully.", force=True)
            self._shutdown_event.set()

        signal.signal(signal.SIGTERM, handle_shutdown)
        signal.signal(signal.SIGINT, handle_shutdown)

        self._log(f"caddy-watch started (polling every {self.poll_interval}s).", force=True)

        # Initialise inode tracking with optional checkpoint resume
        if os.path.exists(self.log_path):
            self._ensure_checkpoint_table()
            current_inode = os.stat(self.log_path).st_ino
            if self.resume_progress and not self.dry_run:
                # Try to load saved progress
                conn = sqlite3.connect(self.history_db_path)
                cur = conn.execute("SELECT inode, offset, log_path FROM checkpoint WHERE id = 1")
                row = cur.fetchone()
                conn.close()
                if row and row[0] == current_inode and row[2] == self.log_path:
                    self.last_inode = row[0]
                    self.last_offset = row[1]
                    self._log(f"Resumed from checkpoint - offset {self.last_offset}")
                else:
                    self.last_inode = current_inode
                    self.last_offset = 0
                    self._log("Starting from beginning (new inode or no valid checkpoint)")
            else:
                self.last_inode = current_inode
                # self.last_offset remains 0
        else:
            self._log("Log file not found, will wait for it.")

        try:
            while not self._shutdown_event.is_set():
                try:
                    if not os.path.exists(self.log_path):
                        self._shutdown_event.wait(self.poll_interval)
                        continue

                    stat = os.stat(self.log_path)
                    current_inode = stat.st_ino
                    current_size = stat.st_size

                    # Rotation / truncation detection
                    if self.last_inode != current_inode:
                        self._log("Log rotated or new inode, resetting offset.", force=True)
                        self.last_offset = 0
                        self.last_inode = current_inode
                    if self.last_offset > current_size:
                        self._log("Log truncated, resetting offset.", force=True)
                        self.last_offset = 0

                    if self.last_offset < current_size:
                        with open(self.log_path, "rb") as f:
                            f.seek(self.last_offset)
                            raw = f.read(current_size - self.last_offset)
                            # Temporarily update offset to the end of the current read
                            self.last_offset = f.tell()

                        # keepends=True is critical here so we can check for '\n'
                        lines = raw.decode("utf-8", errors="replace").splitlines(keepends=True)

                        for i, line in enumerate(lines):
                            # If this is the last line in the chunk and it lacks a newline, it's incomplete
                            if i == len(lines) - 1 and not line.endswith('\n'):
                                # Rewind the offset by the byte length of this partial string
                                self.last_offset -= len(line.encode("utf-8"))
                                break

                            try:
                                # Strip the trailing newline before processing
                                self._process_line(line.strip())
                            except Exception as e:
                                self._log_error(f"Failed to process line: {e}")

                    self._save_checkpoint()

                    # Periodic cleanup
                    max_window = self.rules_engine.max_window()
                    self.db.cleanup_old_hits(max_window)

                except Exception as e:
                    self._log_error(f"Main loop error: {e}")
                    self._shutdown_event.wait(self.poll_interval * 5)

                # Short sleep or exit if shutdown requested
                self._shutdown_event.wait(self.poll_interval)

        finally:
            # Graceful shutdown
            self._log("Shutting down workers...", force=True)
            self._shutdown_event.set()
            unban_thread.join(timeout=10)
            self._save_checkpoint()
            self.db.close()
            self.decision_log.shutdown()
            self._log("Shutdown complete.", force=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="caddy-watch - Caddy log watcher")
    parser.add_argument("--dry-run", action="store_true",
                        help="Simulate actions, no nftables, DB or checkpoint changes")
    parser.add_argument("--silent", action="store_true",
                        help="Suppress all output except errors")
    parser.add_argument("--config", default="config.json",
                        help="Path to JSON configuration file (default: config.json)")
    args = parser.parse_args()

    watcher = CaddyWatch(args)
    watcher.run()
