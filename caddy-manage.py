#!/usr/bin/env python3
"""
caddy-manage - advanced management for caddy-watch bans.
Commands:
  list             List active bans (oldest first)
  sync             Compare database vs nftables, optionally repair
  stats            Show total bans and dropped packets/bytes from nftables sets
  test <IP>        Check if an IP is currently banned
  unban <IP>       Remove a ban from database and nftables sets
  history          Show rule hits from the last N hours (default 3)
  ping             Verify the core script is alive and responding
"""

import os
import re
import sys
import socket
import sqlite3
import subprocess
import time
import argparse
from datetime import datetime, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, "caddy-watch.db")
HISTORY_DB_PATH = os.path.join(SCRIPT_DIR, "caddy-watch-history.db")
SOCKET_PATH = os.path.join(SCRIPT_DIR, "caddy-watch.sock")


def format_duration(seconds):
    if seconds < 0:
        return "expired"
    if seconds == float("inf") or seconds == 0:
        return "permanent"
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if secs > 0 or not parts:
        parts.append(f"{secs}s")
    return " ".join(parts)


def get_ban_set_ips(family):
    """Return set of IP addresses currently in the given nftables ban set."""
    set_name = "banned_ipv4" if family == "ip" else "banned_ipv6"
    try:
        output = subprocess.run(
            ["nft", "list", "set", family, "filter", set_name],
            capture_output=True, text=True, check=True
        ).stdout
    except subprocess.CalledProcessError:
        return set()

    ips = set()
    # Isolating items listed inside elements = { ... }
    match = re.search(r'elements\s*=\s*\{([^}]+)\}', output)
    if not match:
        return ips

    for item in match.group(1).split(","):
        tokens = item.strip().split()
        if tokens:
            ip = tokens[0]
            if "." in ip or ":" in ip:
                ips.add(ip)
    return ips


def get_ban_set_counters(family):
    """Return dict IP -> (packets, bytes) from the ban set elements."""
    counters = {}
    set_name = "banned_ipv4" if family == "ip" else "banned_ipv6"
    try:
        output = subprocess.run(
            ["nft", "list", "set", family, "filter", set_name],
            capture_output=True, text=True, check=True
        ).stdout
    except subprocess.CalledProcessError:
        return counters

    match = re.search(r'elements\s*=\s*\{([^}]+)\}', output)
    if not match:
        return counters

    for item in match.group(1).split(","):
        tokens = item.strip().split()
        if tokens:
            ip = tokens[0]
            if "." in ip or ":" in ip:
                pkt_match = re.search(r'packets\s+(\d+)', item)
                bytes_match = re.search(r'bytes\s+(\d+)', item)
                packets = int(pkt_match.group(1)) if pkt_match else 0
                byt = int(bytes_match.group(1)) if bytes_match else 0
                counters[ip] = (packets, byt)
    return counters


def unban_ip(ip: str):
    """Remove the IP from the nftables ban set."""
    family = "ip6" if ":" in ip else "ip"
    set_name = "banned_ipv6" if family == "ip6" else "banned_ipv4"
    try:
        subprocess.run(
            ["nft", "delete", "element", family, "filter", set_name, f"{{ {ip} }}"],
            check=True, capture_output=True, text=True
        )
        return True
    except subprocess.CalledProcessError:
        return False


def load_rules():
    """Return list of rules from rules.json (same format as caddy-watch.py)."""
    import json
    rules_file = os.path.join(SCRIPT_DIR, "rules.json")
    if os.path.isfile(rules_file):
        with open(rules_file) as f:
            rules = json.load(f)
        return rules
    return []


def get_active_bans(conn):
    """Return list of (ip, unban_time, rule_desc) for bans not yet expired."""
    now = time.time()
    cur = conn.execute(
        "SELECT ip, unban_time, rule_desc FROM bans WHERE unban_time > ? ORDER BY unban_time ASC",
        (now,)
    )
    return cur.fetchall()


def remove_ban(conn, ip):
    conn.execute("DELETE FROM bans WHERE ip = ?", (ip,))
    conn.commit()


def cmd_list(conn):
    bans = get_active_bans(conn)
    line_width = 50  # Default separator line width if no bans exist

    # 1. Print Active Bans Table if any exist
    if bans:
        ip_col = 20
        reason_col = 50
        remaining_col = 20
        header = f"{'IP':<{ip_col}} {'Remaining':<{remaining_col}} {'Reason':<{reason_col}}"
        line_width = len(header)
        print(header)
        print("-" * line_width)

        now = time.time()
        for ip, unban_time, rule_desc in bans:
            remaining = unban_time - now if unban_time != float("inf") else float("inf")
            remaining_str = format_duration(remaining)
            if len(rule_desc) > reason_col - 2:
                rule_desc = rule_desc[:reason_col - 5] + "..."
            print(f"{ip:<{ip_col}} {remaining_str:<{remaining_col}} {rule_desc:<{reason_col}}")
    else:
        print("No active bans currently in the database.")

    # 2. Gather additional active metrics
    ipv4_count = sum(1 for row in bans if ":" not in row[0])
    ipv6_count = sum(1 for row in bans if ":" in row[0])
    perm_count = sum(1 for row in bans if row[1] == float("inf"))

    # 3. Gather historical database metrics
    hist_db_path = os.path.join(SCRIPT_DIR, "caddy-watch-history.db")
    bans_per_hour_24h = 0.0
    unbans_per_hour_24h = 0.0
    total_historical_bans = 0

    if os.path.exists(hist_db_path):
        try:
            with sqlite3.connect(hist_db_path) as h_conn:
                now_ts = time.time()
                day_ago = now_ts - 86400

                # Rolling 24h ban rate
                cur = h_conn.execute(
                    "SELECT COUNT(*) FROM decisions WHERE action = 'ban' AND timestamp >= ?",
                    (day_ago,)
                )
                bans_per_hour_24h = cur.fetchone()[0] / 24.0

                # Rolling 24h unban rate
                cur = h_conn.execute(
                    "SELECT COUNT(*) FROM decisions WHERE action = 'unban' AND timestamp >= ?",
                    (day_ago,)
                )
                unbans_per_hour_24h = cur.fetchone()[0] / 24.0

                # Lifetime total bans
                cur = h_conn.execute("SELECT COUNT(*) FROM decisions WHERE action = 'ban'")
                total_historical_bans = cur.fetchone()[0]
        except Exception:
            # Fallback gracefully if history database is temporarily locked or unreadable
            pass

    # 4. Calculate Net Growth Rate and Database Pool Trend
    growth_rate_24h = bans_per_hour_24h - unbans_per_hour_24h

    if growth_rate_24h >= 0.1:
        trend_str = "▲"
    elif growth_rate_24h >= 0.05:
        trend_str = "🡥"
    elif growth_rate_24h <= -0.1:
        trend_str = "▽"
    elif growth_rate_24h <= -0.05:
        trend_str = "🡦"
    else:
        trend_str = "-"

    print("-" * line_width)

    # 5. Print Summary Metrics Block
    print("\n📊 Metrics:")
    print(f"  • IPv4 bans:              {ipv4_count}")
    print(f"  • IPv6 bans:              {ipv6_count}")
    print(f"  • Persistent bans:        {perm_count}")
    print(f"  • Ban Rate:               {bans_per_hour_24h:.2f}  /h (last 24h)")
    print(f"  • Unban Rate:             {unbans_per_hour_24h:.2f}  /h (last 24h)")
    print(f"  • Net Growth Rate:        {growth_rate_24h:+.2f} /h ({trend_str})")
    print(f"  • All bans ever issued:   {total_historical_bans}\n")

    if bans:
        print(f"{len(bans)} current active bans")
        print()
    print("-" * line_width)
    print()


def cmd_sync(conn, repair=False):
    """Check consistency between DB and nftables sets, optionally fix."""
    now = time.time()
    db_ips = {row[0] for row in conn.execute("SELECT ip FROM bans WHERE unban_time > ?", (now,))}
    nft_v4 = get_ban_set_ips("ip")
    nft_v6 = get_ban_set_ips("ip6")
    all_nft = nft_v4 | nft_v6

    missing_in_nft = db_ips - all_nft
    orphan_in_nft = all_nft - db_ips

    if not missing_in_nft and not orphan_in_nft:
        print("✅ Database and nftables sets are in sync.")
        return

    if missing_in_nft:
        print(f"⚠️  IPs in database but missing from nftables sets ({len(missing_in_nft)}):")
        for ip in sorted(missing_in_nft):
            print(f"   {ip}")
        if repair:
            print("Adding missing nftables set elements...")
            for ip in sorted(missing_in_nft):
                family = "ip6" if ":" in ip else "ip"
                set_name = "banned_ipv6" if family == "ip6" else "banned_ipv4"
                subprocess.run(
                    ["nft", "add", "element", family, "filter", set_name, f"{{ {ip} }}"],
                    capture_output=True, text=True
                )
                print(f"   ➕ Added {ip}")
        else:
            print("   Run with --repair to fix automatically.")

    if orphan_in_nft:
        print(f"⚠️  IPs in nftables sets but missing from database ({len(orphan_in_nft)}):")
        for ip in sorted(orphan_in_nft):
            print(f"   {ip}")
        if repair:
            print("Removing orphan nftables elements...")
            for ip in sorted(orphan_in_nft):
                if unban_ip(ip):
                    print(f"   🗑️  Removed {ip}")
        else:
            print("   Run with --repair to remove them.")


def cmd_stats(conn, top_n=10):
    bans = get_active_bans(conn)
    print(f"Active bans in database: {len(bans)}")

    v4_counters = get_ban_set_counters("ip")
    v6_counters = get_ban_set_counters("ip6")
    all_counters = {**v4_counters, **v6_counters}
    total_packets = sum(pkt for pkt, _ in all_counters.values())
    total_bytes = sum(byt for _, byt in all_counters.values())
    print(f"Total dropped packets (since element addition): {total_packets}")
    print(f"Total dropped bytes: {total_bytes}")

    if all_counters:
        print(f"\nTop {top_n} Blocked IPs by Bytes:")
        print(f"   {'IP':<20} {'Packets':<12} {'Bytes':<15}")
        print("   " + "-" * 50)
        sorted_by_bytes = sorted(all_counters.items(), key=lambda x: x[1][1], reverse=True)[:top_n]
        for ip, (pkt, byt) in sorted_by_bytes:
            print(f"   {ip:<20} {pkt:<12} {byt:<15}")

        print(f"\nTop {top_n} Blocked IPs by Packets:")
        print(f"   {'IP':<20} {'Packets':<12} {'Bytes':<15}")
        print("   " + "-" * 50)
        sorted_by_packets = sorted(all_counters.items(), key=lambda x: x[1][0], reverse=True)[:top_n]
        for ip, (pkt, byt) in sorted_by_packets:
            print(f"   {ip:<20} {pkt:<12} {byt:<15}")


def cmd_test(conn, ip):
    """Check if an IP is currently banned (database + nftables)."""
    now = time.time()
    cur = conn.execute("SELECT unban_time, rule_desc FROM bans WHERE ip = ? AND unban_time > ?",
                       (ip, now))
    row = cur.fetchone()
    if row:
        unban_time, reason = row
        remaining = unban_time - now if unban_time != float("inf") else float("inf")
        print(f"📋 Database: BANNED")
        print(f"   Reason: {reason}")
        print(f"   Remaining: {format_duration(remaining)}")
    else:
        print("📋 Database: not banned (or ban expired)")

    family = "ip6" if ":" in ip else "ip"
    nft_ips = get_ban_set_ips(family)
    if ip in nft_ips:
        counters = get_ban_set_counters(family)
        pkt, byt = counters.get(ip, (0, 0))
        print(f"🔒 nftables set: BLOCKED ({pkt} packets, {byt} bytes dropped)")
    else:
        print(f"🔓 nftables set: not blocked")


def cmd_unban(conn, ip):
    cur = conn.execute("SELECT ip FROM bans WHERE ip = ?", (ip,))
    if not cur.fetchone():
        print(f"❌ IP {ip} is not in the ban database.")
        return
    success = unban_ip(ip)
    remove_ban(conn, ip)
    if success:
        print(f"✅ IP {ip} unblocked (nftables element removed).")
    else:
        print(f"⚠️  No nftables set element found, but IP removed from database.")


def cmd_history(history_db_path, hours=3.0):
    """Show ban/unban history entries within the last N hours from the history DB."""
    if not os.path.exists(history_db_path):
        print(f"❌ History database not found at {history_db_path}.")
        return

    conn = sqlite3.connect(history_db_path)
    now = time.time()
    cutoff_timestamp = now - (hours * 3600)

    try:
        cur = conn.execute(
            "SELECT ip, action, rule_desc, duration, timestamp FROM decisions WHERE timestamp >= ? ORDER BY timestamp DESC",
            (cutoff_timestamp,)
        )
        rows = cur.fetchall()
    except sqlite3.OperationalError as e:
        print(f"❌ Error reading history database: {e}")
        conn.close()
        return
    finally:
        conn.close()

    if not rows:
        print(f"No history within the last {hours} hours.")
        return

    print(f"History within the last {hours} hours (newest first, total: {len(rows)}):")
    print(f"{'Time':<22} {'IP':<20} {'Action':<8} {'Duration':<12} {'Reason/Description'}")
    print("-" * 90)
    for ip, action, rule_desc, duration, ts in rows:
        time_str = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        dur_str = format_duration(duration) if action == "ban" else "-"
        desc = rule_desc
        if len(desc) > 30:
            desc = desc[:27] + "..."
        print(f"{time_str:<22} {ip:<20} {action.upper():<8} {dur_str:<12} {desc}")


def cmd_ping():
    """Send a ping to the running caddy-watch daemon via UNIX domain socket."""
    if not os.path.exists(SOCKET_PATH):
        print("❌ Connection socket missing. Is the core caddy-watch process running?")
        return
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2.0)
            client.connect(SOCKET_PATH)
            client.sendall(b"ping")
            response = client.recv(1024).decode("utf-8").strip()
            if response == "pong!":
                print("🏓 pong! (Core script is active and responding)")
            else:
                print(f"⚠️ Received unexpected response: {response}")
    except socket.timeout:
        print("❌ Ping timed out. The core script might be frozen.")
    except Exception as e:
        print(f"❌ Failed to reach core script: {e}")


def main():
    parser = argparse.ArgumentParser(description="Manage caddy-watch bans")
    sub = parser.add_subparsers(dest="command", help="Command")

    # list
    sub.add_parser("list", help="List active bans (oldest first)")

    # sync
    sync_parser = sub.add_parser("sync", help="Check DB vs nftables consistency")
    sync_parser.add_argument("--repair", action="store_true",
                             help="Automatically fix inconsistencies")

    # stats
    stats_parser = sub.add_parser("stats", help="Show ban statistics and dropped traffic")
    stats_parser.add_argument("--top", type=int, default=10,
                             help="Number of top blocked IPs to show (default: 10)")

    # test
    test_parser = sub.add_parser("test", help="Check if an IP is currently banned")
    test_parser.add_argument("ip", help="IP address")

    # unban
    unban_parser = sub.add_parser("unban", help="Remove a ban for an IP")
    unban_parser.add_argument("ip", help="IP address")

    # history
    hist_parser = sub.add_parser("history", help="Show ban/unban logs from the last N hours")
    hist_parser.add_argument("--hours", type=float, default=3.0,
                             help="Number of hours of history to display (default: 3)")

    # ping
    sub.add_parser("ping", help="Ping the main process to check health status")

    args = parser.parse_args()

    if not os.path.exists(DB_PATH):
        print(f"Database not found at {DB_PATH}. Is caddy-watch running?")
        sys.exit(1)

    # Root needed for nftables operations
    if args.command in ("sync", "unban", "test", "stats") and os.geteuid() != 0:
        print("This command requires root (nftables access). Use sudo.")
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)

    if args.command == "list" or args.command is None:
        cmd_list(conn)
    elif args.command == "sync":
        cmd_sync(conn, repair=args.repair)
    elif args.command == "stats":
        cmd_stats(conn, top_n=args.top)
    elif args.command == "test":
        cmd_test(conn, args.ip)
    elif args.command == "unban":
        cmd_unban(conn, args.ip)
    elif args.command == "history":
        cmd_history(HISTORY_DB_PATH, hours=args.hours)
    elif args.command == "ping":
        cmd_ping()
    else:
        parser.print_help()

    conn.close()


if __name__ == "__main__":
    main()