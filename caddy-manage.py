#!/usr/bin/env python3
"""
caddy-manage - advanced management for caddy-watch bans.
Commands:
  list             List active bans (oldest first)
  sync             Compare database vs nftables, optionally repair
  stats            Show total bans and dropped packets/bytes from nftables sets
  test <IP>        Check if an IP is currently banned
  unban <IP>       Remove a ban from database and nftables sets
  history          Show rule hits from the last N hours (default 3)     <--- CURRENTLY NOT WORKING
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
SOCKET_PATH = os.path.join(SCRIPT_DIR, "caddy-watch.sock")


def format_duration(seconds):
    if seconds < 0:
        return "expired"
    if seconds == float("inf"):
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
    parts.append(f"{secs}s")
    return " ".join(parts)


def get_ban_set_ips(family):
    """Return set of IP addresses currently in the given nftables ban set."""
    try:
        output = subprocess.run(
            ["nft", "list", "set", family, "filter", "ban"],
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
    try:
        output = subprocess.run(
            ["nft", "list", "set", family, "filter", "ban"],
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
    try:
        subprocess.run(
            ["nft", "delete", "element", family, "filter", "ban", f"{{ {ip} }}"],
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
    if not bans:
        print("No active bans.")
        return

    ip_col = 20
    reason_col = 50
    remaining_col = 20
    header = f"{'IP':<{ip_col}} {'Remaining':<{remaining_col}} {'Reason':<{reason_col}}"
    print(header)
    print("-" * len(header))

    now = time.time()
    for ip, unban_time, rule_desc in bans:
        remaining = unban_time - now if unban_time != float("inf") else float("inf")
        remaining_str = format_duration(remaining)
        if len(rule_desc) > reason_col - 2:
            rule_desc = rule_desc[:reason_col - 5] + "..."
        print(f"{ip:<{ip_col}} {remaining_str:<{remaining_col}} {rule_desc:<{reason_col}}")

    print("-" * len(header))
    print(f"{len(bans)} active bans in total\n")


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
                subprocess.run(
                    ["nft", "add", "element", family, "filter", "ban", f"{{ {ip} }}"],
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


def cmd_stats(conn):
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
        print("\nPer‑IP packet/byte counters:")
        for ip, (pkt, byt) in sorted(all_counters.items()):
            print(f"   {ip}: {pkt} packets, {byt} bytes")


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


# def cmd_history(conn, hours=3.0):
#     """Show rule hit entries within the last N hours."""
#     now = time.time()
#     cutoff_timestamp = now - (hours * 3600)
#
#     cur = conn.execute(
#         "SELECT ip, rule_id, timestamp FROM rule_hits WHERE timestamp >= ? ORDER BY timestamp DESC",
#         (cutoff_timestamp,)
#     )
#     rows = cur.fetchall()
#     if not rows:
#         print(f"No rule hit history within the last {hours} hours.")
#         return
#
#     rules = load_rules()
#     print(f"Rule hits within the last {hours} hours (newest first, total: {len(rows)}):")
#     print(f"{'Time':<22} {'IP':<20} {'Rule Description'}")
#     print("-" * 70)
#     for ip, rule_id, ts in rows:
#         time_str = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
#         desc = ""
#         if 0 <= rule_id < len(rules):
#             desc = rules[rule_id].get("description", f"Rule {rule_id}")
#         else:
#             desc = f"Unknown rule {rule_id}"
#         if len(desc) > 45:
#             desc = desc[:42] + "..."
#         print(f"{time_str:<22} {ip:<20} {desc}")


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
    sub.add_parser("stats", help="Show ban statistics and dropped traffic")

    # test
    test_parser = sub.add_parser("test", help="Check if an IP is currently banned")
    test_parser.add_argument("ip", help="IP address")

    # unban
    unban_parser = sub.add_parser("unban", help="Remove a ban for an IP")
    unban_parser.add_argument("ip", help="IP address")

    # history (BROKEN)
    # hist_parser = sub.add_parser("history", help="Show rule hit logs from the last N hours")
    # hist_parser.add_argument("--hours", type=float, default=3.0,
    #                          help="Number of hours of history to display (default: 3)")

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
        cmd_stats(conn)
    elif args.command == "test":
        cmd_test(conn, args.ip)
    elif args.command == "unban":
        cmd_unban(conn, args.ip)
    # elif args.command == "history":
    #     cmd_history(conn, hours=args.hours)
    elif args.command == "ping":
        cmd_ping()
    else:
        parser.print_help()

    conn.close()


if __name__ == "__main__":
    main()