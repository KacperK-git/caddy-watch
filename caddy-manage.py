#!/usr/bin/env python3
"""
caddy-manage - advanced management for caddy-watch bans.
Commands:
  list             List active bans (oldest first)
  sync             Compare database vs nftables, optionally repair
  stats            Show total bans and dropped packets/bytes from nftables
  test <IP>        Check if an IP is currently banned
  unban <IP>       Remove a ban from database and nftables
  history          Show recent hits (rule triggers) - last 20
"""

import os
import re
import sys
import sqlite3
import subprocess
import time
import argparse
from datetime import datetime, timezone


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, "caddy-watch.db")


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

def get_ban_chain_ips(family):
    """Return set of IP addresses currently in the given nftables ban chain."""
    try:
        output = subprocess.run(
            ["nft", "list", "chain", family, "filter", "ban"],
            capture_output=True, text=True, check=True
        ).stdout
    except subprocess.CalledProcessError:
        return set()
    ips = set()
    keyword = "ip6 saddr " if family == "ip6" else "ip saddr "
    for line in output.splitlines():
        if keyword in line and "drop" in line:
            # Extract IP between keyword and " counter"
            parts = line.split(keyword, 1)
            if len(parts) > 1:
                rest = parts[1]
                ip = rest.split(" counter", 1)[0].strip()
                ips.add(ip)
    return ips

def get_ban_chain_counters(family):
    """Return dict IP -> (packets, bytes) from the ban chain."""
    counters = {}
    try:
        output = subprocess.run(
            ["nft", "list", "chain", family, "filter", "ban"],
            capture_output=True, text=True, check=True
        ).stdout
    except subprocess.CalledProcessError:
        return counters

    keyword = "ip6 saddr " if family == "ip6" else "ip saddr "
    for line in output.splitlines():
        if keyword not in line or "drop" not in line:
            continue
        # Extract IP
        _, after_keyword = line.split(keyword, 1)
        parts = after_keyword.split(None, 1)   # split on whitespace: first token is IP
        ip = parts[0]
        # The rest contains "counter packets X bytes Y drop …"
        rest = parts[1] if len(parts) > 1 else ""
        # Find packets and bytes using regex
        pkt_match = re.search(r'packets\s+(\d+)', rest)
        bytes_match = re.search(r'bytes\s+(\d+)', rest)
        packets = int(pkt_match.group(1)) if pkt_match else 0
        byt = int(bytes_match.group(1)) if bytes_match else 0
        counters[ip] = (packets, byt)
    return counters

def unban_ip(ip: str):
    """Remove the nftables rule for the given IP."""
    family = "ip6" if ":" in ip else "ip"
    try:
        result = subprocess.run(
            ["nft", "-a", "list", "chain", family, "filter", "ban"],
            capture_output=True, text=True, check=True
        )
        for line in result.stdout.splitlines():
            addr_keyword = "ip6 saddr" if family == "ip6" else "ip saddr"
            if f"{addr_keyword} {ip}" in line and "drop" in line:
                handle = line.split("handle")[-1].strip()
                if handle.isdigit():
                    subprocess.run(
                        ["nft", "delete", "rule", family, "filter",
                         "ban", "handle", handle],
                        check=True, capture_output=True, text=True
                    )
                    return True
        return False
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
            rule_desc = rule_desc[:reason_col-5] + "..."
        print(f"{ip:<{ip_col}} {remaining_str:<{remaining_col}} {rule_desc:<{reason_col}}")

    print("-" * len(header))
    print(f"{len(bans)} active bans in total\n")

def cmd_sync(conn, repair=False):
    """Check consistency between DB and nftables, optionally fix."""
    now = time.time()
    db_ips = {row[0] for row in conn.execute("SELECT ip FROM bans WHERE unban_time > ?", (now,))}
    nft_v4 = get_ban_chain_ips("ip")
    nft_v6 = get_ban_chain_ips("ip6")
    all_nft = nft_v4 | nft_v6

    missing_in_nft = db_ips - all_nft
    orphan_in_nft = all_nft - db_ips

    if not missing_in_nft and not orphan_in_nft:
        print("✅ Database and nftables are in sync.")
        return

    if missing_in_nft:
        print(f"⚠️  IPs in database but missing from nftables ({len(missing_in_nft)}):")
        for ip in sorted(missing_in_nft):
            print(f"   {ip}")
        if repair:
            print("Adding missing nftables rules...")
            for ip in sorted(missing_in_nft):
                family = "ip6" if ":" in ip else "ip"
                subprocess.run(
                    ["nft", "add", "rule", family, "filter", "ban",
                     "ip6" if family == "ip6" else "ip", "saddr", ip, "counter", "drop"],
                    capture_output=True, text=True
                )
                print(f"   ➕ Added {ip}")
        else:
            print("   Run with --repair to fix automatically.")

    if orphan_in_nft:
        print(f"⚠️  IPs in nftables but missing from database ({len(orphan_in_nft)}):")
        for ip in sorted(orphan_in_nft):
            print(f"   {ip}")
        if repair:
            print("Removing orphan nftables rules...")
            for ip in sorted(orphan_in_nft):
                if unban_ip(ip):
                    print(f"   🗑️  Removed {ip}")
        else:
            print("   Run with --repair to remove them.")

def cmd_stats(conn):
    bans = get_active_bans(conn)
    print(f"Active bans in database: {len(bans)}")

    v4_counters = get_ban_chain_counters("ip")
    v6_counters = get_ban_chain_counters("ip6")
    all_counters = {**v4_counters, **v6_counters}
    total_packets = sum(pkt for pkt, _ in all_counters.values())
    total_bytes = sum(byt for _, byt in all_counters.values())
    print(f"Total dropped packets (since rule creation): {total_packets}")
    print(f"Total dropped bytes: {total_bytes}")
    # Show per‑IP counters if any
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
    nft_ips = get_ban_chain_ips(family)
    if ip in nft_ips:
        counters = get_ban_chain_counters(family)
        pkt, byt = counters.get(ip, (0, 0))
        print(f"🔒 nftables: BLOCKED ({pkt} packets, {byt} bytes dropped)")
    else:
        print(f"🔓 nftables: not blocked")

def cmd_unban(conn, ip):
    cur = conn.execute("SELECT ip FROM bans WHERE ip = ?", (ip,))
    if not cur.fetchone():
        print(f"❌ IP {ip} is not in the ban database.")
        return
    success = unban_ip(ip)
    remove_ban(conn, ip)
    if success:
        print(f"✅ IP {ip} unblocked (nftables rule removed).")
    else:
        print(f"⚠️  No nftables rule found, but IP removed from database.")

def cmd_history(conn, limit=20):
    """Show recent rule hit entries with rule description."""
    cur = conn.execute(
        "SELECT ip, rule_id, timestamp FROM rule_hits ORDER BY timestamp DESC LIMIT ?",
        (limit,)
    )
    rows = cur.fetchall()
    if not rows:
        print("No rule hit history yet.")
        return

    rules = load_rules()
    print(f"Last {len(rows)} rule hits (newest first):")
    print(f"{'Time':<22} {'IP':<20} {'Rule Description'}")
    print("-" * 70)
    for ip, rule_id, ts in rows:
        time_str = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        desc = ""
        if 0 <= rule_id < len(rules):
            desc = rules[rule_id].get("description", f"Rule {rule_id}")
        else:
            desc = f"Unknown rule {rule_id}"
        if len(desc) > 45:
            desc = desc[:42] + "..."
        print(f"{time_str:<22} {ip:<20} {desc}")


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

    # history
    hist_parser = sub.add_parser("history", help="Show recent rule hit logs")
    hist_parser.add_argument("--limit", type=int, default=20,
                             help="Number of entries (default 20)")

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
    elif args.command == "history":
        cmd_history(conn, limit=args.limit)
    else:
        parser.print_help()

    conn.close()

if __name__ == "__main__":
    main()
