#!/usr/bin/env python3
"""
DirFinder v1.0
Author: RedNeutron
A fast, feature-rich directory and file brute-forcer for bug bounty hunting.
"""

import os
import sys
import time
import json
import random
import signal
import argparse
import threading
import requests
import urllib3
from pathlib import Path
from datetime import datetime
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, MofNCompleteColumn
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.live import Live
    from rich.layout import Layout
    from rich import box
    from rich.rule import Rule
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    print("[!] 'rich' not installed. Run: pip install rich")
    print("[!] Falling back to basic output.\n")

try:
    import colorama
    colorama.init()
except ImportError:
    pass

# ══════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════

VERSION     = "1.0.0"
AUTHOR      = "RedNeutron"
TOOL_NAME   = "DirFinder"

BUILTIN_WORDLIST = Path(__file__).parent / "wordlists" / "builtin.txt"

# Status codes to show (others are hidden)
INTERESTING_CODES = {200, 201, 204, 301, 302, 303, 307, 308, 401, 403, 405, 500, 501, 502, 503}

# Color mapping per status code
STATUS_COLORS = {
    200: "bold green",
    201: "bold green",
    204: "green",
    301: "bold yellow",
    302: "bold yellow",
    303: "yellow",
    307: "yellow",
    308: "yellow",
    401: "bold magenta",
    403: "bold red",
    405: "cyan",
    500: "bold red",
    501: "red",
    502: "red",
    503: "red",
}

STATUS_ICONS = {
    200: "✅", 201: "✅", 204: "✅",
    301: "↪ ", 302: "↪ ", 303: "↪ ", 307: "↪ ", 308: "↪ ",
    401: "🔐", 403: "🔒",
    405: "⚡",
    500: "💥", 501: "💥", 502: "💥", 503: "💥",
}

# ══════════════════════════════════════
# STATE
# ══════════════════════════════════════

console     = Console() if HAS_RICH else None
findings    = []          # List of found results
lock        = threading.Lock()
stop_event  = threading.Event()
scan_stats  = {
    "scanned":   0,
    "found":     0,
    "errors":    0,
    "start_time": None,
    "speed":     0.0,
}
resume_file = None
scanned_paths = set()  # For resume functionality

# ══════════════════════════════════════
# BANNER
# ══════════════════════════════════════

def print_banner():
    if HAS_RICH:
        banner = Panel.fit(
            f"[bold cyan]{TOOL_NAME}[/] [dim]v{VERSION}[/]  |  [dim]by[/] [bold cyan]{AUTHOR}[/]\n"
            "[dim]Fast directory & file brute-forcer for bug bounty hunting[/]",
            border_style="cyan",
            box=box.DOUBLE_EDGE,
        )
        console.print(banner)
        console.print()
    else:
        print("=" * 50)
        print(f"  {TOOL_NAME} v{VERSION}  |  by {AUTHOR}")
        print("  Fast directory brute-forcer")
        print("=" * 50)
        print()

def print_config(args, wordlist_count):
    if HAS_RICH:
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("Key",   style="dim", width=14)
        table.add_column("Value", style="bold white")

        table.add_row("Target",     f"[cyan]{args.url}[/]")
        table.add_row("Method",     f"[yellow]{args.method}[/]")
        table.add_row("Threads",    f"[green]{args.threads}[/]")
        table.add_row("Timeout",    f"{args.timeout}s")
        table.add_row("Wordlist",   f"{wordlist_count} paths")

        if args.extensions:
            table.add_row("Extensions", " ".join(f"[magenta].{e}[/]" for e in args.extensions))
        if args.delay:
            table.add_row("Delay",      f"{args.delay[0]}-{args.delay[1]}s (random)")
        if args.headers:
            table.add_row("Headers",    f"{len(args.headers)} custom")
        if args.cookie:
            table.add_row("Cookie",     "[dim]set[/]")
        if args.auth:
            table.add_row("Auth",       "[dim]set[/]")

        table.add_row("Follow Redirects", "Yes" if args.follow_redirects else "No")
        table.add_row("Recurse",    "Yes" if args.recurse else "No")
        table.add_row("Output",     args.output or "[dim]not set[/]")
        table.add_row("Resume",     "Yes" if args.resume else "No")

        console.print(Panel(table, title="[bold]Scan Configuration[/]", border_style="dim", box=box.ROUNDED))
        console.print()
    else:
        print(f"  Target  : {args.url}")
        print(f"  Threads : {args.threads}")
        print(f"  Paths   : {wordlist_count}")
        print()

# ══════════════════════════════════════
# WORDLIST LOADER
# ══════════════════════════════════════

def load_wordlist(args):
    paths = []
    seen  = set()

    def add(word):
        w = word.strip()
        if w and not w.startswith("#") and w not in seen:
            seen.add(w)
            paths.append(w)

    # Built-in wordlist
    if not args.no_builtin:
        if BUILTIN_WORDLIST.exists():
            with open(BUILTIN_WORDLIST, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    add(line)
        else:
            if HAS_RICH:
                console.print(f"[yellow][!] Built-in wordlist not found at {BUILTIN_WORDLIST}[/]")

    # Custom wordlist
    if args.wordlist:
        for wl_path in args.wordlist:
            p = Path(wl_path)
            if not p.exists():
                if HAS_RICH:
                    console.print(f"[red][!] Wordlist not found: {wl_path}[/]")
                continue
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    add(line)

    # Add extensions
    if args.extensions:
        base_paths = list(paths)
        for word in base_paths:
            if "." not in word.split("/")[-1]:  # Only add ext to non-extension paths
                for ext in args.extensions:
                    ext = ext.lstrip(".")
                    new = f"{word}.{ext}"
                    if new not in seen:
                        seen.add(new)
                        paths.append(new)

    return paths

# ══════════════════════════════════════
# RESUME SUPPORT
# ══════════════════════════════════════

def get_resume_file(url):
    safe = url.replace("://", "_").replace("/", "_").replace(":", "_")
    return Path(f".dirfinder_resume_{safe}.json")

def load_resume(url):
    rf = get_resume_file(url)
    if rf.exists():
        try:
            with open(rf) as f:
                data = json.load(f)
            return set(data.get("scanned", []))
        except Exception:
            return set()
    return set()

def save_resume(url, scanned):
    rf = get_resume_file(url)
    try:
        with open(rf, "w") as f:
            json.dump({"scanned": list(scanned), "timestamp": datetime.now().isoformat()}, f)
    except Exception:
        pass

def clear_resume(url):
    rf = get_resume_file(url)
    if rf.exists():
        rf.unlink()

# ══════════════════════════════════════
# HTTP REQUEST
# ══════════════════════════════════════

def make_request(url, args, session, retries=3):
    headers = {
        "User-Agent": args.user_agent,
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
    }

    if args.headers:
        for h in args.headers:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

    if args.cookie:
        headers["Cookie"] = args.cookie

    if args.auth:
        headers["Authorization"] = args.auth

    kwargs = {
        "headers":         headers,
        "timeout":         args.timeout,
        "verify":          False,
        "allow_redirects": args.follow_redirects,
    }

    for attempt in range(retries):
        if stop_event.is_set():
            return None
        try:
            if args.delay:
                time.sleep(random.uniform(args.delay[0], args.delay[1]))

            method = args.method.upper()
            if method == "HEAD":
                resp = session.head(url, **kwargs)
            elif method == "POST":
                resp = session.post(url, **kwargs)
            else:
                resp = session.get(url, **kwargs)

            return resp

        except requests.exceptions.Timeout:
            if attempt == retries - 1:
                with lock:
                    scan_stats["errors"] += 1
            continue
        except requests.exceptions.ConnectionError:
            if attempt == retries - 1:
                with lock:
                    scan_stats["errors"] += 1
            time.sleep(0.5 * (attempt + 1))
            continue
        except Exception:
            with lock:
                scan_stats["errors"] += 1
            return None

    return None

# ══════════════════════════════════════
# SCAN WORKER
# ══════════════════════════════════════

def scan_path(base_url, path, args, session, progress=None, task=None):
    global scanned_paths

    if stop_event.is_set():
        return None

    # Clean path
    path = path.lstrip("/")
    full_url = urljoin(base_url.rstrip("/") + "/", path)

    resp = make_request(full_url, args, session)

    with lock:
        scan_stats["scanned"] += 1
        scanned_paths.add(path)

        if progress and task is not None:
            progress.advance(task)

        if resp is None:
            return None

        code = resp.status_code

        if code not in INTERESTING_CODES:
            return None

        # Content length
        content_len = len(resp.content) if resp.content else 0

        # Redirect location
        location = resp.headers.get("Location", "") if code in {301, 302, 303, 307, 308} else ""

        result = {
            "url":         full_url,
            "path":        path,
            "status":      code,
            "size":        content_len,
            "location":    location,
            "server":      resp.headers.get("Server", ""),
            "content_type":resp.headers.get("Content-Type", ""),
            "timestamp":   datetime.now().isoformat(),
        }

        findings.append(result)
        scan_stats["found"] += 1

        return result

def print_finding(result, args):
    if not result:
        return

    code      = result["status"]
    url       = result["url"]
    size      = result["size"]
    location  = result["location"]
    icon      = STATUS_ICONS.get(code, "  ")
    color     = STATUS_COLORS.get(code, "white")

    if HAS_RICH:
        size_str = f"[dim]{size:,}b[/]" if size else ""
        loc_str  = f" [dim]→ {location}[/]" if location else ""
        console.print(
            f" {icon} [{color}]{code}[/] [bold]{url}[/]{loc_str} {size_str}"
        )
    else:
        loc_str = f" -> {location}" if location else ""
        print(f" {icon} {code} {url}{loc_str} ({size}b)")

# ══════════════════════════════════════
# RECURSIVE SCAN
# ══════════════════════════════════════

def get_dirs_to_recurse(results):
    dirs = set()
    for r in results:
        if r["status"] in {200, 301, 302, 403} and (
            r["path"].endswith("/") or "." not in r["path"].split("/")[-1]
        ):
            dirs.add(r["url"].rstrip("/") + "/")
    return dirs

# ══════════════════════════════════════
# EXPORT
# ══════════════════════════════════════

def export_results(output_path, args):
    if not findings:
        return

    lines = []
    lines.append(f"# DirFinder v{VERSION} — by {AUTHOR}")
    lines.append(f"# Target    : {args.url}")
    lines.append(f"# Scanned   : {scan_stats['scanned']} paths")
    lines.append(f"# Found     : {scan_stats['found']} results")
    lines.append(f"# Duration  : {time.time() - scan_stats['start_time']:.1f}s")
    lines.append(f"# Date      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("=" * 60)
    lines.append("")

    # Group by status
    groups = {}
    for r in findings:
        groups.setdefault(r["status"], []).append(r)

    for code in sorted(groups.keys()):
        lines.append(f"## HTTP {code}")
        for r in groups[code]:
            loc = f" -> {r['location']}" if r["location"] else ""
            lines.append(f"  {r['url']}{loc}  ({r['size']}b)")
        lines.append("")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    if HAS_RICH:
        console.print(f"\n[green][+] Results saved to: [bold]{output_path}[/][/]")
    else:
        print(f"\n[+] Results saved to: {output_path}")

# ══════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════

def print_summary(duration):
    if HAS_RICH:
        console.print()
        console.print(Rule("[bold]Scan Complete[/]", style="cyan"))
        console.print()

        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        table.add_column("Metric", style="dim")
        table.add_column("Value",  style="bold white")

        table.add_row("Total Scanned", f"{scan_stats['scanned']:,}")
        table.add_row("Found",         f"[bold green]{scan_stats['found']}[/]")
        table.add_row("Errors",        f"[yellow]{scan_stats['errors']}[/]")
        table.add_row("Duration",      f"{duration:.1f}s")
        table.add_row("Avg Speed",     f"{scan_stats['scanned']/max(duration,1):.0f} req/s")

        console.print(table)

        if findings:
            console.print()
            console.print("[bold]Findings Summary:[/]")
            groups = {}
            for r in findings:
                groups.setdefault(r["status"], []).append(r)
            for code in sorted(groups.keys()):
                color = STATUS_COLORS.get(code, "white")
                icon  = STATUS_ICONS.get(code, "  ")
                console.print(f"  {icon} [{color}]{code}[/] — {len(groups[code])} found")
    else:
        print(f"\n{'='*40}")
        print(f"  Scanned : {scan_stats['scanned']}")
        print(f"  Found   : {scan_stats['found']}")
        print(f"  Errors  : {scan_stats['errors']}")
        print(f"  Time    : {duration:.1f}s")

# ══════════════════════════════════════
# SIGNAL HANDLER
# ══════════════════════════════════════

def handle_interrupt(sig, frame):
    if HAS_RICH:
        console.print("\n\n[yellow][!] Interrupted — saving progress...[/]")
    else:
        print("\n\n[!] Interrupted — saving progress...")
    stop_event.set()

# ══════════════════════════════════════
# ARGUMENT PARSER
# ══════════════════════════════════════

def parse_args():
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=f"{TOOL_NAME} v{VERSION} — Fast directory brute-forcer by {AUTHOR}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan with built-in wordlist
  python dirfinder.py -u https://target.com

  # Custom wordlist + extensions
  python dirfinder.py -u https://target.com -w mylist.txt -e php html bak

  # Fast scan with 50 threads, HEAD method
  python dirfinder.py -u https://target.com -t 50 -X HEAD

  # Authenticated scan with custom cookie
  python dirfinder.py -u https://target.com -c "session=abc123"

  # Full scan with all options
  python dirfinder.py -u https://target.com -w wordlist.txt -e php bak -t 30 -o results.txt --recurse --resume
        """
    )

    # Target
    parser.add_argument("-u", "--url",
        required=True, metavar="URL",
        help="Target URL (e.g. https://target.com)")

    # Wordlist
    parser.add_argument("-w", "--wordlist",
        nargs="+", metavar="FILE",
        help="Custom wordlist file(s) — combined with built-in")
    parser.add_argument("--no-builtin",
        action="store_true",
        help="Disable built-in wordlist (use only custom)")

    # Extensions
    parser.add_argument("-e", "--extensions",
        nargs="+", metavar="EXT",
        help="File extensions to append (e.g. -e php html bak)")

    # Threading
    parser.add_argument("-t", "--threads",
        type=int, default=20, metavar="N",
        help="Number of threads (default: 20)")

    # HTTP Method
    parser.add_argument("-X", "--method",
        default="GET", metavar="METHOD",
        choices=["GET", "HEAD", "POST"],
        help="HTTP method: GET, HEAD, POST (default: GET)")

    # Timeout
    parser.add_argument("--timeout",
        type=float, default=5.0, metavar="SEC",
        help="Request timeout in seconds (default: 5)")

    # Headers
    parser.add_argument("-H", "--headers",
        nargs="+", metavar="HEADER",
        help='Custom headers (e.g. -H "X-Custom: value")')

    # Cookie
    parser.add_argument("-c", "--cookie",
        metavar="COOKIE",
        help="Cookie string (e.g. 'session=abc; token=xyz')")

    # Auth
    parser.add_argument("-a", "--auth",
        metavar="TOKEN",
        help="Authorization header value (e.g. Bearer abc123)")

    # User-Agent
    parser.add_argument("--user-agent",
        default="DirFinder/1.0 (Bug Bounty Scanner)",
        metavar="UA",
        help="Custom User-Agent string")

    # Redirects
    parser.add_argument("--follow-redirects",
        action="store_true",
        help="Follow HTTP redirects")

    # Delay
    parser.add_argument("-d", "--delay",
        nargs=2, type=float, metavar=("MIN", "MAX"),
        help="Random delay between requests in seconds (e.g. -d 0.1 0.5)")

    # Recurse
    parser.add_argument("--recurse",
        action="store_true",
        help="Recursively scan found directories")

    # Status codes filter
    parser.add_argument("-mc", "--match-codes",
        nargs="+", type=int, metavar="CODE",
        help="Only show these status codes (e.g. -mc 200 403)")

    # Output
    parser.add_argument("-o", "--output",
        metavar="FILE",
        help="Save results to file")

    # Resume
    parser.add_argument("--resume",
        action="store_true",
        help="Resume previous scan (skip already scanned paths)")

    # Quiet
    parser.add_argument("-q", "--quiet",
        action="store_true",
        help="Suppress banner and config output")

    return parser.parse_args()

# ══════════════════════════════════════
# MAIN SCAN
# ══════════════════════════════════════

def run_scan(base_url, paths, args, session, depth=0):
    global scanned_paths

    # Filter resume
    if args.resume and scanned_paths:
        paths = [p for p in paths if p not in scanned_paths]
        if HAS_RICH:
            console.print(f"[dim][*] Resuming — {len(paths)} paths remaining[/]\n")

    # Override interesting codes if user specified
    if args.match_codes:
        global INTERESTING_CODES
        INTERESTING_CODES = set(args.match_codes)

    local_findings = []

    if HAS_RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}[/]"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            TextColumn("[dim]{task.fields[speed]} req/s[/]"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
            refresh_per_second=10,
        ) as progress:
            label = f"Scanning {'(recurse)' if depth > 0 else ''}"
            task  = progress.add_task(label, total=len(paths), speed="—")

            last_count = 0
            last_time  = time.time()

            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = {
                    executor.submit(scan_path, base_url, p, args, session, progress, task): p
                    for p in paths
                }

                for future in as_completed(futures):
                    if stop_event.is_set():
                        executor.shutdown(wait=False)
                        break

                    result = future.result()
                    if result:
                        local_findings.append(result)
                        print_finding(result, args)

                    # Update speed
                    now = time.time()
                    if now - last_time >= 1.0:
                        speed = (scan_stats["scanned"] - last_count) / (now - last_time)
                        progress.update(task, speed=f"{speed:.0f}")
                        last_count = scan_stats["scanned"]
                        last_time  = now

                        # Save resume every 5 seconds
                        if args.resume:
                            save_resume(base_url, scanned_paths)
    else:
        # Fallback no-rich mode
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(scan_path, base_url, p, args, session, None, None): p
                for p in paths
            }
            for future in as_completed(futures):
                if stop_event.is_set():
                    break
                result = future.result()
                if result:
                    local_findings.append(result)
                    print_finding(result, args)

    # Recurse into found directories
    if args.recurse and depth < 2 and local_findings:
        dirs = get_dirs_to_recurse(local_findings)
        for dir_url in dirs:
            if stop_event.is_set():
                break
            if HAS_RICH:
                console.print(f"\n[cyan][→] Recursing into: {dir_url}[/]\n")
            run_scan(dir_url, paths, args, session, depth=depth + 1)

# ══════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════

def main():
    global resume_file, scanned_paths

    args = parse_args()
    signal.signal(signal.SIGINT, handle_interrupt)

    # Normalize URL
    if not args.url.startswith(("http://", "https://")):
        args.url = "https://" + args.url

    if not args.quiet:
        print_banner()

    # Load wordlist
    paths = load_wordlist(args)
    if not paths:
        if HAS_RICH:
            console.print("[red][!] No paths to scan. Provide a wordlist or enable built-in.[/]")
        else:
            print("[!] No paths to scan.")
        sys.exit(1)

    if not args.quiet:
        print_config(args, len(paths))

    # Resume
    if args.resume:
        scanned_paths = load_resume(args.url)
        if scanned_paths and HAS_RICH:
            console.print(f"[dim][*] Loaded {len(scanned_paths)} previously scanned paths[/]")

    # Start
    scan_stats["start_time"] = time.time()

    if HAS_RICH:
        console.print(Rule(f"[bold cyan]Scanning {args.url}[/]", style="dim"))
        console.print()

    # Create session
    session = requests.Session()
    session.verify = False

    # Run scan
    run_scan(args.url, paths, args, session)

    # Done
    duration = time.time() - scan_stats["start_time"]

    # Save resume or clear it
    if stop_event.is_set() and args.resume:
        save_resume(args.url, scanned_paths)
        if HAS_RICH:
            console.print(f"[yellow][!] Progress saved. Run with --resume to continue.[/]")
    elif args.resume:
        clear_resume(args.url)

    # Print summary
    print_summary(duration)

    # Export
    if args.output:
        export_results(args.output, args)
    elif findings:
        # Auto-save if findings exist
        auto_out = f"dirfinder_{urlparse(args.url).netloc}_{int(time.time())}.txt"
        export_results(auto_out, args)

    if HAS_RICH:
        console.print()
        console.print(f"[dim]Big respect for Mr Net0[/]")
        console.print()

if __name__ == "__main__":
    main()
