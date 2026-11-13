"""certpulse CLI."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .core import check_many

STATUS_COLOR = {
    "OK": "\033[32m", "WARNING": "\033[33m", "CRITICAL": "\033[31m",
    "EXPIRED": "\033[1;31m", "ERROR": "\033[35m",
}
RESET = "\033[0m"
SEVERITY = {"OK": 0, "WARNING": 1, "CRITICAL": 2, "EXPIRED": 2, "ERROR": 2}


def read_targets(args) -> list[str]:
    targets = list(args.targets)
    if args.file:
        fh = sys.stdin if args.file == "-" else open(args.file, encoding="utf-8")
        with fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    targets.append(line)
    return targets


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="certpulse", description="Check TLS certificate expiry for many hosts.")
    p.add_argument("targets", nargs="*", help="host, host:port, https://url or host:port@sni")
    p.add_argument("-f", "--file", help="read targets from file ('-' for stdin), one per line, # comments ok")
    p.add_argument("-w", "--warn", type=int, default=30, help="warning threshold in days (default 30)")
    p.add_argument("-c", "--crit", type=int, default=7, help="critical threshold in days (default 7)")
    p.add_argument("-t", "--timeout", type=float, default=8.0)
    p.add_argument("-j", "--workers", type=int, default=16)
    p.add_argument("--format", choices=["table", "json", "csv"], default="table")
    p.add_argument("--sort", choices=["days", "input"], default="days")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("-V", "--version", action="version", version=f"certpulse {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    targets = read_targets(args)
    if not targets:
        print("certpulse: no targets given", file=sys.stderr)
        return 3
    results = check_many(targets, args.timeout, args.workers)
    if args.sort == "days":
        results.sort(key=lambda r: (r.days_left is not None, r.days_left if r.days_left is not None else 0))

    worst = 0
    for r in results:
        worst = max(worst, SEVERITY[r.status(args.warn, args.crit)])

    if args.format == "json":
        out = []
        for r in results:
            d = r.to_dict()
            d["status"] = r.status(args.warn, args.crit)
            out.append(d)
        print(json.dumps(out, indent=2))
    elif args.format == "csv":
        print("target,status,days_left,not_after,issuer,error")
        for r in results:
            cells = [r.target, r.status(args.warn, args.crit), "" if r.days_left is None else f"{r.days_left:.1f}",
                     r.not_after or "", r.issuer or "", (r.error or "").replace(",", ";")]
            print(",".join(cells))
    else:
        color = not args.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ
        width = max(len(r.target) for r in results)
        print(f"{'TARGET':<{width}}  {'STATUS':<8}  {'DAYS':>6}  {'EXPIRES (UTC)':<16}  ISSUER / ERROR")
        for r in results:
            st = r.status(args.warn, args.crit)
            st_txt = f"{STATUS_COLOR[st]}{st:<8}{RESET}" if color else f"{st:<8}"
            days = "-" if r.days_left is None else f"{r.days_left:.0f}"
            exp = (r.not_after or "")[:16].replace("T", " ")
            tail = r.issuer or ""
            if r.error:
                tail = f"{tail} ({r.error})" if tail else r.error
            print(f"{r.target:<{width}}  {st_txt}  {days:>6}  {exp:<16}  {tail}")
    return worst


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
