"""secopt: find what a security stack costs, what is unused and what overlaps."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tomllib
from importlib import resources
from pathlib import Path
from typing import Any, Callable

from secopt import __version__
from secopt.core.env import env_int, env_str, load_dotenv
from secopt.core.http import HttpClient, HttpError
from secopt.core.model import Opportunity, is_currency, is_number, money, total_saving
from secopt.core.output import parse_formats, to_json, write_text
from secopt.report import licenses_markdown, overlap_markdown, sentinel_markdown, write_reports

EXIT_OK, EXIT_ERROR = 0, 2

EPILOG = """examples:
  secopt sentinel --demo                         offline demo: Sentinel ingestion cost review
  secopt sentinel --workspace /subscriptions/<id>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<name>
  secopt sentinel --workspace <id> --days 60 --price-per-gb 3.10

  secopt licenses --demo                         offline demo: unused Microsoft 365 licences
  secopt licenses --prices my-prices.toml        your tenant, valued at your agreement's prices

  secopt overlap --demo                          offline demo: tool overlap and gaps
  secopt overlap my-stack.toml                   your own inventory (see examples/security-stack.toml)
  secopt overlap --list-capabilities

exit codes: 0 success, 2 error"""


class UsageError(Exception):
    """A problem the user can fix: bad arguments, missing credentials, unreadable file."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secopt", epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Find what a security stack costs, what is unused and what overlaps. Read-only.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="{sentinel,licenses,overlap}")

    def common(p: argparse.ArgumentParser, snapshots: bool = True) -> None:
        p.add_argument("--demo", action="store_true", help="use built-in fictional data (no credentials)")
        if snapshots:
            p.add_argument("--snapshot", metavar="FILE", help="analyse data saved with --save-snapshot")
            p.add_argument("--save-snapshot", metavar="FILE", help="also save the collected data as JSON")
        p.add_argument("--out", metavar="DIR", default="reports", help="report folder (default: reports)")
        p.add_argument("--format", default="md,csv,json", metavar="LIST", help="report formats: md, csv, json")
        p.add_argument("--env-file", default=".env", metavar="PATH", help="settings file (default: .env)")
        p.add_argument("--quiet", action="store_true", help="print only the report paths")

    s = sub.add_parser("sentinel", help="Microsoft Sentinel ingestion cost review.",
                       description="What each table costs, which pricing plan is cheapest, which tables no "
                                   "detection reads, and what grew.")
    common(s)
    s.add_argument("--workspace", metavar="RESOURCE_ID", help="full resource ID of the Log Analytics workspace")
    s.add_argument("--days", type=int, default=30, help="days of usage to analyse, 7 to 90 (default 30)")
    s.add_argument("--price-per-gb", type=float, metavar="PRICE",
                   help="your pay-as-you-go price per GB, instead of the public list price")
    s.add_argument("--currency", default=None, metavar="CODE", help="currency for list prices (default USD)")

    lic = sub.add_parser("licenses", help="Unused Microsoft 365 licences.",
                         description="Licences that are unassigned, on disabled or inactive accounts, or "
                                     "duplicated by a suite the user already has.")
    common(lic)
    lic.add_argument("--prices", metavar="FILE", help="TOML file with your price per user per month by product")
    lic.add_argument("--inactive-days", type=int, default=90, help="days without sign-in (default 90)")

    o = sub.add_parser("overlap", help="Security tool overlap and gaps.",
                       description="From an inventory of your tools: capabilities paid for twice, tools that "
                                   "are fully redundant, and required capabilities nothing covers.")
    common(o, snapshots=False)
    o.add_argument("inventory", nargs="?", metavar="INVENTORY.toml", help="your tool inventory")
    o.add_argument("--list-capabilities", action="store_true", help="print the capability vocabulary and exit")
    return parser


def _demo(package: str, name: str) -> str:
    return resources.files(package).joinpath(name).read_text(encoding="utf-8")


def _read_snapshot(path: str, kind: str, required_key: str) -> dict[str, Any]:
    """Load a saved snapshot and make sure it is the right one: a licence snapshot fed to the
    Sentinel review (or the other way round) must be an error, never an empty "nothing found"."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise UsageError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise UsageError(f"{path} is not a snapshot saved with --save-snapshot")
    found = data.get("kind")
    if found not in (None, kind):
        raise UsageError(f"{path} is a '{found}' snapshot; use it with: secopt {found} --snapshot {path}")
    if found is None and required_key not in data:
        raise UsageError(f"{path} is not a {kind} snapshot (it has no '{required_key}' section)")
    return data


def _day(captured: str) -> str:
    """The date for a report file name. The value comes from a snapshot file, so anything that is
    not a plain date is dropped rather than put into a path."""
    return captured[:10] if re.fullmatch(r"\d{4}-\d{2}-\d{2}", captured[:10]) else "undated"


def _analysed(run: Callable[[], Any], args: argparse.Namespace) -> Any:
    """Run an analysis. For a snapshot file, damage that the checks did not anticipate is reported
    as a problem with the file; for live data it stays a traceback, because that would be a bug."""
    snapshot = getattr(args, "snapshot", None)
    if not snapshot or args.demo:
        return run()
    try:
        return run()
    except (KeyError, TypeError, AttributeError, IndexError) as exc:
        raise UsageError(f"{snapshot} is not a valid snapshot ({type(exc).__name__}: {exc})") from exc


def _credential(http: HttpClient):
    from secopt.core.auth import AuthError, credential_from_env
    try:
        return credential_from_env(http)
    except AuthError as exc:
        raise UsageError(str(exc)) from exc


def _finish(args: argparse.Namespace, opportunities: list[Opportunity], currency: str, paths: list[Path]) -> int:
    if not args.quiet:
        saving = total_saving(opportunities)
        print(f"Opportunities: {len(opportunities)}"
              + (f", up to {money(saving, currency)} a month" if saving else ""))
        for o in opportunities[:12]:
            amount = money(o.monthly_saving, currency) if o.monthly_saving is not None else "-"
            print(f"  {amount:>10}{' ' if o.additive else '*'} {o.title}")
        if any(o.monthly_saving is not None and not o.additive for o in opportunities):
            print("  * overlaps with other items; not included in the total")
        if len(opportunities) > 12:
            print(f"  ... and {len(opportunities) - 12} more in the report")
    for path in paths:
        print(f"Report: {path}")
    return EXIT_OK


def _sentinel(args: argparse.Namespace, formats: list[str], log: Callable[[str], None]) -> int:
    from secopt.core.auth import AuthError
    from secopt.sentinel.analyze import SentinelConfig, analyze
    from secopt.sentinel.collect import AzureReader, collect

    if args.price_per_gb is not None and not is_number(args.price_per_gb, 1e-6, 1e6):
        raise UsageError("--price-per-gb must be a number greater than 0 (and below 1,000,000)")
    config = SentinelConfig(price_per_gb=args.price_per_gb)
    if args.demo:
        snapshot, source = json.loads(_demo("secopt.sentinel", "demo.json")), "built-in demo workspace (fictional data)"
    elif args.snapshot:
        snapshot, source = _read_snapshot(args.snapshot, "sentinel", "usage"), f"snapshot {args.snapshot}"
    else:
        workspace = args.workspace or env_str("SENTINEL_WORKSPACE_RESOURCE_ID")
        if not workspace:
            raise UsageError("pass --workspace <resource id> (or set SENTINEL_WORKSPACE_RESOURCE_ID), or try --demo")
        if not 7 <= args.days <= 90:
            raise UsageError("--days must be between 7 and 90")
        http = HttpClient(timeout=float(env_int("HTTP_TIMEOUT_SECONDS", 60)))
        reader = AzureReader(http, _credential(http), env_str("AZURE_ARM_BASE_URL", "https://management.azure.com"),
                             env_str("LOG_ANALYTICS_BASE_URL", "https://api.loganalytics.io"))
        if not args.quiet:
            print("Collecting from Azure (read-only)...", file=sys.stderr)
        try:
            currency = (args.currency or env_str("CURRENCY", "USD")).upper()
            snapshot = collect(reader, workspace, days=args.days, currency=currency, log=log)
        except AuthError as exc:
            raise UsageError(str(exc)) from exc
        except HttpError as exc:
            raise UsageError(f"could not read the workspace: {exc}. Assign Microsoft Sentinel Reader or "
                             "Log Analytics Reader on the workspace.") from exc
        source = "Azure Resource Manager, Log Analytics and the Azure Retail Prices API"
    if args.save_snapshot:
        write_text(Path(args.save_snapshot), to_json(snapshot))
    report = _analysed(lambda: analyze(snapshot, config), args)
    captured = str(snapshot.get("captured_at") or "")
    table_fields = ("table", "gb_per_day", "billable_gb", "share_pct", "monthly_cost", "plan", "retention_days",
                    "rules", "trend_pct", "free_gb", "tip")
    paths = write_reports(Path(args.out), f"sentinel-cost-{_day(captured)}", formats,
                          sentinel_markdown(report, source, captured),
                          {"report": "sentinel", "captured_at": captured, "source": source, "totals": report.totals,
                           "pricing_options": report.pricing_options, "tables": report.tables, "notes": report.notes},
                          report.opportunities, report.tables, table_fields, "tables")
    return _finish(args, report.opportunities, report.totals["currency"], paths)


def load_prices(path: str) -> tuple[dict[str, float], str]:
    """Read a price file: ``currency = "USD"`` and a ``[prices]`` table of part number -> monthly price."""
    try:
        data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise UsageError(f"cannot read {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise UsageError(f"{path}: {exc}") from exc
    prices = data.get("prices")
    if not isinstance(prices, dict) or not prices:
        raise UsageError(f"{path}: add a [prices] table, for example SPE_E5 = 57.00")
    unknown = set(data) - {"prices", "currency"}
    if unknown:
        raise UsageError(f"{path}: unknown key(s) {', '.join(sorted(unknown))}")
    for part, price in prices.items():
        if not is_number(price, 0, 1e6):
            raise UsageError(f"{path}: the price for {part} must be a number, 0 or more (and below 1,000,000)")
    currency = data.get("currency", "USD")
    if not is_currency(currency):
        raise UsageError(f"{path}: currency must be a three-letter code such as USD")
    return {part: float(price) for part, price in prices.items()}, currency.upper()


def _licenses(args: argparse.Namespace, formats: list[str], log: Callable[[str], None]) -> int:
    from secopt.core.auth import AuthError
    from secopt.licenses.analyze import LicenseConfig, analyze
    from secopt.licenses.collect import GraphReader, collect

    if args.inactive_days < 1:
        raise UsageError("--inactive-days must be at least 1")
    prices, currency = load_prices(args.prices) if args.prices else ({}, "USD")
    if args.demo:
        snapshot, source = json.loads(_demo("secopt.licenses", "demo.json")), "built-in demo tenant (fictional data)"
        if not args.prices:
            demo_prices = tomllib.loads(_demo("secopt.licenses", "demo_prices.toml"))
            prices, currency = dict(demo_prices["prices"]), demo_prices["currency"]
    elif args.snapshot:
        snapshot, source = _read_snapshot(args.snapshot, "licenses", "skus"), f"snapshot {args.snapshot}"
    else:
        http = HttpClient(timeout=float(env_int("HTTP_TIMEOUT_SECONDS", 60)))
        graph = GraphReader(http, _credential(http), env_str("GRAPH_BASE_URL", "https://graph.microsoft.com"))
        if not args.quiet:
            print("Collecting from Microsoft Graph (read-only)...", file=sys.stderr)
        try:
            snapshot = collect(graph, log)
        except AuthError as exc:
            raise UsageError(str(exc)) from exc
        except HttpError as exc:
            raise UsageError(f"could not read licences: {exc}. Grant Organization.Read.All.") from exc
        source = "Microsoft Graph"
    if args.save_snapshot:
        write_text(Path(args.save_snapshot), to_json(snapshot))
    config = LicenseConfig(prices=prices, currency=currency, inactive_days=args.inactive_days)
    report = _analysed(lambda: analyze(snapshot, config), args)
    captured = str(snapshot.get("captured_at") or "")
    product_fields = ("product", "part_number", "purchased", "assigned", "unassigned", "disabled", "inactive",
                      "duplicate", "price", "monthly_waste", "status")
    paths = write_reports(Path(args.out), f"license-review-{_day(captured)}", formats,
                          licenses_markdown(report, source, captured),
                          {"report": "licenses", "captured_at": captured, "source": source, "totals": report.totals,
                           "products": report.products, "notes": report.notes},
                          report.opportunities, report.products, product_fields, "products")
    return _finish(args, report.opportunities, currency, paths)


def _overlap(args: argparse.Namespace, formats: list[str]) -> int:
    from secopt.overlap.analyze import InventoryError, analyze, load_inventory, parse_inventory
    from secopt.overlap.capabilities import CAPABILITIES

    if args.list_capabilities:
        for c in CAPABILITIES.values():
            print(f"{c.id:<28} {c.domain:<22} {c.name}" + ("  [baseline]" if c.baseline else ""))
        return EXIT_OK
    try:
        if args.demo:
            inventory = parse_inventory(tomllib.loads(_demo("secopt.overlap", "demo_stack.toml")), "demo inventory")
            source = "built-in demo inventory (fictional company)"
        elif args.inventory:
            inventory, source = load_inventory(Path(args.inventory)), args.inventory
        else:
            raise UsageError("pass an inventory file (see examples/security-stack.toml), or try --demo")
    except InventoryError as exc:
        raise UsageError(str(exc)) from exc
    report = analyze(inventory)
    paths = write_reports(Path(args.out), "tool-overlap", formats, overlap_markdown(report, source),
                          {"report": "overlap", "source": source, "totals": report.totals, "tools": report.tools,
                           "matrix": report.matrix, "notes": report.notes},
                          report.opportunities, report.matrix, ("domain", "name", "capability", "status", "required", "tools"),
                          "matrix")
    return _finish(args, report.opportunities, inventory.currency, paths)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        load_dotenv(args.env_file)
        formats = parse_formats(args.format, ("md", "csv", "json"))
        log = (lambda _m: None) if args.quiet else (lambda m: print(f"  {m}", file=sys.stderr))
        if args.command == "sentinel":
            code = _sentinel(args, formats, log)
        elif args.command == "licenses":
            code = _licenses(args, formats, log)
        else:
            code = _overlap(args, formats)
        sys.stdout.flush()  # here, so a closed pipe or a full disk is handled below, not at exit
        return code
    except BrokenPipeError:  # output piped into something that stopped reading, such as head
        _discard_stdout()
        return EXIT_OK
    except (UsageError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except OverflowError:
        print("error: a number in the input is too large to work with", file=sys.stderr)
        return EXIT_ERROR
    except OSError as exc:  # cannot create the report folder, write a report, save a snapshot...
        print(f"error: {exc.strerror or exc}" + (f": {exc.filename}" if exc.filename else ""), file=sys.stderr)
        try:
            sys.stdout.flush()
        except OSError:  # it was standard output itself that could not be written
            _discard_stdout()
        return EXIT_ERROR


def _discard_stdout() -> None:
    """Point standard output at nothing, so text still buffered for a closed or full destination
    does not raise again when Python flushes it on exit."""
    try:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    except (OSError, ValueError):
        pass
