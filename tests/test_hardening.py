"""Regression tests for defects found in review: each one failed before the fix."""

import contextlib
import http.server
import io
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from secopt import cli
from secopt.core.env import load_dotenv
from secopt.core.http import HttpClient, HttpError, Response
from secopt.core.output import md_escape, md_inline
from secopt.licenses.analyze import LicenseConfig, analyze as analyze_licenses
from secopt.overlap.analyze import InventoryError, analyze as analyze_overlap, parse_inventory
from secopt.report import sentinel_markdown
from secopt.sentinel.analyze import analyze as analyze_sentinel
from secopt.sentinel.collect import fetch_prices, usage_query
from tests.fakes import FakeTransport, json_response
from tests.test_licenses_overlap import PRICES, license_demo, sku, tenant, user
from tests.test_sentinel import REAL_ITEMS, demo, flat, snapshot

ENV = ("--env-file", "/nonexistent")


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main([*argv])
        except SystemExit as exc:
            code = int(exc.code or 0)
    return code, out.getvalue(), err.getvalue()


def table(name: str, plan: str = "Analytics", retention: int = 90) -> dict:
    return {"name": name, "plan": plan, "retention_days": retention, "total_retention_days": retention}


class TablePlanTests(unittest.TestCase):
    """Only Analytics-plan data is billed at the Sentinel price and counts toward a commitment tier."""

    def test_basic_plan_data_is_not_counted_toward_a_commitment_tier(self):
        usage = flat("SecurityEvent", 20.0, days=30) + flat("ContainerLogV2", 100.0, days=30)
        report = analyze_sentinel(snapshot(usage, tables=[table("SecurityEvent"), table("ContainerLogV2", "Basic")],
                                           rules=[]))
        # 20 GB/day at 4.00 plus 100 GB/day at the Basic price of 1.00
        self.assertEqual(report.totals["gb_per_day"], 20.0)
        self.assertEqual(report.totals["basic_gb_per_day"], 100.0)
        self.assertEqual(report.totals["monthly_cost"], 20 * 30 * 4.0 + 100 * 30 * 1.0)
        self.assertNotIn("pricing-tier", [o.id for o in report.opportunities])  # a tier would cost more
        costs = {t["table"]: t["monthly_cost"] for t in report.tables}
        self.assertEqual(costs, {"ContainerLogV2": 3000.0, "SecurityEvent": 2400.0})
        # a Basic table is not offered a move to the Basic plan
        self.assertNotIn("unread-table:ContainerLogV2", [o.id for o in report.opportunities])
        markdown = sentinel_markdown(report, "test", "2026-10-01T00:00:00Z")
        self.assertIn("| Billable ingestion, Basic plan | 100.0 GB/day |", markdown)

    def test_unpriced_plans_are_shown_by_volume_with_a_note(self):
        usage = flat("SecurityEvent", 20.0, days=30) + flat("Custom_CL", 50.0, days=30)
        report = analyze_sentinel(snapshot(usage, tables=[table("SecurityEvent"), table("Custom_CL", "Auxiliary")]))
        self.assertEqual(report.totals["monthly_cost"], 2400.0)
        self.assertEqual(report.totals["other_plan_gb_per_day"], 50.0)
        self.assertIsNone({t["table"]: t["monthly_cost"] for t in report.tables}["Custom_CL"])
        self.assertTrue(any("does not price" in n for n in report.notes))

    def test_tables_without_plan_information_are_treated_as_analytics(self):
        report = analyze_sentinel(snapshot(flat("Syslog", 150.0, days=30), tables=None))
        self.assertEqual(report.totals["gb_per_day"], 150.0)
        self.assertIn("pricing-tier", [o.id for o in report.opportunities])


class SpikeTests(unittest.TestCase):
    def test_new_table_is_caught_even_though_its_period_average_is_small(self):
        usage = flat("Syslog", 5.0, days=30) + flat("NewSource_CL", 2.0, days=5, start=26)
        report = analyze_sentinel(snapshot(usage))
        spike = [o for o in report.opportunities if o.id == "spike:NewSource_CL"]
        self.assertEqual(len(spike), 1)
        self.assertIn("new table", spike[0].detail)

    def test_small_table_that_grew_a_lot_is_caught(self):
        usage = flat("Syslog", 0.1, days=23) + flat("Syslog", 1.5, days=7, start=24)
        report = analyze_sentinel(snapshot(usage))
        self.assertIn("spike:Syslog", [o.id for o in report.opportunities])

    def test_short_history_says_that_growth_was_not_measured(self):
        usage = flat("Syslog", 1.0, days=6) + flat("Syslog", 9.0, days=7, start=7)
        report = analyze_sentinel(snapshot(usage))
        self.assertEqual([o.id for o in report.opportunities if o.id.startswith("spike")], [])
        self.assertTrue(any(n.startswith("trend: only 13 day(s)") for n in report.notes))

    def test_usage_query_groups_on_the_hour_the_data_belongs_to(self):
        query = usage_query(30)
        self.assertIn("StartTime >= startofday(ago(30d)) and EndTime < startofday(now())", query)
        self.assertIn("Day = bin(StartTime, 1d)", query)


class TransportTests(unittest.TestCase):
    def test_redirects_are_not_followed_so_a_token_never_reaches_another_host(self):
        seen: list[tuple[str, str | None]] = []

        class Target(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                seen.append((self.path, self.headers.get("Authorization")))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *args):
                pass

        target = http.server.HTTPServer(("127.0.0.1", 0), Target)

        class Redirector(Target):
            def do_GET(self):  # noqa: N802
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{target.server_port}/stolen")
                self.end_headers()

        redirector = http.server.HTTPServer(("127.0.0.1", 0), Redirector)
        threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (target, redirector)]
        for thread in threads:
            thread.start()
        try:
            with mock.patch.dict(os.environ, {"NO_PROXY": "*", "no_proxy": "*"}):
                with self.assertRaises(HttpError) as ctx:
                    HttpClient(retries=0, timeout=5).request(
                        "GET", f"http://127.0.0.1:{redirector.server_port}/v1.0/users",
                        headers={"Authorization": "Bearer SECRET-TOKEN"})
        finally:
            for server in (target, redirector):
                server.shutdown()
                server.server_close()
        self.assertEqual(ctx.exception.status, 302)
        self.assertIn("redirect", str(ctx.exception))
        self.assertEqual(seen, [])

    def test_a_redirect_response_is_an_error_not_a_retry(self):
        fake = FakeTransport().add("GET", "example.test", Response(307, b"", {"Location": "https://evil.example/"}))
        with self.assertRaises(HttpError):
            fake.client().request("GET", "https://example.test/x")
        self.assertEqual(len(fake.calls), 1)

    def test_price_paging_follows_microsofts_link_with_a_port_and_nothing_else(self):
        fake = FakeTransport()
        fake.add("GET", r"\$skip=100", json_response({"Items": REAL_ITEMS[1:], "NextPageLink": None}))
        fake.add("GET", r"prices\.azure\.com/api", json_response(
            {"Items": REAL_ITEMS[:1], "NextPageLink": "https://prices.azure.com:443/api/retail/prices?$filter=x eq 'y'&$skip=100"}))
        prices = fetch_prices(fake.client(), "eastus")
        self.assertEqual((prices["payg_per_gb"], prices["basic_per_gb"]), (4.3, 1.0))
        self.assertNotIn(" ", fake.calls[-1].url)
        for link in ("http://prices.azure.com/api/retail/prices?$skip=100", "https://prices.azure.com.evil.example/x",
                     "https://evil.example/prices.azure.com"):
            bad = FakeTransport().add("GET", r"prices\.azure\.com/api", json_response({"Items": [], "NextPageLink": link}))
            with self.subTest(link=link), self.assertRaises(HttpError):
                fetch_prices(bad.client(), "eastus")
            self.assertEqual(len(bad.calls), 1)


class SnapshotRobustnessTests(unittest.TestCase):
    """A snapshot can be edited by hand or sent by someone else. Damage is an error, never a traceback."""

    def edit(self, tmp: str, command: str, change) -> tuple[int, str, str]:
        base = demo() if command == "sentinel" else license_demo()
        base.setdefault("kind", command)
        change(base)
        path = Path(tmp) / "snap.json"
        path.write_text(json.dumps(base), encoding="utf-8")
        return run(command, "--snapshot", str(path), "--out", str(Path(tmp) / "out"), "--quiet", *ENV)

    def test_damaged_snapshots_are_reported_cleanly(self):
        edits = {
            "sentinel": [
                lambda s: s["usage"][0].pop("billable_gb"),
                lambda s: s["usage"][0].update(billable_gb=None),
                lambda s: s["usage"][0].update(billable_gb="12"),
                lambda s: s["usage"][0].update(date=None),
                lambda s: s["usage"].append("not a row"),
                lambda s: s.update(usage={"a": 1}),
                lambda s: s.update(rules="none"),
            ],
            "licenses": [
                lambda s: s["users"][0].pop("upn"),
                lambda s: s["users"][0].update(sku_ids=None),
                lambda s: s["skus"][0].pop("purchased"),
                lambda s: s["skus"][0].pop("part_number"),
                lambda s: s["skus"][0].update(purchased="120"),
                lambda s: s.update(skus="none"),
                lambda s: s.update(users=[1, 2]),
                lambda s: s.update(captured_at="yesterday"),
            ],
        }
        for command, changes in edits.items():
            for n, change in enumerate(changes):
                with self.subTest(command=command, edit=n), tempfile.TemporaryDirectory() as tmp:
                    code, _, err = self.edit(tmp, command, change)
                    self.assertEqual(code, 2, err)
                    self.assertTrue(err.startswith("error: "), err)
                    self.assertNotIn("Traceback", err)

    def test_tolerated_oddities_still_give_a_report(self):
        for change in (lambda s: s["tables"].append({"plan": "Analytics"}),      # a table entry with no name
                       lambda s: s["prices"].update(payg_per_gb="4.30"),          # price as text: volumes only
                       lambda s: s.update(tables=None, rules=None, prices=None)):
            with self.subTest(), tempfile.TemporaryDirectory() as tmp:
                self.assertEqual(self.edit(tmp, "sentinel", change)[0], 0)

    def test_report_file_name_cannot_leave_the_output_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "a" / "b" / "reports"
            snap = demo()
            snap["captured_at"] = "/../../../x"
            path = Path(tmp) / "snap.json"
            path.write_text(json.dumps(snap), encoding="utf-8")
            code, stdout, _ = run("sentinel", "--snapshot", str(path), "--out", str(out), "--quiet", *ENV)
            self.assertEqual(code, 0)
            written = sorted(p.relative_to(tmp).as_posix() for p in Path(tmp).rglob("*") if p.is_file())
            self.assertEqual(written, ["a/b/reports/sentinel-cost-undated-opportunities.csv",
                                       "a/b/reports/sentinel-cost-undated-tables.csv",
                                       "a/b/reports/sentinel-cost-undated.json", "a/b/reports/sentinel-cost-undated.md",
                                       "snap.json"])

    def test_filesystem_problems_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            blocker = Path(tmp) / "file"
            blocker.write_text("x", encoding="utf-8")
            for argv in (("overlap", "--demo", "--out", str(blocker)),
                         ("sentinel", "--demo", "--out", str(blocker / "reports")),
                         ("sentinel", "--demo", "--out", str(Path(tmp) / "ok"), "--save-snapshot", tmp),
                         ("licenses", "--demo", "--out", str(Path(tmp) / "ok"), "--save-snapshot", str(blocker / "s.json"))):
                with self.subTest(argv=argv):
                    code, _, err = run(*argv, "--quiet", *ENV)
                    self.assertEqual(code, 2)
                    self.assertTrue(err.startswith("error: "), err)

    def test_days_only_matters_when_collecting(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(run("sentinel", "--demo", "--days", "5", "--out", tmp, "--quiet", *ENV)[0], 0)


class MarkdownTests(unittest.TestCase):
    def test_links_images_and_html_in_names_are_neutralised(self):
        hostile = "[click](javascript:alert(1)) ![p](https://evil.example/p.png) <img src=x onerror=alert(1)>"
        for rendered in (md_inline(hostile), md_escape(hostile)):
            self.assertNotIn("[click](", rendered)
            self.assertNotIn("![p](", rendered)
            self.assertNotIn("<img", rendered)
            self.assertIn("\\[click\\]", rendered)

    def test_dates_in_a_snapshot_cannot_carry_markup(self):
        usage = flat("Syslog", 1.0)
        usage[-1]["date"] = "<img src=x onerror=alert(1)>"
        with self.assertRaises(ValueError):
            analyze_sentinel(snapshot(usage))


class LicenceTests(unittest.TestCase):
    def test_a_product_priced_at_zero_is_treated_as_free_everywhere(self):
        prices = {**PRICES, "SPE_E5": 0}
        report = analyze_licenses(license_demo(), LicenseConfig(prices=prices))
        baseline = analyze_licenses(license_demo(), LicenseConfig(prices=PRICES))
        e5 = next(p for p in report.products if p["part_number"] == "SPE_E5")
        self.assertTrue(e5["free"])
        self.assertEqual(report.totals["paid_products"], baseline.totals["paid_products"] - 1)
        self.assertEqual(report.totals["unassigned"], baseline.totals["unassigned"] - e5["unassigned"])
        self.assertEqual([o for o in report.opportunities if o.id.endswith(":SPE_E5")], [])

    def test_a_misspelled_part_number_in_the_price_file_is_pointed_out(self):
        report = analyze_licenses(license_demo(), LicenseConfig(prices={"SPE-E5": 57.0}))
        self.assertIsNone(report.totals["monthly_waste"])
        self.assertTrue(any("SPE-E5" in n and "check the spelling" in n for n in report.notes))
        clean = analyze_licenses(license_demo(), LicenseConfig(prices=PRICES))
        self.assertFalse(any("check the spelling" in n for n in clean.notes))

    def test_prices_must_be_finite(self):
        for bad in (float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                LicenseConfig(prices={"SPE_E5": bad})
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "p.toml"
            path.write_text("[prices]\nSPE_E5 = inf\n", encoding="utf-8")
            code, _, err = run("licenses", "--demo", "--prices", str(path), "--out", tmp, *ENV)
            self.assertEqual(code, 2)
            self.assertIn("must be a number", err)

    def test_users_holding_products_missing_from_the_list_are_ignored(self):
        report = analyze_licenses(tenant([sku("a", "SPE_E3", 2, 1, ["p1"])], [user("u@x", ["a", "gone"])]),
                                  LicenseConfig(prices={"SPE_E3": 10}))
        self.assertEqual(report.totals["unassigned"], 1)


class OverlapTests(unittest.TestCase):
    def test_names_that_differ_only_in_spacing_are_the_same_tool(self):
        for other in ("Acme EDR ", " acme  edr"):
            with self.subTest(other=other), self.assertRaises(InventoryError) as ctx:
                parse_inventory({"tool": [{"name": "Acme EDR", "annual_cost": 1000, "capabilities": ["edr"]},
                                          {"name": other, "annual_cost": 2000, "capabilities": ["edr"]}]}, "test")
            self.assertIn("listed twice", str(ctx.exception))

    def test_costs_must_be_finite(self):
        for bad in (float("inf"), float("nan")):
            with self.assertRaises(InventoryError):
                parse_inventory({"tool": [{"name": "x", "annual_cost": bad, "capabilities": ["edr"]}]}, "test")

    def test_reports_are_valid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            for command in ("sentinel", "licenses", "overlap"):
                run(command, "--demo", "--out", tmp, "--quiet", "--format", "json", *ENV)
            for path in Path(tmp).glob("*.json"):
                json.loads(path.read_text(encoding="utf-8"), parse_constant=lambda c: self.fail(f"{c} in {path.name}"))
        report = analyze_overlap(parse_inventory({"tool": [{"name": "x", "capabilities": ["edr"]}]}, "test"))
        self.assertEqual(report.totals["redundant_annual_spend"], 0)


class DotenvTests(unittest.TestCase):
    def test_quoted_value_followed_by_a_comment(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text('A="abc123"   # prod app\nB=\'x # y\'\nC=plain # note\nD=""\nE="p#ss"\n', encoding="utf-8")
            with mock.patch.dict(os.environ, {}, clear=True):
                load_dotenv(path)
                self.assertEqual([os.environ[k] for k in "ABCDE"], ["abc123", "x # y", "plain", "", "p#ss"])


if __name__ == "__main__":
    unittest.main()
