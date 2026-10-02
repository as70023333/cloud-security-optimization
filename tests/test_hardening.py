"""Regression tests for defects found in review: each one failed before the fix."""

import contextlib
import http.server
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from secopt import cli
from secopt.core.env import load_dotenv
from secopt.core import http as http_module
from secopt.core.http import HttpClient, HttpError, Response, same_origin
from secopt.core.output import md_escape, md_inline
from secopt.licenses.analyze import LicenseConfig, analyze as analyze_licenses
from secopt.overlap.analyze import InventoryError, analyze as analyze_overlap, parse_inventory
from secopt.report import sentinel_markdown
from secopt.sentinel.analyze import analyze as analyze_sentinel
from secopt.licenses.collect import GraphReader, collect as collect_licenses
from secopt.sentinel.collect import AzureReader, collect as collect_sentinel, fetch_prices, usage_query
from tests.fakes import FakeTransport, StaticCredential, json_response
from tests.test_licenses_overlap import PRICES, license_demo, sku, tenant, user
from tests.test_sentinel import REAL_ITEMS, WORKSPACE, demo, flat, snapshot

REPO = Path(__file__).resolve().parent.parent

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
        self.assertIn("StartTime >= startofday(ago(30d)) and StartTime < startofday(now())", query)
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


class SecondPassTests(unittest.TestCase):
    """Defects found when the first round of fixes was reviewed."""

    def test_proxy_settings_that_arrive_after_import_are_used(self):
        seen: list[str] = []

        class Proxy(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                seen.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"via": "proxy"}')

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Proxy)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(setattr, http_module, "_opener", None)
        try:
            http_module._opener = None
            proxy = f"http://127.0.0.1:{server.server_port}"
            # as load_dotenv would do, after secopt.core.http has been imported
            with mock.patch.dict(os.environ, {"http_proxy": proxy, "HTTP_PROXY": proxy, "no_proxy": "", "NO_PROXY": ""}):
                data = HttpClient(retries=0, timeout=5).request("GET", "http://service.invalid/v1/thing").json()
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(data, {"via": "proxy"})
        self.assertEqual(seen, ["http://service.invalid/v1/thing"])

    def test_same_origin(self):
        base = "https://management.azure.com"
        self.assertTrue(same_origin("https://management.azure.com/x?y=1", base))
        self.assertTrue(same_origin("https://MANAGEMENT.azure.com:443/x", base))
        for other in ("http://management.azure.com/x", "https://management.azure.com:8443/x",
                      "https://management.azure.com.evil.example/x", "https://evil.example/management.azure.com",
                      "//management.azure.com/x", "management.azure.com/x", "https://[bad", ""):
            self.assertFalse(same_origin(other, base), other)

    def test_token_is_not_sent_to_a_plain_http_or_foreign_paging_link(self):
        for link, followed in (("https://graph.microsoft.com:443/v1.0/subscribedSkus?page=2", True),
                               ("http://graph.microsoft.com/v1.0/subscribedSkus?page=2", False),
                               ("https://graph.microsoft.com.evil.example/v1.0/subscribedSkus?page=2", False)):
            fake = FakeTransport()
            fake.add("GET", r"page=2", json_response({"value": []}))
            fake.add("GET", r"/v1.0/subscribedSkus", json_response({"value": [], "@odata.nextLink": link}))
            graph = GraphReader(fake.client(), StaticCredential())
            with self.subTest(link=link):
                if followed:
                    self.assertEqual(graph.get_all("/v1.0/subscribedSkus"), [])
                    self.assertEqual(len(fake.calls), 2)
                else:
                    with self.assertRaises(HttpError):
                        graph.get_all("/v1.0/subscribedSkus")
                    self.assertEqual(len(fake.calls), 1)
        fake = FakeTransport().add("GET", r"/tables", json_response(
            {"value": [], "nextLink": "http://management.azure.com/next"}))
        with self.assertRaises(HttpError):
            AzureReader(fake.client(), StaticCredential()).arm_list(f"{WORKSPACE}/tables", "2022-10-01")
        self.assertEqual(len(fake.calls), 1)

    def test_a_malformed_address_fails_at_once_and_keeps_the_query_string_out_of_the_message(self):
        sleeps: list[float] = []
        with self.assertRaises(HttpError) as ctx:
            HttpClient(sleep=sleeps.append).request("GET", "graph.microsoft.us/v1.0/users", params={"key": "SECRET"})
        self.assertEqual(sleeps, [])
        self.assertNotIn("SECRET", str(ctx.exception))
        self.assertIn("not a valid URL", str(ctx.exception))

    def test_text_at_the_start_of_a_line_cannot_open_a_block(self):
        for hostile in ("# Pwned", "## x", "```", "~~~", "> quote", "- item", "+ item", "* item", "1. item", "2) item",
                        "=====", "---"):
            self.assertTrue(md_inline(hostile).startswith(("\\", "1\\", "2\\")), hostile)
        self.assertEqual(md_inline("10.7 GB/day of billable data"), "10.7 GB/day of billable data")
        self.assertEqual(md_inline("Acme `EDR`"), "Acme \\`EDR\\`")
        report = analyze_overlap(parse_inventory({"tool": [
            {"name": "```", "capabilities": ["edr"], "bundled_with": "Suite"},
            {"name": "# Pwned", "annual_cost": 100, "capabilities": ["edr"]}]}, "test"))
        from secopt.report import overlap_markdown
        markdown = overlap_markdown(report, "test")
        self.assertFalse([line for line in markdown.splitlines() if line.startswith(("```", "# Pwned"))])

    def test_currency_must_be_a_three_letter_code(self):
        snap = snapshot(flat("Syslog", 1.0))
        snap["prices"]["currency"] = "<img src=x onerror=alert(1)>"
        with self.assertRaises(ValueError):
            analyze_sentinel(snap)
        with self.assertRaises(ValueError):
            LicenseConfig(prices={}, currency="USD**")
        with self.assertRaises(InventoryError):
            parse_inventory({"currency": "U$D", "tool": [{"name": "x", "capabilities": ["edr"]}]}, "test")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "p.toml"
            path.write_text('currency = "[x](https://evil.example)"\n[prices]\nSPE_E5 = 1\n', encoding="utf-8")
            code, _, err = run("licenses", "--demo", "--prices", str(path), "--out", tmp, *ENV)
            self.assertEqual(code, 2)
            self.assertIn("three-letter code", err)

    def test_a_suite_priced_at_zero_still_makes_its_add_ons_duplicates(self):
        baseline = analyze_licenses(license_demo(), LicenseConfig(prices=PRICES))
        report = analyze_licenses(license_demo(), LicenseConfig(prices={**PRICES, "SPE_E5": 0}))
        self.assertGreater(baseline.totals["duplicates"], 0)
        self.assertEqual(report.totals["duplicates"], baseline.totals["duplicates"])

    def test_table_savings_never_exceed_the_pay_as_you_go_price(self):
        # A 100 GB/day tier with about 27 GB/day: the average price per GB is far above pay-as-you-go.
        usage = flat("SecurityEvent", 20.0, days=30) + flat("Foo_CL", 5.0, days=23) + flat("Foo_CL", 15.0, days=7, start=24)
        report = analyze_sentinel(snapshot(usage, sku="CapacityReservation", level=100, rules=[],
                                           tables=[table("SecurityEvent"), table("Foo_CL")]))
        self.assertGreater(report.totals["effective_price_per_gb"], 4.0)
        by_id = {o.id: o for o in report.opportunities}
        grew = 15.0 - 5.0
        self.assertAlmostEqual(by_id["spike:Foo_CL"].monthly_saving, grew * 30 * 4.0, places=2)
        foo = next(t for t in report.tables if t["table"] == "Foo_CL")
        self.assertAlmostEqual(by_id["unread-table:Foo_CL"].monthly_saving, foo["gb_per_day"] * 30 * (4.0 - 1.0), places=1)

    def test_absurd_numbers_are_an_error_not_a_traceback_or_nan(self):
        huge = 10 ** 400
        edits = {
            "sentinel": [lambda s: s["usage"][0].update(billable_gb=huge),
                         lambda s: s["prices"].update(commitment_tiers={"100": huge}),
                         lambda s: s["workspace"].update(sku="CapacityReservation", capacity_reservation_gb=float("inf"))],
            "licenses": [lambda s: s["skus"][0].update(purchased=huge)],
        }
        for command, changes in edits.items():
            for n, change in enumerate(changes):
                with self.subTest(command=command, edit=n), tempfile.TemporaryDirectory() as tmp:
                    base = demo() if command == "sentinel" else license_demo()
                    change(base)
                    path = Path(tmp) / "snap.json"
                    path.write_text(json.dumps(base), encoding="utf-8")
                    code, _, err = run(command, "--snapshot", str(path), "--out", str(Path(tmp) / "o"), "--quiet", *ENV)
                    self.assertIn(code, (0, 2), err)
                    self.assertNotIn("Traceback", err)
                    for report in (Path(tmp) / "o").glob("*.json"):
                        json.loads(report.read_text(encoding="utf-8"), parse_constant=self.fail)
        with tempfile.TemporaryDirectory() as tmp:
            for argv in (("sentinel", "--demo", "--price-per-gb", "1e308"),
                         ("sentinel", "--demo", "--price-per-gb", "1e-9")):
                code, _, err = run(*argv, "--out", tmp, *ENV)
                self.assertEqual(code, 2)
            stack = Path(tmp) / "stack.toml"
            stack.write_text(f'[[tool]]\nname = "x"\nannual_cost = {huge}\ncapabilities = ["edr"]\n', encoding="utf-8")
            self.assertEqual(run("overlap", str(stack), "--out", tmp, *ENV)[0], 2)
            prices = Path(tmp) / "p.toml"
            prices.write_text(f"[prices]\nSPE_E5 = {huge}\n", encoding="utf-8")
            self.assertEqual(run("licenses", "--demo", "--prices", str(prices), "--out", tmp, *ENV)[0], 2)

    def test_licence_snapshot_cannot_count_anything_twice(self):
        e3 = sku("a", "SPE_E3", 10, 2, ["p1"])
        clean = analyze_licenses(tenant([e3], [user("u1@x", ["a"], enabled=False), user("u2@x", ["a"])]),
                                 LicenseConfig(prices={"SPE_E3": 10}))
        repeated = analyze_licenses(tenant([e3], [user("u1@x", ["a", "a"], enabled=False), user("u2@x", ["a"])]),
                                    LicenseConfig(prices={"SPE_E3": 10}))
        self.assertEqual(repeated.totals, clean.totals)
        self.assertEqual(clean.totals["on_disabled_accounts"], 1)
        missing_enabled = user("u3@x", ["a"])
        del missing_enabled["enabled"]
        for bad in (tenant([e3, dict(e3)], []), tenant([e3], [user("u1@x", ["a"]), user("u1@x", ["a"])]),
                    tenant([e3], [missing_enabled])):
            with self.assertRaises(ValueError):
                analyze_licenses(bad, LicenseConfig())

    def test_collectors_do_not_produce_rows_the_analysis_rejects(self):
        fake = FakeTransport()
        fake.add("GET", r"/v1.0/subscribedSkus", json_response({"value": [
            {"skuId": "a", "skuPartNumber": "SPE_E3", "appliesTo": "User", "consumedUnits": 2,
             "prepaidUnits": {"enabled": 5}, "servicePlans": []}]}))
        fake.add("GET", r"/v1.0/users", json_response({"value": [
            {"id": "id-1", "userPrincipalName": None, "accountEnabled": True, "createdDateTime": "2024-01-01T00:00:00Z",
             "assignedLicenses": [{"skuId": "a"}, {"skuId": "a"}]},
            {"id": "id-2", "userPrincipalName": None, "accountEnabled": None, "assignedLicenses": [{"skuId": "a"}]}]}))
        snap = collect_licenses(GraphReader(fake.client(), StaticCredential()))
        self.assertEqual([(u["upn"], u["sku_ids"], u["enabled"]) for u in snap["users"]],
                         [("id-1", ["a"], True), ("id-2", ["a"], False)])
        analyze_licenses(snap, LicenseConfig())

        azure = FakeTransport()
        azure.add("GET", r"workspaces/soc-ws\?", json_response(
            {"name": "soc-ws", "location": "eastus", "properties": {"customerId": "cid", "sku": {"name": "PerGB2018"}}}))
        azure.add("GET", r"/tables", json_response({"value": []}))
        azure.add("GET", r"alertRules", json_response({"value": []}))
        azure.add("POST", r"/v1/workspaces/cid/query", json_response({"tables": [{
            "columns": [{"name": "Day"}, {"name": "DataType"}, {"name": "BillableMB"}, {"name": "TotalMB"}],
            "rows": [["2026-09-01T00:00:00Z", "Syslog", 2000.0, 2000.0], ["2026-09-01T00:00:00Z", "", 5.0, 5.0],
                     ["2026-09-01T00:00:00Z", None, 5.0, 5.0], [None, "Syslog", 1.0, 1.0],
                     ["2026-09-02T00:00:00Z", "Syslog", -3.0, None]]}]}))
        azure.add("GET", r"prices\.azure\.com", json_response({"Items": REAL_ITEMS, "NextPageLink": None}))
        snap = collect_sentinel(AzureReader(azure.client(), StaticCredential()), WORKSPACE)
        self.assertEqual([(r["date"], r["table"], r["billable_gb"]) for r in snap["usage"]],
                         [("2026-09-01", "Syslog", 2.0), ("2026-09-02", "Syslog", 0.0)])
        analyze_sentinel(snap)

    def test_dotenv_value_that_is_only_a_comment_is_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text("A=   # only a comment\nB=#x\nC=a#b\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {}, clear=True):
                load_dotenv(path)
                self.assertEqual([os.environ[k] for k in "ABC"], ["", "", "a#b"])


class PipeTests(unittest.TestCase):
    """Run as a real process: output is flushed when the interpreter exits, which a test in the
    same process cannot see."""

    def child(self, stdout) -> subprocess.Popen:
        env = {k: v for k, v in os.environ.items() if k != "PYTHONUNBUFFERED"}
        return subprocess.Popen([sys.executable, "-m", "secopt", "overlap", "--list-capabilities"], cwd=REPO, env=env,
                                stdout=stdout, stderr=subprocess.PIPE)

    def test_a_reader_that_stops_early_is_not_an_error(self):
        process = self.child(subprocess.PIPE)
        process.stdout.close()  # like "secopt ... | head -0": nobody reads
        _, err = process.communicate(timeout=60)
        self.assertEqual(process.returncode, 0, err)
        self.assertNotIn(b"Exception ignored", err)
        self.assertNotIn(b"Traceback", err)

    @unittest.skipUnless(os.path.exists("/dev/full"), "needs /dev/full")
    def test_output_that_cannot_be_written_exits_2(self):
        with open("/dev/full", "w") as full:
            process = self.child(full)
            _, err = process.communicate(timeout=60)
        self.assertEqual(process.returncode, 2, err)
        self.assertTrue(err.startswith(b"error: "), err)


if __name__ == "__main__":
    unittest.main()
