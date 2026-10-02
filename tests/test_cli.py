import contextlib
import csv
import io
import json
import os
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

from secopt import __version__, cli
from secopt.core.http import HttpError

REPO = Path(__file__).resolve().parent.parent
ENV = ("--env-file", "/nonexistent")


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main([*argv])
        except SystemExit as exc:  # argparse errors and --version
            code = int(exc.code or 0)
    return code, out.getvalue(), err.getvalue()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


class DemoTests(unittest.TestCase):
    def test_sentinel_demo_writes_every_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = run("sentinel", "--demo", "--out", tmp, *ENV)
            self.assertEqual(code, 0)
            stem = "sentinel-cost-2026-10-01"
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()),
                             [f"{stem}-opportunities.csv", f"{stem}-tables.csv", f"{stem}.json", f"{stem}.md"])
            self.assertIn("Switch to 100 GB/day commitment tier", out)
            self.assertIn("not included in the total", out)
            payload = json.loads((Path(tmp) / f"{stem}.json").read_text(encoding="utf-8"))
            self.assertEqual((payload["report"], payload["version"]), ("sentinel", __version__))
            additive = sum(o["monthly_saving"] for o in payload["opportunities"] if o["additive"] and o["monthly_saving"])
            self.assertAlmostEqual(payload["estimated_monthly_saving"], additive, places=2)
            self.assertLess(payload["estimated_monthly_saving"], payload["totals"]["monthly_cost"])
            markdown = (Path(tmp) / f"{stem}.md").read_text(encoding="utf-8")
            for heading in ("## Summary", "## Opportunities", "## Pricing plans compared", "## Tables"):
                self.assertIn(heading, markdown)
            self.assertIn("Read-only: nothing was changed.", markdown)
            self.assertIn("should not be added up", markdown)
            tables = read_csv(Path(tmp) / f"{stem}-tables.csv")
            self.assertEqual(tables[0]["table"], "SecurityEvent")
            self.assertGreater(float(tables[0]["monthly_cost"]), 1000)  # a number, not a quoted string

    def test_licenses_demo_writes_every_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = run("licenses", "--demo", "--out", tmp, *ENV)
            self.assertEqual(code, 0)
            stem = "license-review-2026-10-01"
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()),
                             [f"{stem}-opportunities.csv", f"{stem}-products.csv", f"{stem}.json", f"{stem}.md"])
            self.assertIn("Opportunities: 10", out)
            payload = json.loads((Path(tmp) / f"{stem}.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["estimated_monthly_saving"], payload["totals"]["monthly_waste"])
            products = {p["part_number"]: p for p in read_csv(Path(tmp) / f"{stem}-products.csv")}
            self.assertEqual(products["SPE_E5"]["unassigned"], "16")
            # every licence is counted once: the four kinds of waste never exceed what was bought
            for row in products.values():
                wasted = sum(int(row[k]) for k in ("unassigned", "disabled", "inactive", "duplicate"))
                self.assertLessEqual(wasted, int(row["purchased"]))

    def test_overlap_demo_writes_every_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = run("overlap", "--demo", "--out", tmp, *ENV)
            self.assertEqual(code, 0)
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()),
                             ["tool-overlap-matrix.csv", "tool-overlap-opportunities.csv", "tool-overlap.json",
                              "tool-overlap.md"])
            self.assertIn("Acme EDR is fully covered by other tools", out)
            markdown = (Path(tmp) / "tool-overlap.md").read_text(encoding="utf-8")
            self.assertIn("## Capability matrix", markdown)
            self.assertIn("**Gap**", markdown)
            statuses = {r["capability"]: r["status"] for r in read_csv(Path(tmp) / "tool-overlap-matrix.csv")}
            self.assertEqual((statuses["edr"], statuses["pam"]), ("overlap", "gap"))

    def test_example_inventory_runs_and_matches_the_demo(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            self.assertEqual(run("overlap", str(REPO / "examples" / "security-stack.toml"), "--out", a, "--quiet",
                                 "--format", "csv", *ENV)[0], 0)
            self.assertEqual(run("overlap", "--demo", "--out", b, "--quiet", "--format", "csv", *ENV)[0], 0)
            for name in ("tool-overlap-matrix.csv", "tool-overlap-opportunities.csv"):
                self.assertEqual((Path(a) / name).read_text(encoding="utf-8"), (Path(b) / name).read_text(encoding="utf-8"))

    def test_sample_reports_in_the_repo_are_current(self):
        samples = {"sentinel": ("sentinel-cost-2026-10-01.md", "sentinel-cost.md"),
                   "licenses": ("license-review-2026-10-01.md", "license-review.md"),
                   "overlap": ("tool-overlap.md", "tool-overlap.md")}
        for command, (written, sample) in samples.items():
            with self.subTest(command=command), tempfile.TemporaryDirectory() as tmp:
                run(command, "--demo", "--out", tmp, "--quiet", "--format", "md", *ENV)
                self.assertEqual((REPO / "examples" / "reports" / sample).read_text(encoding="utf-8"),
                                 (Path(tmp) / written).read_text(encoding="utf-8"),
                                 f"regenerate with: secopt {command} --demo --format md")

    def test_quiet_prints_only_report_paths_and_format_selects_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err = run("licenses", "--demo", "--out", tmp, "--quiet", "--format", "json", *ENV)
            self.assertEqual((code, err), (0, ""))
            self.assertEqual(out.strip(), f"Report: {Path(tmp) / 'license-review-2026-10-01.json'}")


class SnapshotTests(unittest.TestCase):
    def test_snapshot_round_trip_gives_the_same_report(self):
        for command, stem in (("sentinel", "sentinel-cost-2026-10-01"), ("licenses", "license-review-2026-10-01")):
            with self.subTest(command=command), tempfile.TemporaryDirectory() as tmp:
                saved = Path(tmp) / "snap.json"
                first, second = Path(tmp) / "a", Path(tmp) / "b"
                self.assertEqual(run(command, "--demo", "--out", str(first), "--quiet", "--format", "csv",
                                     "--save-snapshot", str(saved), *ENV)[0], 0)
                prices = ("--prices", str(REPO / "examples" / "license-prices.example.toml")) if command == "licenses" else ()
                self.assertEqual(run(command, "--snapshot", str(saved), "--out", str(second), "--quiet",
                                     "--format", "csv", *prices, *ENV)[0], 0)
                name = f"{stem}-opportunities.csv"
                self.assertEqual((first / name).read_text(encoding="utf-8"), (second / name).read_text(encoding="utf-8"))

    def test_wrong_or_broken_snapshot_is_an_error_not_an_empty_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            saved = Path(tmp) / "lic.json"
            run("licenses", "--demo", "--out", tmp, "--quiet", "--save-snapshot", str(saved), *ENV)
            code, _, err = run("sentinel", "--snapshot", str(saved), "--out", tmp, *ENV)
            self.assertEqual(code, 2)
            self.assertIn("is a 'licenses' snapshot", err)
            for text, message in (("[1, 2]", "not a snapshot"), ("{not json", "cannot read"),
                                  ('{"captured_at": "2026-10-01T12:00:00Z"}', "not a licenses snapshot")):
                saved.write_text(text, encoding="utf-8")
                code, _, err = run("licenses", "--snapshot", str(saved), "--out", tmp, *ENV)
                self.assertEqual(code, 2)
                self.assertIn(message, err)
            self.assertEqual(run("sentinel", "--snapshot", str(Path(tmp) / "missing.json"), *ENV)[0], 2)

    def test_collection_errors_in_a_snapshot_reach_the_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            saved = Path(tmp) / "snap.json"
            run("sentinel", "--demo", "--out", tmp, "--quiet", "--save-snapshot", str(saved), *ENV)
            snapshot = json.loads(saved.read_text(encoding="utf-8"))
            snapshot["rules"] = None
            snapshot["errors"] = {"rules": "HTTP 403: AuthorizationFailed"}
            saved.write_text(json.dumps(snapshot), encoding="utf-8")
            code, out, _ = run("sentinel", "--snapshot", str(saved), "--out", tmp, "--format", "md", *ENV)
            self.assertEqual(code, 0)
            self.assertNotIn("No analytics rule reads", out)  # unknown is not reported as "unread"
            markdown = (Path(tmp) / "sentinel-cost-2026-10-01.md").read_text(encoding="utf-8")
            self.assertIn("rules: HTTP 403: AuthorizationFailed", markdown)
            # no usage at all is an error, not a clean report
            snapshot["usage"] = []
            saved.write_text(json.dumps(snapshot), encoding="utf-8")
            code, _, err = run("sentinel", "--snapshot", str(saved), "--out", tmp, *ENV)
            self.assertEqual(code, 2)
            self.assertIn("no ingestion data to analyse", err)


class PricesTests(unittest.TestCase):
    def write(self, tmp: str, text: str) -> str:
        path = Path(tmp) / "prices.toml"
        path.write_text(text, encoding="utf-8")
        return str(path)

    def test_custom_prices_change_the_valuation(self):
        with tempfile.TemporaryDirectory() as tmp:
            prices = self.write(tmp, 'currency = "eur"\n[prices]\nSPE_E5 = 10\n')
            code, out, _ = run("licenses", "--demo", "--prices", prices, "--out", tmp, "--format", "json", *ENV)
            self.assertEqual(code, 0)
            self.assertIn("€160", out)  # 16 unassigned E5 at 10 each
            payload = json.loads((Path(tmp) / "license-review-2026-10-01.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["totals"]["currency"], "EUR")
            unpriced = [o for o in payload["opportunities"] if o["id"] == "unassigned:SPE_E3"]
            self.assertIsNone(unpriced[0]["monthly_saving"])  # no price given, so no number is invented

    def test_bad_price_files_are_explained(self):
        with tempfile.TemporaryDirectory() as tmp:
            for text, message in (("currency = 'USD'\n", "add a [prices] table"),
                                  ("[prices]\nSPE_E5 = 'cheap'\n", "must be a number"),
                                  ("[prices]\nSPE_E5 = -1\n", "must be a number"),
                                  ("[prices]\nSPE_E5 = 1\n[discounts]\nx = 1\n", "unknown key(s) discounts"),
                                  ("[prices\n", "prices.toml")):
                with self.subTest(text=text):
                    code, _, err = run("licenses", "--demo", "--prices", self.write(tmp, text), "--out", tmp, *ENV)
                    self.assertEqual(code, 2)
                    self.assertIn(message, err)
            self.assertEqual(run("licenses", "--demo", "--prices", str(Path(tmp) / "none.toml"), *ENV)[0], 2)

    def test_example_price_file_is_valid_and_matches_the_demo(self):
        prices, currency = cli.load_prices(str(REPO / "examples" / "license-prices.example.toml"))
        packaged = tomllib.loads((REPO / "secopt" / "licenses" / "demo_prices.toml").read_text(encoding="utf-8"))
        self.assertEqual((prices, currency), ({k: float(v) for k, v in packaged["prices"].items()}, packaged["currency"]))


class ErrorTests(unittest.TestCase):
    def test_usage_errors_exit_2_with_a_reason(self):
        for argv, message in ((("sentinel",), "pass --workspace"),
                              (("sentinel", "--workspace", "x", "--days", "3"), "--days must be between 7 and 90"),
                              (("sentinel", "--demo", "--price-per-gb", "0"), "--price-per-gb must be a number greater"),
                              (("sentinel", "--demo", "--price-per-gb", "nan"), "--price-per-gb must be a number greater"),
                              (("sentinel", "--demo", "--price-per-gb", "inf"), "--price-per-gb must be a number greater"),
                              (("sentinel", "--demo", "--format", "pdf"), "unknown format"),
                              (("sentinel", "--demo", "--format", ","), "no report format given"),
                              (("licenses", "--demo", "--inactive-days", "0"), "--inactive-days must be at least 1"),
                              (("overlap",), "pass an inventory file"),
                              (("overlap", "/no/such/stack.toml"), "stack.toml")):
            with self.subTest(argv=argv), mock.patch.dict(os.environ, {}, clear=True):
                code, _, err = run(*argv, *ENV)
                self.assertEqual(code, 2)
                self.assertIn(message, err)
        self.assertEqual(run()[0], 2)
        self.assertEqual(run("nope")[0], 2)

    def test_missing_credentials_are_explained(self):
        workspace = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/"
                     "Microsoft.OperationalInsights/workspaces/ws")
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch("shutil.which", return_value=None):
            for argv in (("sentinel", "--workspace", workspace), ("licenses",)):
                code, _, err = run(*argv, "--quiet", *ENV)
                self.assertEqual(code, 2)
                self.assertIn("Azure CLI not found", err)
        with mock.patch.dict(os.environ, {"AZURE_AUTH": "secret"}, clear=True):
            code, _, err = run("licenses", "--quiet", *ENV)
            self.assertEqual(code, 2)
            self.assertIn("AZURE_", err)

    def test_malformed_workspace_id_is_rejected_before_any_request(self):
        with mock.patch.dict(os.environ, {"AZURE_TENANT_ID": "t", "AZURE_CLIENT_ID": "c", "AZURE_CLIENT_SECRET": "s"},
                             clear=True), mock.patch("secopt.core.http.HttpClient.request",
                                                     side_effect=AssertionError("no request expected")):
            code, _, err = run("sentinel", "--workspace", "my-workspace", "--quiet", *ENV)
            self.assertEqual(code, 2)
            self.assertIn("resource ID", err)

    def test_api_failure_is_reported_with_the_permission_to_grant(self):
        denied = HttpError(403, "Authorization_RequestDenied", url="https://graph.microsoft.com/v1.0/subscribedSkus")
        with mock.patch.dict(os.environ, {"AZURE_TENANT_ID": "t", "AZURE_CLIENT_ID": "c", "AZURE_CLIENT_SECRET": "s"},
                             clear=True), mock.patch("secopt.licenses.collect.collect", side_effect=denied):
            code, _, err = run("licenses", "--quiet", *ENV)
            self.assertEqual(code, 2)
            self.assertIn("Organization.Read.All", err)

    def test_version_and_capability_list(self):
        code, out, _ = run("--version")
        self.assertEqual((code, out.strip()), (0, f"secopt {__version__}"))
        code, out, _ = run("overlap", "--list-capabilities")
        self.assertEqual(code, 0)
        self.assertIn("edr", out)
        self.assertIn("[baseline]", out)


class HostileInputTests(unittest.TestCase):
    INVENTORY = """currency = "USD"

[[tool]]
name = "Evil|Tool\\n# Injected <script>alert(1)</script>"
annual_cost = 1200
capabilities = ["edr"]

[[tool]]
name = "=HYPERLINK(\\"http://x.example\\")"
capabilities = ["edr", "antivirus"]
"""

    def test_tool_names_cannot_break_the_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            inventory = Path(tmp) / "stack.toml"
            inventory.write_text(self.INVENTORY, encoding="utf-8")
            self.assertEqual(run("overlap", str(inventory), "--out", tmp, "--quiet", *ENV)[0], 0)
            markdown = (Path(tmp) / "tool-overlap.md").read_text(encoding="utf-8")
            self.assertNotIn("<script>", markdown)
            self.assertNotIn("\n# Injected", markdown)  # no smuggled heading
            self.assertIn("| Evil\\|Tool # Injected &lt;script>", markdown)  # table cell
            self.assertIn("### 1. Evil|Tool # Injected &lt;script>", markdown)  # heading, on one line
            matrix = {r["capability"]: r for r in read_csv(Path(tmp) / "tool-overlap-matrix.csv")}
            self.assertEqual(matrix["antivirus"]["tools"], "'=HYPERLINK(\"http://x.example\")")  # not a live formula
            opportunities = read_csv(Path(tmp) / "tool-overlap-opportunities.csv")
            self.assertEqual(float(opportunities[0]["monthly_saving"]), 100.0)


if __name__ == "__main__":
    unittest.main()
