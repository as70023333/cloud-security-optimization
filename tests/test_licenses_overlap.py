import json
import tomllib
import unittest
from importlib import resources
from pathlib import Path

from secopt.core.http import HttpError
from secopt.core.model import Opportunity, money, rank, total_saving
from secopt.licenses.analyze import LicenseConfig, analyze as analyze_licenses, coverage
from secopt.licenses.collect import GraphReader, collect
from secopt.overlap.analyze import InventoryError, analyze as analyze_overlap, parse_inventory
from secopt.overlap.capabilities import BASELINE, CAPABILITIES
from tests.fakes import FakeTransport, StaticCredential, json_response

REPO = Path(__file__).resolve().parent.parent
PRICES = {"SPE_E5": 57.0, "SPE_E3": 36.0, "AAD_PREMIUM_P2": 9.0, "WIN_DEF_ATP": 5.2, "THREAT_INTELLIGENCE": 5.0}


def license_demo() -> dict:
    return json.loads(resources.files("secopt.licenses").joinpath("demo.json").read_text(encoding="utf-8"))


def sku(sku_id, part, purchased, assigned, plans):
    return {"sku_id": sku_id, "part_number": part, "status": "Enabled", "applies_to": "User",
            "purchased": purchased, "assigned": assigned, "service_plans": plans}


def user(upn, skus, enabled=True, last="2026-09-30T00:00:00Z", created="2024-01-01T00:00:00Z"):
    return {"id": upn, "upn": upn, "enabled": enabled, "type": "Member", "created": created,
            "last_sign_in": last, "sku_ids": skus}


def tenant(skus, users, activity=True):
    return {"captured_at": "2026-10-01T00:00:00Z", "skus": skus, "users": users,
            "sign_in_activity_available": activity, "errors": {}}


class LicenseCollectTests(unittest.TestCase):
    def fake(self, activity_status=200) -> FakeTransport:
        t = FakeTransport()
        t.add("GET", r"/v1.0/subscribedSkus", json_response({"value": [
            {"skuId": "s-e5", "skuPartNumber": "SPE_E5", "capabilityStatus": "Enabled", "appliesTo": "User",
             "consumedUnits": 2, "prepaidUnits": {"enabled": 5, "suspended": 0, "warning": 1},
             "servicePlans": [{"servicePlanId": "p2", "appliesTo": "User"}, {"servicePlanId": "p1", "appliesTo": "User"},
                              {"servicePlanId": "org", "appliesTo": "Company"}]}]}))

        def users(req):
            if "signInActivity" in req.url and activity_status != 200:
                return json_response({"error": {"code": "Authentication_RequestFromNonPremiumTenantOrB2CTenant"}},
                                     activity_status)
            return json_response({"value": [
                {"id": "u1", "userPrincipalName": "a@x.example", "accountEnabled": True, "createdDateTime": "2024-01-01T00:00:00Z",
                 "assignedLicenses": [{"skuId": "s-e5"}],
                 "signInActivity": {"lastSignInDateTime": "2026-01-01T00:00:00Z",
                                    "lastNonInteractiveSignInDateTime": "2026-09-01T00:00:00Z"}},
                {"id": "u2", "userPrincipalName": "unlicensed@x.example", "accountEnabled": True, "assignedLicenses": []}]})

        t.add("GET", r"/v1.0/users\?", users)
        return t

    def test_collect(self):
        t = self.fake()
        snap = collect(GraphReader(t.client(retries=0), StaticCredential()))
        self.assertEqual(snap["skus"], [{"sku_id": "s-e5", "part_number": "SPE_E5", "status": "Enabled",
                                         "applies_to": "User", "purchased": 6, "suspended": 0, "assigned": 2,
                                         "service_plans": ["p1", "p2"]}])  # company-level plans are left out
        self.assertEqual(len(snap["users"]), 1)  # only licensed users
        self.assertEqual(snap["users"][0]["last_sign_in"], "2026-09-01T00:00:00Z")  # the later of the two
        self.assertTrue(snap["sign_in_activity_available"])
        self.assertTrue(all(c.method == "GET" for c in t.calls))

    def test_falls_back_without_sign_in_activity(self):
        snap = collect(GraphReader(self.fake(activity_status=403).client(retries=0), StaticCredential()))
        self.assertFalse(snap["sign_in_activity_available"])
        self.assertIn("AuditLog.Read.All", snap["errors"]["sign_in_activity"])
        report = analyze_licenses(snap)
        self.assertTrue(any("inactive accounts: not checked" in n for n in report.notes))

    def test_user_list_denied_still_reports_unassigned(self):
        t = self.fake()
        import re
        t.routes.insert(0, ("GET", re.compile(r"/v1.0/users"), json_response({"error": {"code": "Forbidden"}}, 403)))
        snap = collect(GraphReader(t.client(retries=0), StaticCredential()))
        self.assertIsNone(snap["users"])
        self.assertIn("User.Read.All", snap["errors"]["users"])
        report = analyze_licenses(snap, LicenseConfig(prices={"SPE_E5": 50.0}))
        self.assertEqual([o.id for o in report.opportunities], ["unassigned:SPE_E5"])
        self.assertEqual(report.opportunities[0].monthly_saving, 200.0)  # 4 unused x 50

    def test_licence_list_failure_is_fatal(self):
        t = FakeTransport().add("GET", "subscribedSkus", json_response({"error": {"code": "x"}}, 403))
        with self.assertRaises(HttpError):
            collect(GraphReader(t.client(retries=0), StaticCredential()))


class LicenseAnalyzeTests(unittest.TestCase):
    def test_coverage_comes_from_service_plans(self):
        skus = [sku("e5", "SPE_E5", 1, 1, ["p1", "p2", "mde"]), sku("p2", "AAD_PREMIUM_P2", 1, 1, ["p1", "p2"]),
                sku("x", "OTHER", 1, 1, ["p1", "zzz"]), sku("e5b", "SPE_E5_COPY", 1, 1, ["p1", "p2", "mde"])]
        covered = coverage(skus)
        self.assertEqual(covered["p2"], {"e5", "e5b"})
        self.assertEqual(covered["x"], set())      # has a plan nothing else contains
        self.assertEqual(covered["e5"], set())     # identical sets do not cover each other

    def test_each_licence_is_counted_once(self):
        skus = [sku("e5", "SPE_E5", 10, 4, ["p1", "p2", "mde"]), sku("p2", "AAD_PREMIUM_P2", 5, 4, ["p1", "p2"])]
        users = [user("dup@x", ["e5", "p2"]),                                   # duplicate P2
                 user("gone@x", ["e5", "p2"], enabled=False),                   # disabled: both licences, once each
                 user("quiet@x", ["e5", "p2"], last="2026-01-01T00:00:00Z"),    # inactive: both licences
                 user("new@x", ["p2"], last="", created="2026-09-20T00:00:00Z"),  # new, never signed in: fine
                 user("old@x", ["e5"], last="", created="2025-01-01T00:00:00Z")]  # never signed in for a year
        report = analyze_licenses(tenant(skus, users), LicenseConfig(prices={"SPE_E5": 50.0, "AAD_PREMIUM_P2": 10.0}))
        ids = {o.id: o for o in report.opportunities}
        self.assertEqual(ids["duplicate:AAD_PREMIUM_P2"].evidence["users"], ["dup@x"])
        self.assertIn("Microsoft 365 E5", ids["duplicate:AAD_PREMIUM_P2"].detail)
        self.assertEqual(ids["disabled:SPE_E5"].evidence["count"], 1)
        self.assertEqual(ids["disabled:AAD_PREMIUM_P2"].evidence["count"], 1)
        self.assertEqual(ids["inactive:SPE_E5"].evidence["users"], ["old@x", "quiet@x"])
        self.assertEqual(ids["inactive:AAD_PREMIUM_P2"].evidence["users"], ["quiet@x"])
        self.assertEqual(ids["unassigned:SPE_E5"].monthly_saving, 300.0)        # 6 x 50
        self.assertEqual(ids["unassigned:AAD_PREMIUM_P2"].monthly_saving, 10.0)
        # 6 unassigned + 1 disabled + 2 inactive E5 = 450; 1 unassigned + 1 + 1 + 1 duplicate P2 = 40
        self.assertEqual(report.totals["monthly_waste"], 490.0)
        self.assertEqual(total_saving(report.opportunities), 490.0)
        e5 = next(p for p in report.products if p["part_number"] == "SPE_E5")
        self.assertEqual((e5["unassigned"], e5["disabled"], e5["inactive"], e5["duplicate"], e5["monthly_waste"]),
                         (6, 1, 2, 0, 450.0))

    def test_free_products_and_missing_prices(self):
        skus = [sku("flow", "FLOW_FREE", 10000, 3, ["f"]), sku("e3", "SPE_E3", 10, 8, ["o"])]
        report = analyze_licenses(tenant(skus, [user("a@x", ["flow"], enabled=False)]))
        self.assertEqual([o.id for o in report.opportunities], ["unassigned:SPE_E3"])
        self.assertIsNone(report.opportunities[0].monthly_saving)   # no price: counted, never valued
        self.assertIsNone(report.totals["monthly_waste"])
        self.assertTrue(any("no price file" in n for n in report.notes))
        self.assertEqual(report.totals["unassigned"], 2)

    def test_over_assignment_note_and_config_validation(self):
        report = analyze_licenses(tenant([sku("e3", "SPE_E3", 5, 7, ["o"])], []))
        self.assertTrue(any("2 more assigned than purchased" in n for n in report.notes))
        self.assertEqual(report.opportunities, [])
        with self.assertRaises(ValueError):
            LicenseConfig(prices={"SPE_E3": -1})
        with self.assertRaises(ValueError):
            LicenseConfig(inactive_days=0)

    def test_demo_tenant(self):
        report = analyze_licenses(license_demo(), LicenseConfig(prices=PRICES))
        t = report.totals
        self.assertEqual((t["licensed_users"], t["unassigned"], t["on_disabled_accounts"], t["on_inactive_accounts"],
                          t["duplicates"]), (384, 79, 18, 14, 18))
        ids = {o.id: o.monthly_saving for o in report.opportunities}
        self.assertEqual(ids["unassigned:SPE_E5"], 912.0)
        self.assertEqual(ids["duplicate:AAD_PREMIUM_P2"], 72.0)
        self.assertEqual(ids["duplicate:WIN_DEF_ATP"], 52.0)
        self.assertNotIn("duplicate:THREAT_INTELLIGENCE", ids)   # those users hold E3, which does not include it
        self.assertNotIn("unassigned:FLOW_FREE", ids)
        self.assertEqual(t["monthly_waste"], total_saving(report.opportunities))


def inventory(*tools, **extra):
    return parse_inventory({"tool": [dict(t) for t in tools], **extra})


def tool(name, capabilities, cost=0, bundled=""):
    return {"name": name, "vendor": "V", "annual_cost": cost, "bundled_with": bundled, "capabilities": capabilities}


class OverlapTests(unittest.TestCase):
    def test_demo_inventory(self):
        data = tomllib.loads(resources.files("secopt.overlap").joinpath("demo_stack.toml").read_text(encoding="utf-8"))
        report = analyze_overlap(parse_inventory(data))
        ids = {o.id: o for o in report.opportunities}
        self.assertEqual(ids["redundant:Acme EDR"].monthly_saving, 4500.0)
        self.assertEqual(ids["redundant:Acme Email Gateway"].monthly_saving, 3166.67)
        self.assertEqual(ids["redundant:Acme EDR"].evidence["covered_by"], ["Microsoft Defender for Endpoint"])
        # the legacy SIEM still provides case management, so it is an overlap, not a redundant tool
        self.assertNotIn("redundant:Acme SIEM (legacy)", ids)
        self.assertIn("overlap:siem", ids)
        self.assertIn("overlap:vulnerability-management", ids)
        self.assertNotIn("overlap:antivirus", ids)   # already reported through the redundant EDR
        self.assertEqual({i for i in ids if i.startswith("gap:")}, {"gap:backup", "gap:pam"})
        t = report.totals
        self.assertEqual((t["tools"], t["paid_tools"], t["annual_spend"], t["redundant_annual_spend"], t["gaps"]),
                         (14, 8, 344000.0, 92000.0, 2))
        self.assertEqual(t["redundant_pct"], 26.7)

    def test_example_file_matches_the_demo(self):
        self.assertEqual((REPO / "examples" / "security-stack.toml").read_text(encoding="utf-8"),
                         resources.files("secopt.overlap").joinpath("demo_stack.toml").read_text(encoding="utf-8"))

    def test_two_tools_that_only_duplicate_each_other_count_once(self):
        report = analyze_overlap(inventory(tool("A", ["edr"], cost=24000), tool("B", ["edr"], cost=12000),
                                           not_required=sorted(BASELINE - {"edr"})))
        redundant = [o for o in report.opportunities if o.id.startswith("redundant:")]
        self.assertEqual([o.id for o in redundant], ["redundant:A"])   # the more expensive one
        self.assertEqual(redundant[0].monthly_saving, 2000.0)
        self.assertEqual(report.totals["redundant_annual_spend"], 24000.0)

    def test_bundled_tools_are_never_savings(self):
        report = analyze_overlap(inventory(tool("Suite EDR", ["edr"], bundled="Suite"), tool("Suite AV", ["edr"], bundled="Suite"),
                                           not_required=sorted(BASELINE - {"edr"})))
        self.assertEqual(report.opportunities, [])
        self.assertEqual(report.totals["capabilities_overlapping"], 1)
        self.assertTrue(any("no tool has an annual_cost" in n for n in report.notes))

    def test_required_and_not_required_shape_the_gaps(self):
        base = inventory(tool("A", ["edr"]))
        self.assertEqual(base.required, BASELINE)
        gaps = {o.id for o in analyze_overlap(base).opportunities if o.id.startswith("gap:")}
        self.assertEqual(gaps, {f"gap:{c}" for c in BASELINE - {"edr"}})
        custom = inventory(tool("A", ["edr"]), required=["pam"], not_required=sorted(BASELINE))
        self.assertEqual({o.id for o in analyze_overlap(custom).opportunities}, {"gap:pam"})

    def test_validation(self):
        bad = {
            "no tools": {},
            "unknown capability": {"tool": [tool("A", ["telepathy"])]},
            "no capabilities": {"tool": [tool("A", [])]},
            "negative cost": {"tool": [tool("A", ["edr"], cost=-1)]},
            "duplicate name": {"tool": [tool("A", ["edr"]), tool("a", ["siem"])]},
            "unknown field": {"tool": [{**tool("A", ["edr"]), "colour": "red"}]},
            "unknown key": {"tool": [tool("A", ["edr"])], "budget": 1},
            "bad required": {"tool": [tool("A", ["edr"])], "required": ["nope"]},
            "missing name": {"tool": [{"capabilities": ["edr"]}]},
            "bad currency": {"tool": [tool("A", ["edr"])], "currency": "dollars"},
        }
        for name, data in bad.items():
            with self.subTest(case=name):
                with self.assertRaises(InventoryError):
                    parse_inventory(data)

    def test_vocabulary_is_consistent(self):
        self.assertGreaterEqual(len(CAPABILITIES), 40)
        self.assertTrue(BASELINE <= set(CAPABILITIES))
        self.assertEqual(len({c.name for c in CAPABILITIES.values()}), len(CAPABILITIES))


class ModelTests(unittest.TestCase):
    def test_ranking_totals_and_money(self):
        a = Opportunity("a", "x", "A", "d", "do", 10.0)
        b = Opportunity("b", "x", "B", "d", "do", 99.999)
        c = Opportunity("c", "x", "C", "d", "do", None)
        d = Opportunity("d", "x", "D", "d", "do", 500.0, additive=False)
        self.assertEqual([o.id for o in rank([c, a, d, b])], ["d", "b", "a", "c"])
        self.assertEqual(total_saving([a, b, c, d]), 110.0)   # the overlapping one is not added
        self.assertEqual(b.monthly_saving, 100.0)
        self.assertEqual((money(1234.5), money(12.5), money(None), money(50, "EUR"), money(50, "SEK")),
                         ("$1,234", "$12.50", "n/a", "€50.00", "50.00 SEK"))
        with self.assertRaises(ValueError):
            Opportunity("e", "x", "E", "d", "do", effort="trivial")


if __name__ == "__main__":
    unittest.main()
