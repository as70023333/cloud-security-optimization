import json
import unittest
from importlib import resources

from secopt.core.http import HttpError
from secopt.sentinel.analyze import SentinelConfig, analyze, daily_cost, tables_read_by_rules
from secopt.sentinel.collect import AzureReader, collect, fetch_prices, parse_prices, usage_query
from tests.fakes import FakeTransport, StaticCredential, body_json, json_response

WORKSPACE = ("/subscriptions/11111111-2222-4333-8444-555555555555/resourceGroups/rg-sec/providers/"
             "Microsoft.OperationalInsights/workspaces/soc-ws")

# Three items exactly as the Azure Retail Prices API returned them for eastus (October 2026).
REAL_ITEMS = [
    {"currencyCode": "USD", "tierMinimumUnits": 0.0, "retailPrice": 4.3, "unitPrice": 4.3, "armRegionName": "eastus",
     "location": "US East", "effectiveStartDate": "2023-07-01T00:00:00Z", "meterName": "Pay-as-you-go Analysis",
     "productName": "Sentinel", "skuName": "Pay-as-you-go", "serviceName": "Sentinel", "unitOfMeasure": "1 GB",
     "type": "Consumption", "isPrimaryMeterRegion": True, "armSkuName": "Pay-as-you-go"},
    {"currencyCode": "USD", "tierMinimumUnits": 0.0, "retailPrice": 296.0, "unitPrice": 296.0, "armRegionName": "eastus",
     "location": "US East", "effectiveStartDate": "2023-07-01T00:00:00Z",
     "meterName": "100 GB Commitment Tier Capacity Reservation", "productName": "Sentinel",
     "skuName": "100 GB Commitment Tier", "serviceName": "Sentinel", "unitOfMeasure": "1/Day", "type": "Consumption"},
    {"currencyCode": "USD", "tierMinimumUnits": 0.0, "retailPrice": 1.0, "unitPrice": 1.0, "armRegionName": "eastus",
     "location": "US East", "effectiveStartDate": "2023-07-01T00:00:00Z", "meterName": "Basic Logs Analysis",
     "productName": "Sentinel", "skuName": "Basic Logs", "serviceName": "Sentinel", "unitOfMeasure": "1 GB",
     "type": "Consumption"},
]
OTHER_ITEMS = [
    {"retailPrice": 548.0, "meterName": "200 GB Commitment Tier Capacity Reservation", "unitOfMeasure": "1/Day",
     "type": "Consumption", "effectiveStartDate": "2023-07-01T00:00:00Z"},
    {"retailPrice": 0.0, "meterName": "Free Benefit - M365 Defender Analysis", "unitOfMeasure": "1 GB", "type": "Consumption"},
    {"retailPrice": 2.0, "meterName": "Solution for SAP Applications Hourly", "unitOfMeasure": "1/Hour", "type": "Consumption"},
    {"retailPrice": 3.9, "meterName": "Pay-as-you-go Analysis", "unitOfMeasure": "1 GB", "type": "Consumption",
     "effectiveStartDate": "2021-01-01T00:00:00Z"},  # an older price for the same meter
    {"retailPrice": 100.0, "meterName": "Pay-as-you-go Analysis", "unitOfMeasure": "1 GB", "type": "Reservation"},
]


def demo() -> dict:
    return json.loads(resources.files("secopt.sentinel").joinpath("demo.json").read_text(encoding="utf-8"))


def snapshot(usage, *, sku="PerGB2018", level=None, tables=None, rules=None, prices="default", errors=None) -> dict:
    if prices == "default":
        prices = {"currency": "USD", "region": "eastus", "payg_per_gb": 4.0, "basic_per_gb": 1.0,
                  "commitment_tiers": {"100": 300.0, "200": 500.0}, "source": "test prices"}
    return {"captured_at": "2026-10-01T00:00:00Z", "days": 30,
            "workspace": {"name": "ws", "location": "eastus", "sku": sku, "capacity_reservation_gb": level},
            "usage": usage, "tables": tables, "rules": rules, "prices": prices, "errors": errors or {}}


def flat(table: str, gb: float, days: int = 14, start: int = 1) -> list[dict]:
    return [{"date": f"2026-09-{d:02d}", "table": table, "billable_gb": gb, "total_gb": gb}
            for d in range(start, start + days)]


class PriceTests(unittest.TestCase):
    def test_parse_real_api_items(self):
        prices = parse_prices(REAL_ITEMS + OTHER_ITEMS, "eastus", "USD")
        self.assertEqual(prices["payg_per_gb"], 4.3)  # newest consumption price wins
        self.assertEqual(prices["basic_per_gb"], 1.0)
        self.assertEqual(prices["commitment_tiers"], {"100": 296.0, "200": 548.0})

    def test_fetch_follows_paging_and_builds_the_documented_url(self):
        fake = FakeTransport()
        fake.add("GET", r"prices\.azure\.com/api/retail/prices\?currencyCode", json_response(
            {"Items": REAL_ITEMS[:1], "NextPageLink": "https://prices.azure.com/api/retail/prices?$skip=100"}))
        fake.add("GET", r"\$skip=100", json_response({"Items": REAL_ITEMS[1:], "NextPageLink": None}))
        fake.routes.reverse()
        prices = fetch_prices(fake.client(retries=0), "eastus", "USD")
        self.assertEqual((prices["payg_per_gb"], prices["commitment_tiers"]), (4.3, {"100": 296.0}))
        self.assertIn("Azure Retail Prices API", prices["source"])
        self.assertEqual(fake.calls[0].url, "https://prices.azure.com/api/retail/prices?currencyCode=%27USD%27&$filter="
                         "serviceName%20eq%20%27Sentinel%27%20and%20armRegionName%20eq%20%27eastus%27%20and%20"
                         "priceType%20eq%20%27Consumption%27")
        self.assertNotIn("Authorization", fake.calls[0].headers)  # public API: no token is sent

    def test_bad_region_and_foreign_paging_link(self):
        with self.assertRaises(ValueError):
            fetch_prices(FakeTransport().client(), "east us'; drop", "USD")
        fake = FakeTransport().add("GET", "prices.azure.com", json_response(
            {"Items": [], "NextPageLink": "https://evil.example/next"}))
        with self.assertRaises(HttpError):
            fetch_prices(fake.client(retries=0), "eastus")


class CollectTests(unittest.TestCase):
    def fake(self) -> FakeTransport:
        t = FakeTransport()
        t.add("GET", r"workspaces/soc-ws\?api-version", json_response({
            "id": WORKSPACE, "name": "soc-ws", "location": "East US",
            "properties": {"customerId": "cust-guid", "retentionInDays": 90, "workspaceCapping": {"dailyQuotaGb": -1.0},
                           "sku": {"name": "CapacityReservation", "capacityReservationLevel": 100}}}))
        t.add("GET", r"soc-ws/tables\?", json_response({"value": [
            {"name": "SecurityEvent", "properties": {"plan": "Analytics", "retentionInDays": 180, "totalRetentionInDays": 365}},
            {"name": "ContainerLogV2", "properties": {"plan": "Basic", "retentionInDays": 30}}]}))
        t.add("GET", r"Microsoft\.SecurityInsights/alertRules\?", json_response({"value": [
            {"kind": "Scheduled", "name": "guid-1", "properties": {"displayName": "Rule A", "enabled": True,
                                                                    "query": "SecurityEvent | take 1"}},
            {"kind": "Fusion", "name": "guid-2", "properties": {"enabled": True}}]}))
        t.add("POST", r"api\.loganalytics\.io/v1/workspaces/cust-guid/query", json_response({"tables": [{
            "name": "PrimaryResult",
            "columns": [{"name": "Day"}, {"name": "DataType"}, {"name": "BillableMB"}, {"name": "TotalMB"}],
            "rows": [["2026-09-29T00:00:00Z", "SecurityEvent", 41500.0, 41500.0],
                     ["2026-09-29T00:00:00Z", "OfficeActivity", 0.0, 5200.0]]}]}))
        t.add("GET", r"prices\.azure\.com", json_response({"Items": REAL_ITEMS, "NextPageLink": None}))
        return t

    def test_collect(self):
        t = self.fake()
        credential = StaticCredential()
        snap = collect(AzureReader(t.client(retries=0), credential), WORKSPACE, days=30)
        ws = snap["workspace"]
        self.assertEqual((ws["location"], ws["sku"], ws["capacity_reservation_gb"], ws["daily_cap_gb"]),
                         ("eastus", "CapacityReservation", 100, None))
        self.assertEqual(snap["usage"], [
            {"date": "2026-09-29", "table": "SecurityEvent", "billable_gb": 41.5, "total_gb": 41.5},
            {"date": "2026-09-29", "table": "OfficeActivity", "billable_gb": 0.0, "total_gb": 5.2}])
        self.assertEqual(snap["tables"][0], {"name": "SecurityEvent", "plan": "Analytics", "retention_days": 180,
                                             "total_retention_days": 365})
        self.assertEqual([r["name"] for r in snap["rules"]], ["Rule A", "guid-2"])
        self.assertEqual(snap["prices"]["payg_per_gb"], 4.3)
        self.assertEqual(snap["errors"], {})
        self.assertEqual(set(credential.scopes), {"https://management.azure.com/.default",
                                                  "https://api.loganalytics.io/.default"})
        query = body_json(t.requests_to("loganalytics")[0])["query"]
        self.assertEqual(query, usage_query(30))
        self.assertIn("ago(30d)", query)
        # read-only: every call is a GET except the log query
        self.assertEqual([c.method for c in t.calls if c.method != "GET"], ["POST"])

    def test_sections_fail_independently_and_analysis_still_runs(self):
        t = self.fake()
        denied = json_response({"error": {"code": "AuthorizationFailed", "message": "no"}}, 403)
        import re
        t.routes.insert(0, ("GET", re.compile("alertRules"), denied))
        t.routes.insert(0, ("GET", re.compile("prices.azure.com"), json_response({"Items": []})))
        snap = collect(AzureReader(t.client(retries=0), StaticCredential()), WORKSPACE)
        self.assertIsNone(snap["rules"])
        self.assertIn("Microsoft Sentinel Reader", snap["errors"]["rules"])
        self.assertIsNone(snap["prices"])
        self.assertIn("--price-per-gb", snap["errors"]["prices"])
        report = analyze(snap)
        self.assertIsNone(report.totals["monthly_cost"])
        self.assertTrue(any(n.startswith("rules:") for n in report.notes))
        self.assertFalse([o for o in report.opportunities if o.id.startswith("unread-table")])

    def test_workspace_id_is_validated_and_workspace_failure_is_fatal(self):
        reader = AzureReader(FakeTransport().client(), StaticCredential())
        with self.assertRaises(ValueError):
            collect(reader, "soc-ws")
        with self.assertRaises(ValueError):
            usage_query(1000)
        t = FakeTransport().add("GET", "management.azure.com", json_response({"error": {"code": "x"}}, 404))
        with self.assertRaises(HttpError):
            collect(AzureReader(t.client(retries=0), StaticCredential()), WORKSPACE)


class AnalyzeMathTests(unittest.TestCase):
    def test_daily_cost(self):
        tiers = {100: 300.0}
        self.assertEqual(daily_cost(50, None, 4.0, tiers), 200.0)
        self.assertEqual(daily_cost(50, 100, 4.0, tiers), 300.0)     # below the tier you still pay the tier
        self.assertEqual(daily_cost(150, 100, 4.0, tiers), 450.0)    # overage at the tier's own rate (3.00)

    def test_recommends_the_cheapest_plan(self):
        # 150 GB every day: PAYG 600/day, 100 tier 450/day, 200 tier 500/day.
        report = analyze(snapshot(flat("T", 150.0)))
        self.assertEqual(report.totals["monthly_cost"], 18000.0)
        tier = next(o for o in report.opportunities if o.id == "pricing-tier")
        self.assertEqual(tier.title, "Switch to 100 GB/day commitment tier")
        self.assertEqual(tier.monthly_saving, 4500.0)
        self.assertTrue(tier.additive)
        costs = {o["plan"]: o["monthly_cost"] for o in report.pricing_options}
        self.assertEqual(costs, {"Pay-as-you-go": 18000.0, "100 GB/day commitment tier": 13500.0,
                                 "200 GB/day commitment tier": 15000.0})

    def test_small_workspace_stays_on_pay_as_you_go(self):
        report = analyze(snapshot(flat("T", 20.0)))
        self.assertFalse([o for o in report.opportunities if o.id == "pricing-tier"])
        self.assertEqual(report.totals["current_plan"], "Pay-as-you-go")

    def test_oversized_commitment_tier_is_flagged(self):
        # On the 200 tier (500/day) but ingesting 40 GB/day: PAYG would be 160/day.
        report = analyze(snapshot(flat("T", 40.0), sku="CapacityReservation", level=200))
        self.assertEqual(report.totals["current_plan"], "200 GB/day commitment tier")
        self.assertEqual(report.totals["monthly_cost"], 15000.0)
        self.assertEqual(report.totals["effective_price_per_gb"], 12.5)
        tier = next(o for o in report.opportunities if o.id == "pricing-tier")
        self.assertEqual((tier.title, tier.monthly_saving), ("Switch to Pay-as-you-go", 10200.0))

    def test_uses_each_days_volume_not_the_average(self):
        # 50 GB and 250 GB on alternate days average 150, but on the 100 tier the quiet days still
        # cost the full tier: (300 + 750) / 2 = 525/day, not 450.
        usage = [{"date": f"2026-09-{d:02d}", "table": "T", "billable_gb": 50.0 if d % 2 else 250.0, "total_gb": 0}
                 for d in range(1, 15)]
        costs = {o["tier_gb"]: o["monthly_cost"] for o in analyze(snapshot(usage)).pricing_options}
        self.assertEqual(costs[100], 15750.0)

    def test_price_override_and_missing_prices(self):
        report = analyze(snapshot(flat("T", 10.0)), SentinelConfig(price_per_gb=2.5))
        self.assertEqual(report.totals["monthly_cost"], 750.0)
        self.assertTrue(any("using your price" in n for n in report.notes))
        report = analyze(snapshot(flat("T", 10.0), prices=None))
        self.assertIsNone(report.totals["monthly_cost"])
        self.assertIsNone(report.tables[0]["monthly_cost"])
        self.assertTrue(any("volumes only" in n for n in report.notes))
        with self.assertRaises(ValueError):
            SentinelConfig(price_per_gb=0)

    def test_no_usage_is_an_error_with_the_reason(self):
        with self.assertRaisesRegex(ValueError, "HTTP 403"):
            analyze(snapshot(None, errors={"usage": "HTTP 403: denied"}))

    def test_rule_matching_is_whole_word(self):
        rules = [{"enabled": True, "query": "SigninLogs | join (AADNonInteractiveUserSignInLogs) on UserId"},
                 {"enabled": False, "query": "Syslog | take 1"},
                 {"enabled": True, "query": "MyDb.SecurityEvent_CL | take 1"}]
        counts = tables_read_by_rules(rules, ["SigninLogs", "AADNonInteractiveUserSignInLogs", "Syslog",
                                              "SecurityEvent"])
        self.assertEqual(counts, {"SigninLogs": 1, "AADNonInteractiveUserSignInLogs": 1, "Syslog": 0,
                                  "SecurityEvent": 0})

    def test_unread_spike_and_retention_opportunities(self):
        usage = flat("Read", 5.0) + flat("Unread", 5.0) + flat("Tiny", 0.1) + flat("SecurityIncident", 2.0)
        usage += flat("Growing", 2.0, days=7) + flat("Growing", 6.0, days=7, start=8)
        tables = [{"name": n, "plan": "Analytics", "retention_days": r} for n, r in
                  (("Read", 365), ("Unread", 90), ("Tiny", 730), ("Growing", 90), ("SecurityIncident", 90))]
        rules = [{"enabled": True, "query": "Read | union Growing"}]
        report = analyze(snapshot(usage, tables=tables, rules=rules))
        ids = {o.id: o for o in report.opportunities}
        # Unread: 5 GB/day x 30 x (4.00 - 1.00 Basic) = 450. Feature tables and tiny tables are left alone.
        self.assertEqual(ids["unread-table:Unread"].monthly_saving, 450.0)
        self.assertFalse(ids["unread-table:Unread"].additive)
        self.assertNotIn("unread-table:SecurityIncident", ids)
        self.assertNotIn("unread-table:Tiny", ids)
        self.assertNotIn("unread-table:Read", ids)
        # Growing: 2 -> 6 GB/day, +4 GB/day x 30 x 4.00 = 480.
        self.assertEqual(ids["spike:Growing"].monthly_saving, 480.0)
        self.assertIn("+200%", ids["spike:Growing"].detail)
        self.assertNotIn("spike:Read", ids)
        self.assertEqual(ids["long-retention"].evidence["tables"], ["Read"])  # Tiny is below the size floor
        self.assertIsNone(ids["long-retention"].monthly_saving)
        growing = next(t for t in report.tables if t["table"] == "Growing")
        self.assertEqual((growing["rules"], growing["trend_pct"]), (1, 200.0))

    def test_short_history_has_no_trend(self):
        report = analyze(snapshot(flat("T", 5.0, days=10)))
        self.assertIsNone(report.tables[0]["trend_pct"])


class DemoTests(unittest.TestCase):
    def test_demo_report(self):
        report = analyze(demo())
        self.assertEqual(report.totals["days_analysed"], 30)
        self.assertEqual(report.totals["tables_with_billable_data"], 11)
        ids = [o.id for o in report.opportunities]
        self.assertEqual(ids[0], "pricing-tier")
        self.assertIn("100 GB/day", report.opportunities[0].title)
        for expected in ("unread-table:AADNonInteractiveUserSignInLogs", "unread-table:DeviceNetworkEvents",
                         "unread-table:AzureDiagnostics", "unread-table:StorageBlobLogs", "spike:AzureDiagnostics",
                         "long-retention"):
            self.assertIn(expected, ids)
        # tables that enabled rules read, and free tables, are not flagged
        for table in ("SecurityEvent", "CommonSecurityLog", "Syslog", "SigninLogs", "DeviceProcessEvents", "OfficeActivity"):
            self.assertNotIn(f"unread-table:{table}", ids)
        shares = sum(t["share_pct"] for t in report.tables)
        self.assertAlmostEqual(shares, 100.0, delta=0.5)
        costs = sum(t["monthly_cost"] for t in report.tables)
        self.assertAlmostEqual(costs, report.totals["monthly_cost"], delta=1.0)


if __name__ == "__main__":
    unittest.main()
