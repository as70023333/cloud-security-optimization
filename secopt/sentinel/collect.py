"""Read-only collection for the Sentinel cost analysis.

Four sources, all read-only:
* Azure Resource Manager: the workspace, its tables (plan and retention) and Sentinel analytics rules
* Log Analytics: the ``Usage`` table (how many GB each table ingested per day)
* Azure Retail Prices API: public list prices for the workspace's region (no sign-in needed)

Each source is collected independently. If one fails, the analysis still runs on the rest and the
report says what is missing.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any, Callable, Mapping

from secopt.core.auth import ARM_SCOPE, LOG_ANALYTICS_SCOPE, TokenCredential
from secopt.core.http import HttpClient, HttpError, same_origin
from secopt.core.timeutil import iso, utcnow

ARM_BASE = "https://management.azure.com"
LOG_ANALYTICS_BASE = "https://api.loganalytics.io"
RETAIL_PRICES_URL = "https://prices.azure.com/api/retail/prices"
WORKSPACE_ID = re.compile(r"^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.OperationalInsights/"
                          r"workspaces/[^/]+$", re.IGNORECASE)
_TIER = re.compile(r"^(\d+) GB Commitment Tier")
MIN_DAYS, MAX_DAYS = 7, 90

Log = Callable[[str], None]


def usage_query(days: int) -> str:
    """Billable and total volume per table per day. ``Quantity`` is in MB; billing GB = MB / 1000.

    As in Microsoft's documented billing queries, Usage records are hourly and are filtered and
    grouped on StartTime (the hour the data belongs to), not on TimeGenerated (when the record was
    written, shortly after the hour ended). Every hour that started before today's midnight is
    included, so only whole days are counted.
    """
    if not MIN_DAYS <= days <= MAX_DAYS:
        raise ValueError(f"days must be between {MIN_DAYS} and {MAX_DAYS}")
    return ("Usage\n"
            f"| where TimeGenerated > ago({days + 2}d)\n"
            f"| where StartTime >= startofday(ago({days}d)) and StartTime < startofday(now())\n"
            "| summarize BillableMB = sumif(Quantity, IsBillable == true), TotalMB = sum(Quantity) "
            "by DataType, Day = bin(StartTime, 1d)\n"
            "| project Day, DataType, BillableMB, TotalMB\n"
            "| order by Day asc, DataType asc")


class AzureReader:
    """GET (and the Log Analytics query POST) against Azure with bearer tokens, per-host scoped."""

    def __init__(self, http: HttpClient, credential: TokenCredential, arm_base: str = ARM_BASE,
                 log_analytics_base: str = LOG_ANALYTICS_BASE) -> None:
        self.http = http
        self.credential = credential
        self.arm_base = arm_base.rstrip("/")
        self.log_analytics_base = log_analytics_base.rstrip("/")

    def _arm_headers(self) -> dict[str, str]:
        scope = ARM_SCOPE if self.arm_base == ARM_BASE else f"{self.arm_base}/.default"
        return {"Authorization": f"Bearer {self.credential.get_token(scope)}"}

    def arm_get(self, path: str, api_version: str) -> dict:
        return self.http.request("GET", f"{self.arm_base}{path}", params={"api-version": api_version},
                                 headers=self._arm_headers(), ok=(200,)).json() or {}

    def arm_list(self, path: str, api_version: str) -> list[dict]:
        url: str | None = f"{self.arm_base}{path}"
        query: Mapping[str, str] | None = {"api-version": api_version}
        items: list[dict] = []
        while url:
            # Never send the token to another host, or over plain http, even if a paging link points there.
            if not same_origin(url, self.arm_base):
                raise HttpError(0, "refusing to follow a paging link to another host")
            data = self.http.request("GET", url, params=query, headers=self._arm_headers(), ok=(200,)).json() or {}
            items.extend(data.get("value") or [])
            url, query = data.get("nextLink"), None
        return items

    def log_query(self, customer_id: str, kql: str) -> list[dict]:
        scope = (LOG_ANALYTICS_SCOPE if self.log_analytics_base == LOG_ANALYTICS_BASE
                 else f"{self.log_analytics_base}/.default")
        headers = {"Authorization": f"Bearer {self.credential.get_token(scope)}"}
        data = self.http.request("POST", f"{self.log_analytics_base}/v1/workspaces/{customer_id}/query",
                                 json_body={"query": kql}, headers=headers, ok=(200,)).json() or {}
        tables = data.get("tables") or []
        if not tables:
            return []
        columns = [c["name"] for c in tables[0].get("columns", [])]
        return [dict(zip(columns, row)) for row in tables[0].get("rows", [])]


# --------------------------------------------------------------------------------------------- prices

def parse_prices(items: list[dict], region: str, currency: str) -> dict[str, Any]:
    """Turn Azure Retail Prices items for Microsoft Sentinel into the few numbers the analysis needs."""
    latest: dict[str, dict] = {}
    for item in items:
        if item.get("type") not in (None, "Consumption"):
            continue
        name = str(item.get("meterName") or "")
        previous = latest.get(name)
        if previous is None or str(item.get("effectiveStartDate") or "") > str(previous.get("effectiveStartDate") or ""):
            latest[name] = item
    prices: dict[str, Any] = {"currency": currency, "region": region, "payg_per_gb": None, "basic_per_gb": None,
                              "commitment_tiers": {}}
    for name, item in latest.items():
        price, unit = item.get("retailPrice"), str(item.get("unitOfMeasure") or "")
        if not isinstance(price, (int, float)) or price <= 0:
            continue
        tier = _TIER.match(name)
        if name == "Pay-as-you-go Analysis" and unit == "1 GB":
            prices["payg_per_gb"] = float(price)
        elif name == "Basic Logs Analysis" and unit == "1 GB":
            prices["basic_per_gb"] = float(price)
        elif tier and unit == "1/Day":
            prices["commitment_tiers"][tier.group(1)] = float(price)
    return prices


def fetch_prices(http: HttpClient, region: str, currency: str = "USD") -> dict[str, Any]:
    """Public list prices for Microsoft Sentinel in a region. No authentication."""
    if not re.fullmatch(r"[a-z0-9]+", region) or not re.fullmatch(r"[A-Z]{3}", currency):
        raise ValueError("region must look like 'eastus' and currency like 'USD'")
    odata = f"serviceName eq 'Sentinel' and armRegionName eq '{region}' and priceType eq 'Consumption'"
    # "$filter" is kept literal (not percent-encoded), as in Microsoft's own examples.
    url: str | None = (f"{RETAIL_PRICES_URL}?currencyCode={urllib.parse.quote(repr(currency))}"
                       f"&$filter={urllib.parse.quote(odata)}")
    items: list[dict] = []
    while url:
        # Paging links come back as https://prices.azure.com:443/..., which is the same origin.
        # No credentials are sent here, but the tool still only talks to the one host.
        if not same_origin(url, RETAIL_PRICES_URL):
            raise HttpError(0, "refusing to follow a paging link to another host")
        data = http.request("GET", url, ok=(200,)).json() or {}
        items.extend(data.get("Items") or [])
        url = str(data.get("NextPageLink") or "").strip().replace(" ", "%20") or None
        if len(items) > 20000:  # the Sentinel filter returns a few dozen items; never loop forever
            raise HttpError(0, "the price list did not end")
    prices = parse_prices(items, region, currency)
    prices["source"] = f"Azure Retail Prices API, list prices on {iso(utcnow())[:10]}"
    return prices


# --------------------------------------------------------------------------------------------- collection

def _workspace(reader: AzureReader, workspace_id: str) -> dict[str, Any]:
    data = reader.arm_get(workspace_id, "2023-09-01")
    props = data.get("properties") or {}
    sku = props.get("sku") or {}
    cap = (props.get("workspaceCapping") or {}).get("dailyQuotaGb")
    return {"id": data.get("id") or workspace_id, "name": data.get("name") or workspace_id.rsplit("/", 1)[-1],
            "location": str(data.get("location") or "").lower().replace(" ", ""),
            "customer_id": props.get("customerId") or "", "sku": sku.get("name") or "",
            "capacity_reservation_gb": sku.get("capacityReservationLevel"),
            "retention_days": props.get("retentionInDays"),
            "daily_cap_gb": cap if isinstance(cap, (int, float)) and cap > 0 else None}


def _tables(reader: AzureReader, workspace_id: str) -> list[dict[str, Any]]:
    return [{"name": t.get("name", ""), "plan": (t.get("properties") or {}).get("plan") or "Analytics",
             "retention_days": (t.get("properties") or {}).get("retentionInDays"),
             "total_retention_days": (t.get("properties") or {}).get("totalRetentionInDays")}
            for t in reader.arm_list(f"{workspace_id}/tables", "2022-10-01")]


def _rules(reader: AzureReader, workspace_id: str) -> list[dict[str, Any]]:
    path = f"{workspace_id}/providers/Microsoft.SecurityInsights/alertRules"
    return [{"name": (r.get("properties") or {}).get("displayName") or r.get("name", ""), "kind": r.get("kind", ""),
             "enabled": bool((r.get("properties") or {}).get("enabled")),
             "query": (r.get("properties") or {}).get("query") or ""}
            for r in reader.arm_list(path, "2024-03-01")]


def _usage(reader: AzureReader, customer_id: str, days: int) -> list[dict[str, Any]]:
    rows = []
    for row in reader.log_query(customer_id, usage_query(days)):
        date, table = str(row.get("Day") or "")[:10], str(row.get("DataType") or "").strip()
        if not table or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
            continue  # a record with no table name or day cannot be attributed to anything
        rows.append({"date": date, "table": table,
                     "billable_gb": round(max(0.0, float(row.get("BillableMB") or 0)) / 1000.0, 6),
                     "total_gb": round(max(0.0, float(row.get("TotalMB") or 0)) / 1000.0, 6)})
    return rows


def collect(reader: AzureReader, workspace_id: str, *, days: int = 30, currency: str = "USD",
            prices_http: HttpClient | None = None, log: Log = lambda _m: None) -> dict[str, Any]:
    """Collect the snapshot. Raises HttpError only if the workspace itself cannot be read."""
    if not WORKSPACE_ID.match(workspace_id):
        raise ValueError("workspace must be a full resource ID: /subscriptions/<id>/resourceGroups/<rg>/providers/"
                         "Microsoft.OperationalInsights/workspaces/<name>")
    workspace = _workspace(reader, workspace_id)
    log(f"workspace {workspace['name']} in {workspace['location']}, pricing {workspace['sku'] or 'unknown'}")
    snapshot: dict[str, Any] = {"kind": "sentinel", "captured_at": iso(utcnow()), "days": days, "workspace": workspace, "usage": None,
                                "tables": None, "rules": None, "prices": None, "errors": {}}

    def section(key: str, fn: Callable[[], Any], hint: str) -> None:
        try:
            snapshot[key] = fn()
        except (HttpError, ValueError) as exc:
            denied = isinstance(exc, HttpError) and exc.status in (401, 403)
            snapshot["errors"][key] = f"{exc} ({hint})" if denied else str(exc)
            log(f"{key}: skipped ({exc})")

    role = "assign Microsoft Sentinel Reader or Log Analytics Reader on the workspace"
    section("usage", lambda: _usage(reader, workspace["customer_id"], days), role)
    section("tables", lambda: _tables(reader, workspace_id), role)
    section("rules", lambda: _rules(reader, workspace_id), role)
    section("prices", lambda: fetch_prices(prices_http or reader.http, workspace["location"], currency),
            "the Azure Retail Prices API is public")
    if snapshot["prices"] is not None and not snapshot["prices"].get("payg_per_gb"):
        snapshot["errors"]["prices"] = (f"no Microsoft Sentinel prices published for region "
                                        f"'{workspace['location']}' in {currency}; pass --price-per-gb")
        snapshot["prices"] = None
    return snapshot
