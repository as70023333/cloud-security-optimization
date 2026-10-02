"""Turn a Sentinel snapshot into numbers and savings opportunities. Pure functions, no network."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from secopt.core.model import Opportunity, is_currency, is_number, money, rank

AREA = "sentinel"
# Plans billed per GB at the Sentinel price and counted toward a commitment tier. A table whose plan
# could not be read is treated as Analytics, the default.
ANALYTICS_PLANS = ("Analytics", "unknown")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# Tables that Sentinel features read without an analytics rule (UEBA, incidents, watchlists, health),
# so "no rule reads it" says nothing about their value.
FEATURE_TABLES = frozenset({
    "SecurityAlert", "SecurityIncident", "Watchlist", "IdentityInfo", "BehaviorAnalytics", "UserPeerAnalytics",
    "UserAccessAnalytics", "Anomalies", "SentinelHealth", "SentinelAudit", "Usage", "Heartbeat", "Operation",
    "LAQueryLogs", "ThreatIntelIndicators", "ThreatIntelligenceIndicator", "ThreatIntelObjects",
})
# Where the volume in the usual heavy tables comes from, and the standard way to cut it.
TABLE_TIPS: dict[str, str] = {
    "SecurityEvent": "Collect the Common or Minimal event set instead of All Events, and filter noisy event IDs "
                     "in the data collection rule.",
    "Syslog": "Filter facilities and severities in the data collection rule; drop debug and info from chatty daemons.",
    "CommonSecurityLog": "Filter allowed-traffic and informational firewall logs at the source or with a "
                         "data collection rule transformation.",
    "AzureDiagnostics": "Send only the diagnostic categories you use, and move resources to resource-specific tables.",
    "AADNonInteractiveUserSignInLogs": "Use a workspace transformation to drop columns you do not query; this table "
                                       "is usually several times larger than interactive sign-ins.",
    "DeviceNetworkEvents": "Defender XDR already keeps 30 days for hunting; stream this table only if detections "
                           "or long retention need it.",
    "DeviceFileEvents": "Defender XDR already keeps 30 days for hunting; stream this table only if detections "
                        "or long retention need it.",
    "DeviceProcessEvents": "Defender XDR already keeps 30 days for hunting; stream this table only if detections "
                           "or long retention need it.",
    "DeviceEvents": "Defender XDR already keeps 30 days for hunting; stream this table only if detections "
                    "or long retention need it.",
    "ContainerLogV2": "Filter namespaces in the Container Insights settings; application logs rarely need the "
                      "Analytics plan.",
    "AzureActivity": "Azure Activity logs are free to ingest in Microsoft Sentinel.",
    "StorageBlobLogs": "Storage data-plane logs are very high volume; keep them on a cheaper plan unless a "
                       "detection needs them.",
    "AWSCloudTrail": "Exclude data events and read-only management events you do not detect on.",
    "W3CIISLog": "Web server logs are high volume; collect only the sites you detect on.",
}


@dataclass
class SentinelConfig:
    min_table_gb_per_day: float = 0.5   # ignore tables smaller than this in opportunities
    spike_ratio: float = 1.5            # last 7 days vs the days before
    spike_min_gb_per_day: float = 0.5
    free_retention_days: int = 90       # interactive retention included with Sentinel
    price_per_gb: float | None = None   # override the pay-as-you-go list price (e.g. your negotiated rate)
    max_table_opportunities: int = 10

    def __post_init__(self) -> None:
        if self.spike_ratio <= 1:
            raise ValueError("spike_ratio must be greater than 1")
        if self.price_per_gb is not None and not is_number(self.price_per_gb, 1e-6, 1e6):
            raise ValueError("the price per GB must be a number greater than 0 (and below 1,000,000)")


@dataclass
class SentinelReport:
    totals: dict[str, Any]
    tables: list[dict[str, Any]]
    pricing_options: list[dict[str, Any]]
    opportunities: list[Opportunity]
    notes: list[str] = field(default_factory=list)


def daily_cost(gb: float, tier_gb: int | None, payg: float, tiers: dict[int, float]) -> float:
    """Cost of one day. Pay-as-you-go bills per GB; a commitment tier bills its daily price, with
    anything above the tier billed at the tier's own effective per-GB rate."""
    if tier_gb is None:
        return gb * payg
    price = tiers[tier_gb]
    return price + max(0.0, gb - tier_gb) * (price / tier_gb)


def _plan_label(tier_gb: int | None) -> str:
    return "Pay-as-you-go" if tier_gb is None else f"{tier_gb} GB/day commitment tier"


def tables_read_by_rules(rules: list[dict[str, Any]], table_names: list[str]) -> dict[str, int]:
    """How many enabled analytics rules mention each table (whole-word match in the rule's query)."""
    queries = [r.get("query") or "" for r in rules if r.get("enabled") and r.get("query")]
    counts = {}
    for name in table_names:
        pattern = re.compile(rf"(?<![\w.]){re.escape(name)}(?!\w)")
        counts[name] = sum(1 for q in queries if pattern.search(q))
    return counts


def _usage_rows(usage: Any) -> list[tuple[str, str, float, float]]:
    """Validate usage rows: (date, table, billable GB, total GB). A snapshot can be edited by hand
    or come from someone else, so a bad row is a clear error rather than a wrong report."""
    rows = []
    for n, row in enumerate(usage, start=1):
        date, table = (row.get("date"), row.get("table")) if isinstance(row, dict) else (None, None)
        billable = row.get("billable_gb") if isinstance(row, dict) else None
        total = row.get("total_gb", billable) if isinstance(row, dict) else None
        numbers_ok = is_number(billable) and is_number(total)
        if not (isinstance(date, str) and _DATE.match(date) and isinstance(table, str) and table and numbers_ok):
            raise ValueError(f"usage row {n} is not valid: it needs a date (YYYY-MM-DD), a table name and "
                             "billable_gb as a number")
        rows.append((date, table, float(billable), float(total)))
    return rows


def _price(value: Any) -> float | None:
    return float(value) if is_number(value, 1e-6, 1e6) else None


def analyze(snapshot: dict[str, Any], cfg: SentinelConfig | None = None) -> SentinelReport:
    cfg = cfg or SentinelConfig()
    usage = snapshot.get("usage")
    if not usage or not isinstance(usage, list):
        reason = (snapshot.get("errors") or {}).get("usage", "the Usage table returned no rows")
        raise ValueError(f"no ingestion data to analyse: {reason}")
    rows = _usage_rows(usage)
    workspace = snapshot.get("workspace") or {}
    notes = [f"{key}: {message}" for key, message in sorted((snapshot.get("errors") or {}).items())]
    table_meta = {t["name"]: t for t in snapshot.get("tables") or [] if isinstance(t, dict) and t.get("name")}

    def plan_of(table: str) -> str:
        return str(table_meta.get(table, {}).get("plan") or "unknown")

    # ---- volume ---------------------------------------------------------------------------
    # Only Analytics-plan data is billed at the Sentinel price and counts toward a commitment
    # tier. Basic-plan data has its own price; other plans are reported by volume only.
    by_day: dict[str, float] = defaultdict(float)          # Analytics plan
    basic_by_day: dict[str, float] = defaultdict(float)
    other_total = 0.0
    by_table_day: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    total_by_table: dict[str, float] = defaultdict(float)
    all_days: set[str] = set()
    for date, table, billable, total in rows:
        all_days.add(date)
        by_table_day[table][date] += billable
        total_by_table[table] += total
        plan = plan_of(table)
        if plan in ANALYTICS_PLANS:
            by_day[date] += billable
        elif plan == "Basic":
            basic_by_day[date] += billable
        else:
            other_total += billable
    days = sorted(all_days)
    n_days = len(days)
    billable_total = sum(sum(series.values()) for series in by_table_day.values())
    avg_daily = sum(by_day.values()) / n_days
    peak_daily = max(by_day.get(d, 0.0) for d in days)
    basic_daily = sum(basic_by_day.values()) / n_days
    other_daily = other_total / n_days

    # ---- pricing --------------------------------------------------------------------------
    prices = snapshot.get("prices") or {}
    currency = prices.get("currency") or "USD"
    if not is_currency(currency):
        raise ValueError("the currency in the snapshot's prices must be a three-letter code such as USD")
    currency = currency.upper()
    payg = cfg.price_per_gb or _price(prices.get("payg_per_gb"))
    tiers = {}
    for level, price in (prices.get("commitment_tiers") or {}).items():
        if str(level).isdigit() and 0 < int(level) <= 1_000_000 and _price(price):
            tiers[int(level)] = float(price)
    basic = _price(prices.get("basic_per_gb"))
    if cfg.price_per_gb:
        notes.append(f"pricing: using your price of {money(cfg.price_per_gb, currency)} per GB for pay-as-you-go; "
                     "commitment tiers use list prices.")
    elif payg:
        notes.append(f"pricing: {prices.get('source', 'list prices')}; your agreement may differ "
                     "(use --price-per-gb).")

    current_tier: int | None = None
    if str(workspace.get("sku") or "").lower() == "capacityreservation":
        level = workspace.get("capacity_reservation_gb")
        current_tier = int(level) if is_number(level, 1, 1_000_000) else None
        if current_tier is not None and current_tier not in tiers and payg:
            notes.append(f"pricing: the workspace is on a {current_tier} GB/day commitment tier that has no "
                         "published price; costs are shown at pay-as-you-go rates.")
            current_tier = None

    def monthly(tier_gb: int | None) -> float:
        return sum(daily_cost(by_day.get(d, 0.0), tier_gb, payg, tiers) for d in days) / n_days * 30

    pricing_options: list[dict[str, Any]] = []
    analytics_monthly = effective_rate = None
    opportunities: list[Opportunity] = []
    if payg:
        analytics_monthly = monthly(current_tier)
        effective_rate = analytics_monthly / (avg_daily * 30) if avg_daily else payg
        for option in [None, *sorted(tiers)]:
            pricing_options.append({"plan": _plan_label(option), "tier_gb": option, "monthly_cost": round(monthly(option), 2),
                                    "current": option == current_tier})
        best = min(pricing_options, key=lambda o: o["monthly_cost"])
        saving = analytics_monthly - best["monthly_cost"]
        if not best["current"] and saving >= max(10.0, 0.01 * analytics_monthly):
            opportunities.append(Opportunity(
                "pricing-tier", AREA, f"Switch to {best['plan']}",
                f"Ingestion that counts toward a commitment tier averages {avg_daily:,.1f} GB/day "
                f"(peak {peak_daily:,.1f}). {_plan_label(current_tier)} costs about "
                f"{money(analytics_monthly, currency)} a month; {best['plan']} would cost about "
                f"{money(best['monthly_cost'], currency)}.",
                "Change the pricing tier under Microsoft Sentinel > Settings > Pricing. A commitment tier is "
                "fixed for 31 days, so check that the volume is steady first.",
                saving, "low", {"current": _plan_label(current_tier), "recommended": best["plan"]}))
    else:
        notes.append("pricing: no price available, so the report shows volumes only. Pass --price-per-gb.")

    basic_monthly = basic_daily * 30 * basic if basic and payg else None
    if basic_daily and payg and not basic:
        notes.append(f"pricing: {basic_daily:,.1f} GB/day is in Basic-plan tables and no Basic price is available, "
                     "so its cost is not included.")
    if other_daily:
        notes.append(f"pricing: {other_daily:,.1f} GB/day is in tables on a plan this tool does not price "
                     "(for example Auxiliary); it is shown by volume and left out of the cost.")
    monthly_cost = None if analytics_monthly is None else analytics_monthly + (basic_monthly or 0.0)

    def rate_for(plan: str) -> float | None:
        """Average price per GB for a table on this plan: its share of the bill."""
        if plan in ANALYTICS_PLANS:
            return effective_rate
        return basic if plan == "Basic" and payg else None

    # What one GB less would save. On a commitment tier that is larger than the ingestion, the
    # average price per GB is above pay-as-you-go, but nobody can save more than the pay-as-you-go
    # price by removing a GB (they would drop the tier first), so savings are capped there.
    saving_rate = min(effective_rate, payg) if effective_rate and payg else None

    def saving_rate_for(plan: str) -> float | None:
        return saving_rate if plan in ANALYTICS_PLANS else rate_for(plan)

    # ---- tables ---------------------------------------------------------------------------
    rules = snapshot.get("rules")
    if rules is not None and not isinstance(rules, list):
        raise ValueError("the snapshot's 'rules' section is not a list")
    names = sorted(by_table_day)
    rule_counts = tables_read_by_rules([r for r in rules if isinstance(r, dict)], names) if rules is not None else {}
    recent_days, earlier_days = days[-7:], days[:-7]
    if len(earlier_days) < 7:
        notes.append(f"trend: only {n_days} day(s) of data, so growth cannot be measured. "
                     "Analyse 14 days or more (--days).")
    tables: list[dict[str, Any]] = []
    for name in names:
        series = by_table_day[name]
        billable = sum(series.values())
        per_day = billable / n_days
        meta = table_meta.get(name, {})
        plan = plan_of(name)
        rate = rate_for(plan)
        trend = None
        recent_avg = previous_avg = None
        if len(earlier_days) >= 7:
            recent_avg = sum(series.get(d, 0.0) for d in recent_days) / len(recent_days)
            previous_avg = sum(series.get(d, 0.0) for d in earlier_days) / len(earlier_days)
            if previous_avg > 0:
                trend = round((recent_avg - previous_avg) / previous_avg * 100, 1)
        retention = meta.get("retention_days")
        tables.append({
            "table": name, "billable_gb": round(billable, 2), "gb_per_day": round(per_day, 3),
            "share_pct": round(billable / billable_total * 100, 1) if billable_total else 0.0,
            "free_gb": round(max(0.0, total_by_table[name] - billable), 2),
            "monthly_cost": round(per_day * 30 * rate, 2) if rate else None,
            "plan": plan, "retention_days": retention if isinstance(retention, int) and not isinstance(retention, bool) else None,
            "rules": rule_counts.get(name) if rules is not None else None,
            "trend_pct": trend, "recent_gb_per_day": recent_avg, "previous_gb_per_day": previous_avg,
            "tip": TABLE_TIPS.get(name, ""),
        })
    tables.sort(key=lambda t: (-t["billable_gb"], t["table"]))

    significant = [t for t in tables if t["gb_per_day"] >= cfg.min_table_gb_per_day]

    # Paid for, but no detection reads it.
    if rules is not None:
        unread = [t for t in significant if t["rules"] == 0 and t["plan"] in ANALYTICS_PLANS
                  and t["table"] not in FEATURE_TABLES]
        if len(unread) > cfg.max_table_opportunities:
            notes.append(f"tables: {len(unread)} tables have no analytics rule reading them; the "
                         f"{cfg.max_table_opportunities} largest are listed as opportunities, the rest are in the "
                         "tables list (Rules = 0).")
        for t in unread[: cfg.max_table_opportunities]:
            saving = None
            upper = ""
            if saving_rate and basic and saving_rate > basic:
                saving = t["gb_per_day"] * 30 * (saving_rate - basic)
                upper = (f" Up to {money(saving, currency)} a month if the table can move to the Basic plan "
                         f"({money(basic, currency)} per GB); not every table supports it.")
            cost = f", about {money(t['monthly_cost'], currency)} a month" if t["monthly_cost"] is not None else ""
            tip = f" {t['tip']}" if t["tip"] else ""
            opportunities.append(Opportunity(
                f"unread-table:{t['table']}", AREA, f"No analytics rule reads {t['table']}",
                f"{t['gb_per_day']:,.1f} GB/day of billable data{cost}, and no enabled analytics rule queries "
                f"it.{upper}",
                "Decide what the table is for. If it is only for investigation or compliance, move it to a cheaper "
                f"plan or reduce what is collected; if it should be detected on, write the rules.{tip}",
                saving, "medium", {"table": t["table"], "gb_per_day": t["gb_per_day"]}, additive=False))

    # Sudden growth. Judged on the last 7 days, so a table that only just appeared is caught even
    # though its average over the whole period is still small.
    for t in tables:
        recent, previous = t["recent_gb_per_day"], t["previous_gb_per_day"]
        if recent is None or previous is None:
            continue
        grew = recent - previous
        if grew >= cfg.spike_min_gb_per_day and (previous == 0 or recent / previous >= cfg.spike_ratio):
            rate = saving_rate_for(t["plan"])
            opportunities.append(Opportunity(
                f"spike:{t['table']}", AREA, f"{t['table']} ingestion jumped",
                f"The last 7 days average {recent:,.1f} GB/day against {previous:,.1f} GB/day before"
                + (f" (+{t['trend_pct']:.0f}%)." if t["trend_pct"] is not None else " (new table)."),
                "Find the source: summarize _BilledSize by Computer or _ResourceId in this table for the last "
                "7 days. If the increase is not intended, fix the source or filter it in the data collection rule.",
                grew * 30 * rate if rate else None, "low",
                {"table": t["table"], "recent_gb_per_day": round(recent, 2), "previous_gb_per_day": round(previous, 2)},
                additive=False))

    # Long interactive retention.
    long_retention = [t for t in significant if t["plan"] == "Analytics"
                      and t["retention_days"] is not None and t["retention_days"] > cfg.free_retention_days]
    if long_retention:
        listed = ", ".join(f"{t['table']} ({t['retention_days']} days)" for t in long_retention[:8])
        more = f" and {len(long_retention) - 8} more" if len(long_retention) > 8 else ""
        opportunities.append(Opportunity(
            "long-retention", AREA, f"Interactive retention longer than {cfg.free_retention_days} days",
            f"Sentinel includes {cfg.free_retention_days} days of interactive retention; beyond that every GB is "
            f"billed monthly. Tables above it: {listed}{more}.",
            f"Keep interactive retention at {cfg.free_retention_days} days and use long-term (total) retention for "
            "older data; it costs a fraction and can still be searched or restored.",
            None, "low", {"tables": [t["table"] for t in long_retention]}))

    cap = workspace.get("daily_cap_gb")
    totals = {
        "workspace": workspace.get("name"), "region": workspace.get("location"), "currency": currency,
        "days_analysed": n_days, "first_day": days[0], "last_day": days[-1],
        "billable_gb": round(billable_total, 2), "gb_per_day": round(avg_daily, 2), "peak_gb_per_day": round(peak_daily, 2),
        "basic_gb_per_day": round(basic_daily, 2), "other_plan_gb_per_day": round(other_daily, 2),
        "free_gb": round(sum(t["free_gb"] for t in tables), 2),
        "current_plan": _plan_label(current_tier), "price_per_gb": payg,
        "monthly_cost": round(monthly_cost, 2) if monthly_cost is not None else None,
        "analytics_monthly_cost": round(analytics_monthly, 2) if analytics_monthly is not None else None,
        "basic_monthly_cost": round(basic_monthly, 2) if basic_monthly is not None else None,
        "effective_price_per_gb": round(effective_rate, 3) if effective_rate else None,
        "tables_with_billable_data": sum(1 for t in tables if t["billable_gb"] > 0),
        "daily_cap_gb": cap if is_number(cap, 1e-9) else None,
    }
    for t in tables:  # helper values used only for the spike check
        t.pop("recent_gb_per_day"), t.pop("previous_gb_per_day")
    return SentinelReport(totals, tables, pricing_options, rank(opportunities), notes)
