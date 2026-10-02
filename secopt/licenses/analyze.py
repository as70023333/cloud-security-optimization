"""Find licences that are paid for and not used. Pure functions, no network.

Four kinds of waste, each licence counted once:
* unassigned    bought, assigned to nobody
* disabled      assigned to an account that is disabled
* inactive      assigned to an enabled account that has not signed in for N days
* duplicate     a standalone product assigned to someone whose suite already includes it

"Includes" is worked out from the tenant's own data: product B is covered by product A when every
user-level service plan in B is also in A. No hard-coded product tables to go stale.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from secopt.core.model import Opportunity, rank
from secopt.core.timeutil import days_between, parse_time

AREA = "licenses"
# Common security-relevant products, for readable names. Unknown products show their part number.
PRODUCT_NAMES: dict[str, str] = {
    "SPE_E5": "Microsoft 365 E5", "SPE_E3": "Microsoft 365 E3", "SPB": "Microsoft 365 Business Premium",
    "ENTERPRISEPREMIUM": "Office 365 E5", "ENTERPRISEPACK": "Office 365 E3",
    "EMSPREMIUM": "Enterprise Mobility + Security E5", "EMS": "Enterprise Mobility + Security E3",
    "IDENTITY_THREAT_PROTECTION": "Microsoft 365 E5 Security",
    "INFORMATION_PROTECTION_COMPLIANCE": "Microsoft 365 E5 Compliance",
    "AAD_PREMIUM": "Microsoft Entra ID P1", "AAD_PREMIUM_P2": "Microsoft Entra ID P2",
    "WIN_DEF_ATP": "Microsoft Defender for Endpoint P2", "DEFENDER_ENDPOINT_P1": "Microsoft Defender for Endpoint P1",
    "ATP_ENTERPRISE": "Microsoft Defender for Office 365 Plan 1",
    "THREAT_INTELLIGENCE": "Microsoft Defender for Office 365 Plan 2",
    "ATA": "Microsoft Defender for Identity", "ADALLOM_STANDALONE": "Microsoft Defender for Cloud Apps",
    "INTUNE_A": "Microsoft Intune Plan 1",
}
# Free, trial or self-service products whose "purchased" count is not a cost.
FREE_PRODUCTS = frozenset({
    "FLOW_FREE", "POWER_BI_STANDARD", "TEAMS_EXPLORATORY", "WINDOWS_STORE", "STREAM", "POWERAPPS_VIRAL",
    "POWERAPPS_DEV", "CCIBOTS_PRIVPREV_VIRAL", "MICROSOFT_BUSINESS_CENTER", "RIGHTSMANAGEMENT_ADHOC",
    "DYN365_ENTERPRISE_VIRTUAL_AGENT_VIRAL", "Microsoft_Teams_Exploratory_Dept", "POWER_PAGES_VTRIAL_FOR_MAKERS",
})


@dataclass
class LicenseConfig:
    prices: dict[str, float] = field(default_factory=dict)  # part number -> price per user per month
    currency: str = "USD"
    inactive_days: int = 90
    now: datetime | None = None

    def __post_init__(self) -> None:
        if self.inactive_days < 1:
            raise ValueError("inactive_days must be at least 1")
        for part, price in self.prices.items():
            if not isinstance(price, (int, float)) or isinstance(price, bool) or not math.isfinite(price) or price < 0:
                raise ValueError(f"price for {part} must be a non-negative number")


@dataclass
class LicenseReport:
    totals: dict[str, Any]
    products: list[dict[str, Any]]
    opportunities: list[Opportunity]
    notes: list[str] = field(default_factory=list)


def product_name(part_number: str) -> str:
    return PRODUCT_NAMES.get(part_number, part_number)


def coverage(skus: list[dict[str, Any]]) -> dict[str, set[str]]:
    """sku_id -> ids of the other products that include everything it contains."""
    plans = {s["sku_id"]: set(s.get("service_plans") or []) for s in skus}
    covered: dict[str, set[str]] = {}
    for small, small_plans in plans.items():
        if not small_plans:
            continue
        covered[small] = {big for big, big_plans in plans.items()
                          if big != small and small_plans < big_plans}
    return covered


def _count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _checked_skus(skus: Any) -> list[dict[str, Any]]:
    """A snapshot can be edited by hand or come from someone else: a bad entry is a clear error."""
    if not isinstance(skus, list):
        raise ValueError("the snapshot's 'skus' section is not a list")
    for n, sku in enumerate(skus, start=1):
        if not (isinstance(sku, dict) and isinstance(sku.get("sku_id"), str) and sku["sku_id"]
                and isinstance(sku.get("part_number"), str) and _count(sku.get("purchased"))
                and _count(sku.get("assigned")) and isinstance(sku.get("service_plans") or [], list)):
            raise ValueError(f"product {n} in the snapshot is not valid: it needs sku_id, part_number, and "
                             "purchased and assigned as whole numbers")
    return skus


def _checked_users(users: Any) -> list[dict[str, Any]] | None:
    if users is None:
        return None
    if not isinstance(users, list):
        raise ValueError("the snapshot's 'users' section is not a list")
    for n, user in enumerate(users, start=1):
        if not (isinstance(user, dict) and isinstance(user.get("upn"), str)
                and isinstance(user.get("sku_ids"), list) and all(isinstance(s, str) for s in user["sku_ids"])):
            raise ValueError(f"user {n} in the snapshot is not valid: it needs upn and a list of sku_ids")
    return users


def analyze(snapshot: dict[str, Any], cfg: LicenseConfig | None = None) -> LicenseReport:
    cfg = cfg or LicenseConfig()
    now = cfg.now or parse_time(snapshot.get("captured_at"))
    if now is None:
        raise ValueError("snapshot has no captured_at and no 'now' was given")
    skus = [s for s in _checked_skus(snapshot.get("skus")) if s.get("applies_to", "User") != "Company"]
    by_id = {s["sku_id"]: s for s in skus}
    notes = [f"{key}: {message}" for key, message in sorted((snapshot.get("errors") or {}).items())]
    priced = {s["sku_id"]: cfg.prices[s["part_number"]] for s in skus if s["part_number"] in cfg.prices}
    if not cfg.prices:
        notes.append("prices: no price file given, so the report counts licences but cannot value them. "
                     "Pass --prices with your agreement's prices.")
    else:
        unmatched = sorted(set(cfg.prices) - {s["part_number"] for s in skus})
        if unmatched:
            notes.append(f"prices: no product in this tenant has the part number {', '.join(unmatched)}. "
                         "That is expected for products you do not own; otherwise check the spelling against "
                         "the part_number column.")

    def paid(sku_id: str) -> bool:
        sku = by_id[sku_id]
        return sku["part_number"] not in FREE_PRODUCTS and priced.get(sku_id, 1) > 0

    # ---- classify every assigned licence once ---------------------------------------------
    users = _checked_users(snapshot.get("users"))
    activity = bool(snapshot.get("sign_in_activity_available"))
    covered_by = coverage(skus)
    reclaim: dict[str, dict[str, list[str]]] = {"disabled": defaultdict(list), "inactive": defaultdict(list),
                                               "duplicate": defaultdict(list)}
    duplicate_of: dict[str, set[str]] = defaultdict(set)
    for user in users or []:
        held = [s for s in user.get("sku_ids", []) if s in by_id and paid(s)]
        last = parse_time(user.get("last_sign_in"))
        created = parse_time(user.get("created"))
        stale = False
        if activity and user.get("enabled"):
            reference = last or created
            stale = reference is not None and days_between(now, reference) >= cfg.inactive_days
        for sku_id in held:
            if not user.get("enabled"):
                reclaim["disabled"][sku_id].append(user["upn"])
            elif stale:
                reclaim["inactive"][sku_id].append(user["upn"])
            else:
                suites = covered_by.get(sku_id, set()) & set(held)
                if suites:
                    reclaim["duplicate"][sku_id].append(user["upn"])
                    duplicate_of[sku_id] |= suites

    # ---- per product ----------------------------------------------------------------------
    products: list[dict[str, Any]] = []
    for sku in skus:
        sku_id, part = sku["sku_id"], sku["part_number"]
        unused = max(0, sku["purchased"] - sku["assigned"])
        price = priced.get(sku_id)
        free = not paid(sku_id)  # a known free product, or one you priced at 0
        counts = {kind: len(reclaim[kind].get(sku_id, [])) for kind in reclaim}
        wasted = (0 if free else unused) + sum(counts.values())
        products.append({
            "product": product_name(part), "part_number": part, "purchased": sku["purchased"],
            "assigned": sku["assigned"], "unassigned": unused, "disabled": counts["disabled"],
            "inactive": counts["inactive"], "duplicate": counts["duplicate"], "free": free,
            "price": price, "monthly_waste": round(wasted * price, 2) if price is not None else None,
            "over_assigned": max(0, sku["assigned"] - sku["purchased"]), "status": sku.get("status", ""),
        })
    products.sort(key=lambda p: (p["monthly_waste"] is None, -(p["monthly_waste"] or 0), p["product"]))

    # ---- opportunities --------------------------------------------------------------------
    opportunities: list[Opportunity] = []

    def value(sku_id: str, count: int) -> float | None:
        return count * priced[sku_id] if sku_id in priced else None

    for sku in skus:
        sku_id, part = sku["sku_id"], sku["part_number"]
        name = product_name(part)
        unused = max(0, sku["purchased"] - sku["assigned"])
        if unused and paid(sku_id):
            share = unused / sku["purchased"] * 100 if sku["purchased"] else 0
            opportunities.append(Opportunity(
                f"unassigned:{part}", AREA, f"{unused} unassigned {name} licence(s)",
                f"{sku['purchased']} purchased, {sku['assigned']} assigned ({share:.0f}% unused).",
                "Reduce the quantity at the next renewal or true-up, or assign them if people are waiting.",
                value(sku_id, unused), "low", {"part_number": part, "unassigned": unused}))
        for kind, title, detail, action, effort in (
            ("disabled", "{n} {name} licence(s) on disabled accounts",
             "Disabled accounts keep their licences until someone removes them.",
             "Remove the licences (use group-based licensing so it happens automatically when an account is disabled).",
             "low"),
            ("inactive", "{n} {name} licence(s) on accounts with no sign-in for {days} days",
             "These accounts are enabled but nobody has signed in.",
             "Confirm with the owner or manager, then disable the account and reclaim the licence.", "medium"),
            ("duplicate", "{n} {name} licence(s) duplicate a suite the user already has",
             "Each of these users also holds {suites}, which includes everything in this product.",
             "Remove the standalone licence from these users and reduce the count at renewal.", "low"),
        ):
            who = reclaim[kind].get(sku_id, [])
            if not who:
                continue
            suites = ", ".join(sorted(product_name(by_id[s]["part_number"]) for s in duplicate_of.get(sku_id, ())))
            opportunities.append(Opportunity(
                f"{kind}:{part}", AREA, title.format(n=len(who), name=name, days=cfg.inactive_days),
                detail.format(suites=suites) + " Examples: " + ", ".join(sorted(who)[:5])
                + (f" and {len(who) - 5} more." if len(who) > 5 else "."),
                action, value(sku_id, len(who)), effort,
                {"part_number": part, "count": len(who), "users": sorted(who)}))

    over = [p for p in products if p["over_assigned"]]
    for p in over:
        notes.append(f"{p['product']}: {p['over_assigned']} more assigned than purchased (grace period or "
                     "expired subscription); check before it is enforced.")
    if users is not None and not activity:
        notes.append("inactive accounts: not checked because sign-in activity was not available.")
    quantified = [o.monthly_saving for o in opportunities if o.monthly_saving is not None]
    totals = {
        "currency": cfg.currency, "products": len(products),
        "paid_products": sum(1 for p in products if not p["free"]),
        "licensed_users": len(users) if users is not None else None,
        "unassigned": sum(p["unassigned"] for p in products if not p["free"]),
        "on_disabled_accounts": sum(p["disabled"] for p in products),
        "on_inactive_accounts": sum(p["inactive"] for p in products),
        "duplicates": sum(p["duplicate"] for p in products),
        "monthly_waste": round(sum(quantified), 2) if quantified else None,
        "inactive_days": cfg.inactive_days,
    }
    return LicenseReport(totals, products, rank(opportunities), notes)
