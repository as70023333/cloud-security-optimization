"""Analyse a security tool inventory: overlaps, redundant tools and gaps. Pure functions, no network.

The inventory is a TOML file you maintain (see examples/security-stack.toml):

    currency = "USD"
    required = ["pam"]          # optional: capabilities you need beyond the baseline
    not_required = ["ztna"]     # optional: baseline capabilities that do not apply to you

    [[tool]]
    name = "Example EDR"
    vendor = "Example"
    annual_cost = 48000         # what you pay for it on its own; 0 or omitted if bundled
    bundled_with = ""           # the licence it comes with, if it has no separate cost
    capabilities = ["antivirus", "edr"]
    notes = "renews in March"
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from secopt.core.model import Opportunity, is_currency, is_number, money, rank
from secopt.overlap.capabilities import BASELINE, CAPABILITIES, DOMAINS

AREA = "overlap"
INVENTORY_KEYS = {"currency", "required", "not_required", "tool"}
TOOL_KEYS = {"name", "vendor", "annual_cost", "bundled_with", "capabilities", "notes"}


class InventoryError(ValueError):
    """The inventory file is invalid."""


@dataclass
class Tool:
    name: str
    vendor: str
    annual_cost: float
    bundled_with: str
    capabilities: tuple[str, ...]
    notes: str = ""

    @property
    def paid_separately(self) -> bool:
        return self.annual_cost > 0


@dataclass
class Inventory:
    tools: list[Tool]
    currency: str = "USD"
    required: frozenset[str] = BASELINE


@dataclass
class OverlapReport:
    totals: dict[str, Any]
    tools: list[dict[str, Any]]
    matrix: list[dict[str, Any]]          # one row per capability in use or required
    opportunities: list[Opportunity]
    notes: list[str] = field(default_factory=list)


def _strings(value: Any, where: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise InventoryError(f"{where} must be a list of strings")
    return value


def _known(ids: list[str], where: str) -> None:
    unknown = sorted(set(ids) - set(CAPABILITIES))
    if unknown:
        raise InventoryError(f"{where}: unknown capability {', '.join(unknown)}. "
                             "Run 'secopt overlap --list-capabilities' for the vocabulary.")


def parse_inventory(data: dict[str, Any], source: str = "inventory") -> Inventory:
    unknown = set(data) - INVENTORY_KEYS
    if unknown:
        raise InventoryError(f"{source}: unknown key(s) {', '.join(sorted(unknown))}")
    raw_tools = data.get("tool")
    if not isinstance(raw_tools, list) or not raw_tools:
        raise InventoryError(f"{source}: add at least one [[tool]]")
    tools: list[Tool] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_tools, start=1):
        where = f"{source}: tool {index}"
        if not isinstance(raw, dict):
            raise InventoryError(f"{where} must be a table")
        name = raw.get("name")
        if not isinstance(name, str) or not name.strip():
            raise InventoryError(f"{where}: 'name' is required")
        name = " ".join(name.split())  # "Acme EDR " and "Acme  EDR" are the same tool
        where = f"{source}: tool '{name}'"
        extra = set(raw) - TOOL_KEYS
        if extra:
            raise InventoryError(f"{where}: unknown field(s) {', '.join(sorted(extra))}")
        if name.lower() in seen:
            raise InventoryError(f"{where}: listed twice")
        seen.add(name.lower())
        cost = raw.get("annual_cost", 0)
        if not is_number(cost):
            raise InventoryError(f"{where}: annual_cost must be a number, 0 or more")
        capabilities = _strings(raw.get("capabilities"), f"{where}: capabilities")
        if not capabilities:
            raise InventoryError(f"{where}: list at least one capability")
        _known(capabilities, where)
        tools.append(Tool(name, str(raw.get("vendor") or ""), float(cost), str(raw.get("bundled_with") or ""),
                          tuple(dict.fromkeys(capabilities)), str(raw.get("notes") or "")))
    required = _strings(data.get("required"), f"{source}: required")
    not_required = _strings(data.get("not_required"), f"{source}: not_required")
    _known(required, f"{source}: required")
    _known(not_required, f"{source}: not_required")
    currency = data.get("currency", "USD")
    if not is_currency(currency):
        raise InventoryError(f"{source}: currency must be a three-letter code")
    return Inventory(tools, currency.upper(), frozenset((BASELINE | set(required)) - set(not_required)))


def load_inventory(path: Path) -> Inventory:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise InventoryError(f"cannot read {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise InventoryError(f"{path}: {exc}") from exc
    return parse_inventory(data, str(path))


def analyze(inventory: Inventory) -> OverlapReport:
    currency = inventory.currency
    providers: dict[str, list[Tool]] = {}
    for tool in inventory.tools:
        for capability in tool.capabilities:
            providers.setdefault(capability, []).append(tool)

    # ---- capability matrix ----------------------------------------------------------------
    relevant = sorted(set(providers) | inventory.required,
                      key=lambda c: (DOMAINS.index(CAPABILITIES[c].domain), CAPABILITIES[c].name))
    matrix = []
    for capability in relevant:
        tools = providers.get(capability, [])
        status = "gap" if not tools else ("overlap" if len(tools) > 1 else "covered")
        matrix.append({"capability": capability, "name": CAPABILITIES[capability].name,
                       "domain": CAPABILITIES[capability].domain, "required": capability in inventory.required,
                       "tools": [t.name for t in tools], "status": status})

    # ---- per tool: what would be lost if it went away -------------------------------------
    tool_rows: list[dict[str, Any]] = []
    for tool in inventory.tools:
        unique = [c for c in tool.capabilities if len(providers[c]) == 1]
        shared = [c for c in tool.capabilities if len(providers[c]) > 1]
        tool_rows.append({"tool": tool.name, "vendor": tool.vendor, "annual_cost": tool.annual_cost,
                          "bundled_with": tool.bundled_with, "capabilities": len(tool.capabilities),
                          "unique": [CAPABILITIES[c].name for c in unique],
                          "shared": [CAPABILITIES[c].name for c in shared],
                          "fully_redundant": not unique})

    # A paid tool can be retired when everything it does is still provided by a tool that stays.
    # Most expensive first, and each retirement is taken into account for the next one, so two tools
    # that only duplicate each other are never both counted as savings.
    opportunities: list[Opportunity] = []
    redundant_spend = 0.0
    staying = {t.name for t in inventory.tools}
    retired: set[str] = set()
    for tool in sorted(inventory.tools, key=lambda t: (-t.annual_cost, t.name)):
        if not tool.paid_separately:
            continue
        others = {c: [o.name for o in providers[c] if o.name != tool.name and o.name in staying]
                  for c in tool.capabilities}
        if not all(others.values()):
            continue
        staying.discard(tool.name)
        retired.add(tool.name)
        redundant_spend += tool.annual_cost
        covered_by = sorted({name for names in others.values() for name in names})
        opportunities.append(Opportunity(
            f"redundant:{tool.name}", AREA, f"{tool.name} is fully covered by other tools",
            f"All {len(tool.capabilities)} of its capabilities ("
            + ", ".join(CAPABILITIES[c].name for c in tool.capabilities)
            + f") are also provided by {', '.join(covered_by)}. It costs {money(tool.annual_cost, currency)} a year.",
            "Compare depth, not just the label: confirm the other tools meet the same requirements, plan the "
            "migration, then retire this one at renewal.",
            tool.annual_cost / 12, "high", {"tool": tool.name, "covered_by": covered_by}))

    # ---- overlaps where more than one tool is paid for -------------------------------------
    for row in matrix:
        if row["status"] != "overlap":
            continue
        tools = providers[row["capability"]]
        paid = [t for t in tools if t.paid_separately]
        if len(paid) < 2 and not (paid and len(tools) > len(paid)):
            continue  # all bundled: nothing to save
        if all(t.name in retired for t in paid):
            continue  # already reported as a whole-tool opportunity
        described = ", ".join(f"{t.name} ({money(t.annual_cost, currency)}/yr)" if t.paid_separately
                              else f"{t.name} (bundled{' with ' + t.bundled_with if t.bundled_with else ''})"
                              for t in tools)
        opportunities.append(Opportunity(
            f"overlap:{row['capability']}", AREA, f"{row['name']} is provided by {len(tools)} tools",
            f"{described}.",
            "Pick one as the standard for this capability. If a paid tool is kept only for this, negotiate it "
            "out of the contract or drop the module.",
            None, "medium", {"capability": row["capability"], "tools": [t.name for t in tools]}))

    # ---- gaps ------------------------------------------------------------------------------
    gaps = [row for row in matrix if row["status"] == "gap"]
    for row in gaps:
        opportunities.append(Opportunity(
            f"gap:{row['capability']}", AREA, f"No tool covers {row['name']}",
            f"{row['name']} ({row['domain']}) is required but no tool in the inventory provides it.",
            "Check whether a licence you already own includes it before buying something new; if it does not "
            "apply to you, add it to not_required in the inventory.",
            None, "medium", {"capability": row["capability"]}))

    total_spend = sum(t.annual_cost for t in inventory.tools)
    totals = {
        "currency": currency, "tools": len(inventory.tools),
        "paid_tools": sum(1 for t in inventory.tools if t.paid_separately),
        "annual_spend": round(total_spend, 2),
        "capabilities_covered": sum(1 for r in matrix if r["status"] != "gap"),
        "capabilities_overlapping": sum(1 for r in matrix if r["status"] == "overlap"),
        "gaps": len(gaps),
        "redundant_annual_spend": round(redundant_spend, 2),
        "redundant_pct": round(redundant_spend / total_spend * 100, 1) if total_spend else 0.0,
    }
    notes = []
    if not any(t.paid_separately for t in inventory.tools):
        notes.append("costs: no tool has an annual_cost, so overlaps are listed without savings.")
    return OverlapReport(totals, tool_rows, matrix, rank(opportunities), notes)
