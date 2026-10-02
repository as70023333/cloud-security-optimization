"""The one result type every analyzer produces."""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

EFFORTS = ("low", "medium", "high")


def is_number(value: Any, low: float = 0.0, high: float = 1e12) -> bool:
    """A real, finite number within sensible bounds. Rejects booleans, NaN, infinity and numbers so
    large that arithmetic on them overflows; prices and volumes come from files people edit."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    if isinstance(value, float) and not math.isfinite(value):
        return False
    return low <= value <= high


def is_currency(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 3 and value.isascii() and value.isalpha()


@dataclass
class Opportunity:
    """Something that could be changed to cut cost or close a gap.

    ``monthly_saving`` is an estimate in the report's currency, or None when the tool has no
    honest way to put a number on it (no price supplied, or the saving depends on a decision
    only you can make). It is never guessed.
    """

    id: str
    area: str
    title: str
    detail: str
    action: str
    monthly_saving: float | None = None
    effort: str = "medium"
    evidence: dict[str, Any] = field(default_factory=dict)
    # False when the saving overlaps with other opportunities (for example two ways of cutting the
    # same table), so it must not be added into a total.
    additive: bool = True

    def __post_init__(self) -> None:
        if self.effort not in EFFORTS:
            raise ValueError(f"effort must be one of {', '.join(EFFORTS)}")
        if self.monthly_saving is not None:
            self.monthly_saving = round(float(self.monthly_saving), 2)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def rank(opportunities: Iterable[Opportunity]) -> list[Opportunity]:
    """Largest quantified saving first; unquantified ones after, in a stable order."""
    return sorted(opportunities, key=lambda o: (o.monthly_saving is None, -(o.monthly_saving or 0.0), o.id, o.title))


def total_saving(opportunities: Iterable[Opportunity]) -> float:
    """Sum of the savings that can honestly be added together."""
    return round(sum(o.monthly_saving or 0.0 for o in opportunities if o.additive), 2)


def money(value: float | None, currency: str = "USD") -> str:
    if value is None:
        return "n/a"
    symbol = {"USD": "$", "EUR": "€", "GBP": "£"}.get(currency, "")
    text = f"{value:,.0f}" if abs(value) >= 100 else f"{value:,.2f}"
    return f"{symbol}{text}" if symbol else f"{text} {currency}"
