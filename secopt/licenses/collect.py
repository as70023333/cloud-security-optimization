"""Read-only collection of licence data from Microsoft Graph (two GET endpoints)."""

from __future__ import annotations

import urllib.parse
from typing import Any, Callable, Mapping

from secopt.core.auth import GRAPH_SCOPE, TokenCredential
from secopt.core.http import HttpClient, HttpError
from secopt.core.timeutil import iso, utcnow

GRAPH_BASE = "https://graph.microsoft.com"
USER_FIELDS = "id,userPrincipalName,accountEnabled,userType,createdDateTime,assignedLicenses"

Log = Callable[[str], None]


class GraphReader:
    def __init__(self, http: HttpClient, credential: TokenCredential, base: str = GRAPH_BASE) -> None:
        self.http = http
        self.credential = credential
        self.base = base.rstrip("/")
        self._host = urllib.parse.urlsplit(self.base).netloc.lower()

    def get_all(self, path: str, params: Mapping[str, str] | None = None) -> list[dict]:
        scope = GRAPH_SCOPE if self.base == GRAPH_BASE else f"{self.base}/.default"
        url: str | None = f"{self.base}{path}"
        query = params
        items: list[dict] = []
        while url:
            # Never send the token to another host, even if a paging link points there.
            if urllib.parse.urlsplit(url).netloc.lower() != self._host:
                raise HttpError(0, "refusing to follow a paging link to another host")
            headers = {"Authorization": f"Bearer {self.credential.get_token(scope)}"}
            data = self.http.request("GET", url, params=query, headers=headers, ok=(200,)).json() or {}
            items.extend(data.get("value") or [])
            url, query = data.get("@odata.nextLink"), None
        return items


def _skus(graph: GraphReader) -> list[dict[str, Any]]:
    out = []
    for sku in graph.get_all("/v1.0/subscribedSkus"):
        prepaid = sku.get("prepaidUnits") or {}
        out.append({
            "sku_id": sku.get("skuId", ""), "part_number": sku.get("skuPartNumber", ""),
            "status": sku.get("capabilityStatus", ""), "applies_to": sku.get("appliesTo", ""),
            "purchased": int(prepaid.get("enabled") or 0) + int(prepaid.get("warning") or 0),
            "suspended": int(prepaid.get("suspended") or 0), "assigned": int(sku.get("consumedUnits") or 0),
            "service_plans": sorted(p.get("servicePlanId", "") for p in sku.get("servicePlans") or []
                                    if p.get("appliesTo") != "Company" and p.get("servicePlanId")),
        })
    return out


def _users(graph: GraphReader, snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """Licensed users. Sign-in activity is added when the tenant and permissions allow it."""
    last_error: HttpError | None = None
    for extra, top in (("signInActivity", "500"), ("signInActivity", "120"), ("", "999")):
        select = USER_FIELDS + ("," + extra if extra else "")
        try:
            users = graph.get_all("/v1.0/users", {"$select": select, "$top": top})
        except HttpError as exc:
            if exc.status not in (400, 403):
                raise
            last_error = exc
            continue
        snapshot["sign_in_activity_available"] = bool(extra)
        if not extra and last_error is not None:
            snapshot["errors"]["sign_in_activity"] = (
                f"sign-in activity unavailable ({last_error}); inactive-user checks were skipped. "
                "Grant AuditLog.Read.All; the tenant needs Entra ID P1.")
        out = []
        for user in users:
            licences = [a.get("skuId", "") for a in user.get("assignedLicenses") or [] if a.get("skuId")]
            if not licences:
                continue
            activity = user.get("signInActivity") or {}
            last = activity.get("lastSuccessfulSignInDateTime") or max(
                (activity.get("lastSignInDateTime") or "", activity.get("lastNonInteractiveSignInDateTime") or ""))
            out.append({"id": user.get("id", ""), "upn": user.get("userPrincipalName", ""),
                        "enabled": bool(user.get("accountEnabled")), "type": user.get("userType") or "Member",
                        "created": user.get("createdDateTime") or "", "last_sign_in": last or "",
                        "sku_ids": sorted(licences)})
        return out
    raise last_error  # type: ignore[misc]


def collect(graph: GraphReader, log: Log = lambda _m: None) -> dict[str, Any]:
    """Collect the snapshot. Raises HttpError only if the licence list itself cannot be read."""
    snapshot: dict[str, Any] = {"kind": "licenses", "captured_at": iso(utcnow()), "skus": _skus(graph), "users": None,
                                "sign_in_activity_available": False, "errors": {}}
    log(f"licence products: {len(snapshot['skus'])}")
    try:
        snapshot["users"] = _users(graph, snapshot)
        log(f"licensed users: {len(snapshot['users'])}")
    except HttpError as exc:
        hint = " (grant User.Read.All)" if exc.status in (401, 403) else ""
        snapshot["errors"]["users"] = f"{exc}{hint}"
        log(f"users: skipped ({exc})")
    return snapshot
