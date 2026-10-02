# Permissions

Everything `secopt` does is a read. It never changes a pricing tier, a table plan, a retention
setting, a licence assignment or an account. The only `POST` it sends is the Log Analytics query
(a query is a read; the API takes it as a POST body).

`secopt overlap` reads one local file and makes no network calls at all.

## Who signs in

Pick whichever fits where you run it. The same three options work for both `sentinel` and `licenses`.

| Option | Use it when | Set |
|---|---|---|
| Your own sign-in | Running by hand on your laptop | `az login`, nothing else |
| App registration + client secret | Scheduled runs, CI | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` |
| Managed identity | Running in Azure (Automation, Functions, a VM) | `USE_MANAGED_IDENTITY=true` (and `AZURE_CLIENT_ID` for a user-assigned identity) |

`AZURE_AUTH=secret|managed_identity|cli` forces one of them. Left empty, the order is: client
secret if one is set, then managed identity if switched on, then the Azure CLI.

## `secopt sentinel`

| What is read | API | Role |
|---|---|---|
| Workspace pricing tier, retention, daily cap | Azure Resource Manager, `Microsoft.OperationalInsights/workspaces` | **Microsoft Sentinel Reader** on the workspace |
| Table plans and retention | Azure Resource Manager, `.../workspaces/<name>/tables` | same |
| Analytics rules (their queries, enabled or not) | Azure Resource Manager, `Microsoft.SecurityInsights/alertRules` | same |
| Ingestion per table per day | Log Analytics query API, the `Usage` table | same |
| List prices | Azure Retail Prices API (`prices.azure.com`) | none: public, no sign-in, no token is sent |

**Microsoft Sentinel Reader** on the workspace (or its resource group) is the role intended for
this. **Log Analytics Reader** also works, because it can read every setting and query the
workspace. If the first call (reading the workspace itself) is refused under Sentinel Reader in
your tenant, add Log Analytics Reader.

Each part is collected on its own. If one cannot be read, the report says which and leaves out
the findings that depend on it rather than guessing: without the analytics rules, for example,
there are no "no rule reads this table" findings. Only the workspace itself and its `Usage` data
are essential; without them the run stops with exit code 2.

With the Azure CLI:

```bash
az role assignment create \
  --assignee <app-or-user-object-id> \
  --role "Microsoft Sentinel Reader" \
  --scope /subscriptions/<id>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<name>
```

## `secopt licenses`

| What is read | Microsoft Graph | Permission |
|---|---|---|
| Products bought and how many are assigned | `GET /v1.0/subscribedSkus` | `Organization.Read.All` (or `Directory.Read.All`) |
| Licensed users, enabled or disabled | `GET /v1.0/users` | `User.Read.All` |
| Last sign-in per user | `signInActivity` on the same call | `AuditLog.Read.All`, and the tenant needs Entra ID P1 or P2 |

For an app registration these are **application** permissions and need admin consent. When you
use your own sign-in, your account needs a role that can read them (Global Reader is enough).

Each permission you leave out removes one part of the report, and the report says so:

| Missing | What happens |
|---|---|
| `AuditLog.Read.All` or Entra ID P1 | Inactive-account findings are skipped; a note explains why |
| `User.Read.All` | Only unassigned licences are reported; a note explains why |
| `Organization.Read.All` | The run stops with exit code 2: there is nothing to analyse |

## What leaves your network

| Destination | What is sent |
|---|---|
| `login.microsoftonline.com` | The sign-in for the option you chose |
| `management.azure.com`, `api.loganalytics.io` | Read requests for the workspace (`sentinel`) |
| `graph.microsoft.com` | Read requests for licences and users (`licenses`) |
| `prices.azure.com` | Region and currency only, no credentials (`sentinel`) |

Nothing is sent anywhere else, and there is no telemetry. A token is only ever sent to the host it
was issued for: redirects are never followed, and paging links that point to a different host are
refused.

## What the output contains

Reports and snapshots hold user sign-in names, table names, tool names and what you pay. Treat
them as internal documents. `reports/`, snapshots and `my-*.toml` files are in `.gitignore` so
they do not end up in a commit by accident.
