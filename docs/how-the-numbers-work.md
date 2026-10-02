# How the numbers are worked out

A savings figure is only useful if you can check it. This page shows the arithmetic behind every
number `secopt` prints, and where the tool deliberately does not give one.

Two rules apply everywhere:

1. **No guessed numbers.** If the tool has no price, it reports counts and volumes and leaves the
   saving empty. It never substitutes a "typical" price.
2. **No double counting.** A total only includes savings that can really be added together.

## Sentinel cost review

### Volume

Volume comes from the workspace's own `Usage` table, which is what Azure bills from:

```kusto
Usage
| where TimeGenerated > ago(32d)
| where StartTime >= startofday(ago(30d)) and EndTime < startofday(now())
| summarize BillableMB = sumif(Quantity, IsBillable == true), TotalMB = sum(Quantity) by DataType, Day = bin(StartTime, 1d)
| project Day, DataType, BillableMB, TotalMB
| order by Day asc, DataType asc
```

`Quantity` is in MB and Azure bills in decimal GB, so it is divided by 1000. Usage records are
hourly; they are grouped by the hour the data belongs to (`StartTime`), as in Microsoft's own
billing queries. Only whole days are used, so a half-finished today does not pull the average down.

### Table plans

What a GB costs depends on the plan of the table it lands in, so the volume is split first:

| Table plan | How it is priced |
|---|---|
| Analytics (the default) | The Sentinel price per GB, or a commitment tier. This is the only data that counts toward a tier |
| Basic | The Basic logs price per GB. Never counted toward a tier |
| Anything else (Auxiliary, for example) | Not priced. Shown by volume, with a note |

A table whose plan could not be read is treated as Analytics. Getting this split wrong matters:
counting Basic-plan data toward a commitment tier would recommend a tier that raises the bill.

### Prices

Prices come from the public [Azure Retail Prices API](https://learn.microsoft.com/rest/api/cost-management/retail-prices/azure-retail-prices)
for the workspace's region: the pay-as-you-go price per GB, the daily price of each commitment
tier, and the Basic logs price. These are **list prices**. If you have a negotiated rate, pass it
with `--price-per-gb`.

### Cost of each plan

Each plan is priced against the Analytics-plan ingestion you actually had, one day at a time:

| Plan | Cost of one day |
|---|---|
| Pay-as-you-go | GB that day × price per GB |
| Commitment tier | The tier's daily price, plus any GB above the tier at the tier's own rate (daily price ÷ tier size) |

The daily costs are averaged and multiplied by 30 to give a monthly figure. Pricing day by day
matters: a workspace that averages 100 GB/day but swings between 60 and 140 pays for the full
tier on quiet days and overage on busy ones, which an average hides.

A plan change is only suggested when it saves at least 1% of the bill (and at least 10 in your
currency).

**Worked example (the demo):** 118.4 GB/day at $4.30 is about $15,268 a month on pay-as-you-go.
The 100 GB/day tier costs $296 a day, with overage at $2.96 per GB, which comes to about $10,600
a month. Saving: about $4,668 a month.

### Table findings

| Finding | Rule | Saving shown |
|---|---|---|
| No analytics rule reads a table | The table averages 0.5 GB/day or more over the period, is on the Analytics plan (or its plan is unknown), and no **enabled** analytics rule names it in its query. The 10 largest are listed | GB/day × 30 × (your effective price − the Basic logs price): the most you would save if the table moved to the Basic plan |
| Ingestion jumped | The last 7 days average at least 1.5 times the days before, and at least 0.5 GB/day more. A table that did not exist before counts. Needs 14 days of data or more; with fewer, a note says growth was not measured | The extra GB/day × 30 × the price for that table's plan |
| Long interactive retention | An Analytics table averaging 0.5 GB/day or more keeps more than the 90 days Sentinel includes | None: retention billing depends on how much data has aged, which the tool does not measure |

*Effective price* is the monthly Analytics-plan cost divided by the monthly Analytics-plan
volume, so it already reflects a commitment tier if you have one.

Table savings are marked with `*` and **left out of the total**. They overlap: a table can be both
unread and spiking, and trimming tables changes which pricing plan is cheapest. Adding them to
the plan saving would promise money twice.

### What it does not know

- **Rules are not the only readers.** Hunting queries, workbooks, playbooks and people in the
  query window read tables too. "No rule reads it" is a question to ask, not a verdict. Tables
  that Sentinel features read without a rule (UEBA, incidents, watchlists, threat intelligence)
  are excluded.
- **Table names are matched as whole words** in the rule query. A rule that reaches a table only
  through a saved function or a parser (for example an ASIM parser) is not counted as reading it.
- **Not every table can move to the Basic plan**, and Basic tables have query limits. The saving
  is an upper bound.
- **Benefits and allowances are not modelled**: the Microsoft 365 E5 data grant, the Defender for
  Servers allowance, and dedicated-cluster pricing. If you have them, your real bill is lower than
  the estimate.
- **Simplified pricing is assumed**: one combined Sentinel price per GB. Workspaces still on the
  classic two-meter pricing pay a separate Log Analytics charge that is not included.

## Licence review

Counts come from Microsoft Graph. Each assigned licence is put in **one** bucket, checked in this
order, so no licence is counted twice:

| Bucket | Rule |
|---|---|
| Disabled | The account is disabled |
| Inactive | The account is enabled and has not signed in for 90 days (`--inactive-days`). Accounts that have never signed in are measured from their creation date, so a new starter is not flagged |
| Duplicate | The user also holds another product that contains every service plan of this one |

Separately, **unassigned** = purchased − assigned, per product.

Waste per product = (unassigned + disabled + inactive + duplicate) × your monthly price.

**Duplicates are worked out from your tenant, not from a product list.** Product B is "included
in" product A when every user-level service plan in B is also in A, as reported by Graph. That
keeps working when Microsoft renames or repackages products.

**Prices are yours.** Microsoft does not publish licence prices through an API, and what you pay
depends on your agreement, so the tool reads them from a file you write (`--prices`). A product
with no price is still counted, with an empty saving.

### What it does not know

- **Sign-in is not usage.** Someone can sign in daily and never touch the E5 security features.
  The tool does not measure feature usage.
- **Shared and service mailboxes**, break-glass accounts and people on long leave look inactive.
  Review the list before removing anything.
- **Reducing a count** only saves money at renewal or true-up, depending on your agreement.
- **Free and trial products** are left out by a list of known part numbers; a product priced at 0
  in your file is treated as free too.

## Tool overlap review

The input is an inventory you write: each tool, what it costs, and which capabilities it provides
from a fixed vocabulary (`secopt overlap --list-capabilities`).

| Finding | Rule | Saving shown |
|---|---|---|
| Fully redundant tool | A tool you pay for separately, where **every** capability it has is also provided by another tool | Its annual cost ÷ 12 |
| Overlap | A capability provided by two or more tools, at least one of them paid for separately, and not already reported as a redundant tool | None: you cannot retire part of a tool |
| Gap | A required capability no tool provides | None |

Redundant tools are picked most expensive first, and a tool is only counted if the remaining
tools still cover everything it did. Two tools that duplicate each other are therefore counted
once, never both.

"Required" starts from a baseline of 14 capabilities most organizations need (shown as
`[baseline]` in the capability list). Add to it with `required = [...]` and remove what does not
apply with `not_required = [...]`.

### What it does not know

- **A label is not depth.** Two tools can both "do EDR" at very different quality, or cover
  different operating systems. The report tells you where to look; the comparison is yours.
- **The answer is only as good as the inventory.** Capabilities you leave off a tool can make
  another tool look irreplaceable, and the reverse.
- **Contract terms** (notice periods, multi-year commitments) decide when a saving is real.
