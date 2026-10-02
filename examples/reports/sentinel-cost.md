# Microsoft Sentinel cost review

**Workspace:** contoso-sentinel (demo) (eastus) · **Period:** 2026-09-01 to 2026-09-30 (30 days) · **Captured:** 2026-10-01T12:00:00Z · **Source:** built-in demo workspace (fictional data)

## Summary

| Measure | Value |
|---|---|
| Billable ingestion, Analytics plan | 118.4 GB/day (peak 133.0) |
| Free ingestion in the period | 188 GB |
| Pricing plan | Pay-as-you-go |
| Estimated cost | $15,268 a month |
| Effective price, Analytics plan | $4.30 per GB |
| Tables with billable data | 11 |
| Daily cap | none |

## Opportunities

**Estimated saving: up to $4,668 a month ($56,019 a year).**

| # | Opportunity | Saving / month | Effort |
|---|---|---|---|
| 1 | Switch to 100 GB/day commitment tier | $4,668 | low |
| 2 | No analytics rule reads AADNonInteractiveUserSignInLogs | $1,061 * | medium |
| 3 | AzureDiagnostics ingestion jumped | $1,037 * | low |
| 4 | No analytics rule reads DeviceNetworkEvents | $772 * | medium |
| 5 | No analytics rule reads AzureDiagnostics | $581 * | medium |
| 6 | No analytics rule reads StorageBlobLogs | $297 * | medium |
| 7 | Interactive retention longer than 90 days | - | low |

\* Estimated at today's effective price per GB. These overlap with each other and with a pricing-plan change, so they are not included in the total and should not be added up.

### 1. Switch to 100 GB/day commitment tier

Ingestion that counts toward a commitment tier averages 118.4 GB/day (peak 133.0). Pay-as-you-go costs about $15,268 a month; 100 GB/day commitment tier would cost about $10,600.

**What to do:** Change the pricing tier under Microsoft Sentinel > Settings > Pricing. A commitment tier is fixed for 31 days, so check that the volume is steady first.

### 2. No analytics rule reads AADNonInteractiveUserSignInLogs

10.7 GB/day of billable data, about $1,382 a month, and no enabled analytics rule queries it. Up to $1,061 a month if the table can move to the Basic plan ($1.00 per GB); not every table supports it.

**What to do:** Decide what the table is for. If it is only for investigation or compliance, move it to a cheaper plan or reduce what is collected; if it should be detected on, write the rules. Use a workspace transformation to drop columns you do not query; this table is usually several times larger than interactive sign-ins.

### 3. AzureDiagnostics ingestion jumped

The last 7 days average 12.0 GB/day against 4.0 GB/day before (+201%).

**What to do:** Find the source: summarize _BilledSize by Computer or _ResourceId in this table for the last 7 days. If the increase is not intended, fix the source or filter it in the data collection rule.

### 4. No analytics rule reads DeviceNetworkEvents

7.8 GB/day of billable data, about $1,006 a month, and no enabled analytics rule queries it. Up to $772 a month if the table can move to the Basic plan ($1.00 per GB); not every table supports it.

**What to do:** Decide what the table is for. If it is only for investigation or compliance, move it to a cheaper plan or reduce what is collected; if it should be detected on, write the rules. Defender XDR already keeps 30 days for hunting; stream this table only if detections or long retention need it.

### 5. No analytics rule reads AzureDiagnostics

5.9 GB/day of billable data, about $757 a month, and no enabled analytics rule queries it. Up to $581 a month if the table can move to the Basic plan ($1.00 per GB); not every table supports it.

**What to do:** Decide what the table is for. If it is only for investigation or compliance, move it to a cheaper plan or reduce what is collected; if it should be detected on, write the rules. Send only the diagnostic categories you use, and move resources to resource-specific tables.

### 6. No analytics rule reads StorageBlobLogs

3.0 GB/day of billable data, about $387 a month, and no enabled analytics rule queries it. Up to $297 a month if the table can move to the Basic plan ($1.00 per GB); not every table supports it.

**What to do:** Decide what the table is for. If it is only for investigation or compliance, move it to a cheaper plan or reduce what is collected; if it should be detected on, write the rules. Storage data-plane logs are very high volume; keep them on a cheaper plan unless a detection needs them.

### 7. Interactive retention longer than 90 days

Sentinel includes 90 days of interactive retention; beyond that every GB is billed monthly. Tables above it: SecurityEvent (180 days), StorageBlobLogs (180 days).

**What to do:** Keep interactive retention at 90 days and use long-term (total) retention for older data; it costs a fraction and can still be searched or restored.

## Pricing plans compared

Monthly cost of the Analytics-plan ingestion you actually had, under each plan. Only Analytics-plan data counts toward a commitment tier.

| Plan | Cost / month |  |
|---|---|---|
| Pay-as-you-go | $15,268 | current |
| 50 GB/day commitment tier | $11,451 |  |
| 100 GB/day commitment tier | $10,600 |  |
| 200 GB/day commitment tier | $16,440 |  |
| 300 GB/day commitment tier | $24,000 |  |
| 400 GB/day commitment tier | $31,120 |  |

## Tables

| Table | GB/day | Share | Cost / month | Plan | Retention | Rules | 7-day trend |
|---|---|---|---|---|---|---|---|
| SecurityEvent | 35.47 | 30.0% | $4,576 | Analytics | 180 d | 2 | 0% |
| CommonSecurityLog | 31.15 | 26.3% | $4,018 | Analytics | 90 d | 1 | 0% |
| Syslog | 13.63 | 11.5% | $1,758 | Analytics | 90 d | 1 | 0% |
| AADNonInteractiveUserSignInLogs | 10.72 | 9.1% | $1,382 | Analytics | 90 d | 0 | -1% |
| DeviceNetworkEvents | 7.80 | 6.6% | $1,006 | Analytics | 90 d | 0 | -2% |
| DeviceProcessEvents | 6.93 | 5.9% | $894 | Analytics | 90 d | 1 | -2% |
| AzureDiagnostics | 5.87 | 5.0% | $757 | Analytics | 90 d | 0 | +201% |
| StorageBlobLogs | 3.00 | 2.5% | $387 | Analytics | 180 d | 0 | 0% |
| SigninLogs | 2.60 | 2.2% | $335 | Analytics | 90 d | 2 | -1% |
| AuditLogs | 0.89 | 0.8% | $115 | Analytics | 90 d | 1 | -2% |
| ThreatIntelIndicators | 0.30 | 0.3% | $38.70 | Analytics | 90 d | 1 | 0% |

_Rules = enabled analytics rules whose query names the table. Free tables are not listed._

## Notes

- pricing: Azure Retail Prices API, list prices on 2026-10-02; your agreement may differ (use --price-per-gb).

---
Generated by cloud-security-optimization 1.0.0. Read-only: nothing was changed.
