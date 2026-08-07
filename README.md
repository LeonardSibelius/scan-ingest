# scan-ingest

**A pipeline that finds the places where the security paperwork and the security
scanner disagree.** C# and Postgres. All data synthetic.

## The problem, in plain language

A federal computer system needs formal permission to operate. Getting that
permission means proving that a long list of security requirements is satisfied —
and then proving, week after week, that it still is.

Two very different things produce that evidence:

- **A vulnerability scanner** crawls every machine on a schedule and reports what
  is broken. Automatic, current, and enormous — thousands of findings.
- **A human assessor** reviews the system against a checklist of security
  *controls* and records a verdict for each one. Thorough, authoritative, and
  going stale from the moment it is written.

Both feed the paperwork that keeps the system authorised. **Neither agrees with
the other**, because one runs weekly and the other runs quarterly, and because a
human triaging a control assessment reasonably ignores the low-severity noise that
a scanner reports forever.

The gap between them is not a data-quality problem to be cleaned up. It is the
most useful thing either source produces:

> A control the assessor marked **satisfied**, that the scanner says is **broken**,
> means the authorisation paperwork is describing a system that no longer exists.

This project ingests both sources, tracks what has been promised and by when, and
reports the contradictions. Here is the output that matters:

```
control eMASS says     sources findings  hosts  verdict
CM-6    Compliant            2       30     26  CONTRADICTED  <-- Configuration Settings
IA-5    Compliant            0        0      0  not assessable  (no scanner can see this)
AC-2    Compliant            0        0      0  not assessable
SC-8    Non-Compliant        6       72     36  corroborated
SC-17   Non-Compliant        6       84     39  corroborated
```

One control is claimed compliant and contradicted by live evidence. Four are
claimed compliant but **nothing could have checked them** — they are procedural,
and no scanner will ever see them. Five are known-bad and correctly tracked.

Not one control in that package is both claimed compliant *and* actually verified.

## The vocabulary

Five terms and the rest of this file reads normally:

| Term | What it means |
|---|---|
| **RMF** | Risk Management Framework. NIST SP 800-37 — the process a federal system walks to get and keep permission to run. |
| **ATO** | Authority to Operate. That permission. No ATO, no production system. |
| **Control** | One security requirement from the NIST SP 800-53 catalogue, e.g. `SC-8`, "Transmission Confidentiality and Integrity". |
| **POA&M** | Plan of Action and Milestones. The register of known gaps — each with an owner and a date they promised to fix it by. |
| **eMASS** | The Department of Defense system of record holding all of the above for a given system. |

The scanner here is modelled on **Nessus**, the vulnerability scanner most widely
used in this space. A *finding* is one problem on one machine.

**New to this?** [**TUTORIAL.md**](TUTORIAL.md) walks through the whole thing in
small steps — install it, run it, then follow one critical finding from raw
scanner output all the way to an overdue report, querying the database yourself at
each stage. No prior security, C# or Postgres knowledge assumed.

## What it actually does

Six weekly scans of forty hosts are generated with realistic churn — findings
persist, get remediated, and reappear. Each scan is landed as raw `jsonb`,
projected into a partitioned fact table, and reconciled against a POA&M register
that opens, closes and reopens commitments. A synthetic eMASS export provides the
second source, and the two are correlated.

Every design decision below is argued for, including the two that were wrong the
first time and had to be fixed.

---

## Setup

You need the **.NET 8 SDK** and a **PostgreSQL server**. On Windows both install
from `winget`; on macOS or Linux use your usual package manager, or run Postgres
in Docker.

**1. .NET 8 SDK** (no admin needed):

```bash
winget install Microsoft.DotNet.SDK.8
```

**2. PostgreSQL** (needs admin — installs a Windows service):

```bash
winget install PostgreSQL.PostgreSQL.17
```

The app defaults to `postgres` / `postgres` on `localhost:5432`. If your superuser
password differs, point it at the right one — PowerShell:

```bash
$env:SCANPREP_CONN = "Host=localhost;Port=5432;Username=postgres;Password=YOURPASSWORD"
```

or bash:

```bash
export SCANPREP_CONN="Host=localhost;Port=5432;Username=postgres;Password=YOURPASSWORD"
```

**3. Run it** — from the repository root, in a fresh terminal so PATH picks up `dotnet`:

```bash
dotnet run
```

First run restores NuGet packages, creates the `scanprep` database, and prints thirteen
sections of output. Running it again changes nothing — verified by running it twice
and diffing row counts, not by assertion.

---

## A walk through the code

The source is heavily commented — every method carries a summary and the
non-obvious SQL is annotated line by line. What follows is the tour: what each
file is for, and what each method in it actually does.

### `Models.cs` — the vocabulary

Every type that crosses a boundary. Two kinds live here: **domain types** the
pipeline moves around, and **report row types** that Dapper materialises straight
from a query result.

- **`Finding`** — one problem, on one machine. Keyed in practice by
  `(host, plugin_id)`: a *plugin* is one specific check whose id is stable
  forever, which is what makes a problem trackable across scans.
- **`ScanRun`** — one execution of the scanner across the estate.
- **`SeverityRow`, `DeltaRow`, `AgingRow`, `TrendRow`** — scan reporting.
- **`PoamSyncResult`, `PoamStatusRow`, `OwnerLoadRow`, `PoamItemRow`** — the
  commitment register.
- **`CorrelationRow`, `UncoveredRow`** — the two-source comparison.

The file header documents the **Dapper contract**, which explains every `AS Name`
alias in the SQL: Dapper matches columns to constructor parameters by name,
ignoring case and underscores, and *silently leaves a parameter at its default*
when nothing matches. The aliases are not decoration.

### `Schema.cs` — the argument, expressed as DDL

The schema is what this project is really claiming, so most of the reasoning sits
in the DDL comments rather than in prose.

- **`EnsureDatabaseAsync`** — creates the database if absent. Connects to the
  `postgres` maintenance database, because you cannot connect to a database in
  order to create it. `CREATE DATABASE` has no `IF NOT EXISTS` form and cannot
  take a parameter, so this is a look-then-leap with proper identifier quoting.
- **`EnsureSchemaAsync`** — applies the whole DDL block in one round trip. Every
  statement is `CREATE … IF NOT EXISTS`, so it is safe on every deploy.
- **`EnsurePartitionAsync`** — creates the monthly partition a scan needs.
  Postgres rejects an insert whose partition key falls outside every defined
  partition, so this runs before each ingest. **The UTC offsets on the boundary
  literals are load-bearing** — see the bugs section below.

### `Generator.cs` — synthetic data with a churn model

Not a stub. The interesting queries are all about *change*, and change needs
history, so getting the churn model wrong makes every report lie.

- **`NextScan(first)`** — produces the next scan. The first call seeds 4–11
  findings per host; every later call ages the population. Remediation is
  **severity-weighted** (34% of criticals per scan, 4% of informationals),
  because triage is real and a flat rate makes the aging report flat-line at one
  number for every severity. New findings are counted by what was genuinely
  *added* rather than by attempts, since a random pick that is already open is a
  collision, not a finding.
- **`NextScanReplay()`** — returns the current open set unchanged. Exists solely
  to test idempotency, and is deliberately separate so that replaying cannot
  accidentally advance the simulation.
- **`Materialise()`** — turns internal state into `Finding` records and sorts
  them. The sort matters: a `HashSet` has no defined iteration order.

### `Ingest.cs` — fast, and exactly once

The two-stage load, and the file most worth reading.

- **`IngestAsync(conn, run, findings)`** — loads one scan inside one transaction,
  and returns how many rows actually landed. Zero on a replay.

  Stage 1 is a **binary `COPY`** into the `jsonb` landing table — Postgres's own
  wire format, roughly an order of magnitude faster than row-by-row `INSERT`.
  Stage 2 is an `INSERT … SELECT` out of the landing table with
  **`ON CONFLICT DO NOTHING`**.

  Why two stages, when one would be simpler: **`COPY` cannot express
  `ON CONFLICT`.** You can have bulk speed or conflict handling in a single
  statement, not both. The landing table is the structural consequence of that one
  limitation — not staging-because-that's-what-people-do.

### `Reports.cs` — the read side

Dapper over hand-written SQL. The SQL *is* the logic; hiding it behind an ORM
would mean writing the same query worse and then obscuring it.

- **`BySeverityAsync`** — open findings per severity, latest scan only.
- **`DeltaAsync`** — new / resolved / still-open against the previous scan.
  `ROW_NUMBER() OVER (ORDER BY scanned_at DESC)` picks the last two runs with no
  dates hardcoded, and a **`FULL OUTER JOIN`** is what makes all three categories
  fall out of one query — an inner join would silently lose the two interesting
  ones.
- **`AgingAsync`** — how long open findings have been open. Measured from the
  *first observation*, not from row insertion, so it reports on the problem rather
  than on the pipeline.
- **`TrendAsync`** — high+critical per scan with the run-over-run change.
  Demonstrates **`LAG()` over an aggregate**: group first, then window over the
  groups. The first row's delta is `NULL` and stays `NULL`, because "no change
  recorded" and "change of zero" are different statements.
- **`TotalFactRowsAsync`** — a row count. Crude, and the exact invariant that
  would have caught the replay bug this pipeline originally shipped with.

### `Poam.cs` — commitments, not observations

Everything above deals in observations: the scanner saw this, here, then. Nobody
is accountable for an observation. A POA&M is a *commitment* — a named person has
accepted a gap and promised a date.

- **`SlaCase`** — the remediation deadline per severity (15/30/90/180/365 days),
  held as a SQL fragment because several queries need it and computing it in C#
  would mean pulling every row back to apply it.
- **`SyncAsync`** — reconciles the register against the latest scan, in one
  transaction, returning what moved. Three transitions:
  - **open** — a finding with no commitment yet. Its clock starts from when the
    problem was *first observed*, not from today, so a long-standing gap does not
    look fresh the moment somebody finally writes it down.
  - **reopen** — a closed commitment whose finding returned. An `UPDATE` of the
    existing row, never a new one: a fresh row would reset the clock and erase the
    recurrence, and a recurrence means the fix did not hold, which is a worse fact
    than a new finding.
  - **close** — dated to the *scan's* date, not to `now()`. The scan is the
    evidence.

  Due dates are computed once at open time and never recalculated. The commitment
  was made on a date.
- **`StatusAsync`** — open and overdue per severity. "As of" is the latest scan,
  not wall-clock: if the scanner has not run for three weeks, nothing has been
  observed for three weeks, and ageing against `now()` would invent overdue days
  no evidence supports.
- **`WorstOverdueAsync`** — names, machines, deadlines and days late. What an
  Authorizing Official actually asks for.
- **`ByOwnerAsync`** — load per owner. Not "how broken is the system" but "who is
  carrying it, and who is drowning".

### `Controls.cs` — the second source, and the correlation

- **`Catalog` / `Evidence`** — ten NIST 800-53 controls and the many-to-many map
  from scanner plugins to the controls they bear on. **This map is the join key
  for the whole file** — without it the two sources share nothing, since one talks
  about hosts and plugins and the other about controls. It is deliberately
  incomplete in both directions, and both gaps show up in the output.
- **`SeedCatalogAsync`** — loads both into the database, idempotently.
- **`GenerateExportAsync`** — writes the synthetic eMASS export, dated to the
  **first** scan. That staleness is the mechanism: the compliance record is a
  photograph, the scanner is a video. The assessor fails a control only on
  `severity >= 3` evidence, which is how triage genuinely works — and it means
  medium and low findings never reach the compliance record while the scanner
  reports them forever. **The contradictions fall out of that asymmetry rather
  than being planted.**
- **`CorrelateAsync`** — the payload. Five verdicts, described in the correlation
  section above. The `coverage` CTE counts how many plugins can speak to each
  control *at all*, which is what separates `not assessable` from
  `verified clean`.
- **`UncoveredAsync`** — the mirror-image gap: findings mapping to no tracked
  control. Either the mapping is incomplete or the package is.

### `Program.cs` — the sequence

Top-level statements: no class, no `Main`. Bootstraps the schema, ingests six
scans while reconciling the register after each, proves idempotency by replaying
the last scan, then prints the ten report sections in order.

---

## The four design decisions worth defending

**1. `jsonb` landing table.**
Nessus output is nested and its shape drifts between plugin versions. Forcing it
into columns on the way in means every scanner update breaks ingest. Land it raw,
project it on read: flexibility on ingest, discipline on query. The GIN index keeps
containment queries over the raw payload usable.

**2. Binary `COPY`, then a separate normalise step.**
`COPY` is roughly an order of magnitude faster than row-by-row `INSERT`, but it
cannot express `ON CONFLICT`. That is the actual reason for two stages — the
landing table isn't ceremony, it's what makes fast *and* idempotent possible
at the same time.

**3. Range partitioning by scan date.**
Findings accumulate per host, per plugin, per scan, forever. Monthly partitions
keep queries bounded and turn retention into a `DETACH PARTITION` instead of a
`DELETE` that runs for an hour and bloats the table.

**4. The primary key is the idempotency guarantee.**
`PRIMARY KEY (scanned_at, host, plugin_id)`. Scans get re-run and re-delivered.
A pipeline that double-counts on replay quietly corrupts every number downstream —
and downstream here is a POA&M an Authorizing Official signs. Section `[3]` of the
output proves it: re-ingest the last scan, row count doesn't move.

---

## The POA&M register

A finding is an **observation**. A POA&M is a **commitment** — an owner, and a date
they promised. That difference drives the modelling:

| | `finding` | `poam` |
|---|---|---|
| keyed by | `(scanned_at, host, plugin_id)` | `(host, plugin_id)` |
| partitioned | yes, by scan month | no |
| lifetime | one scan | outlives every scan that observed it |

Reconciliation runs after **every** ingest, with three transitions:

- **open** — a finding in the latest scan with no POA&M yet
- **reopen** — a closed item whose finding came back. Deliberately *not* a new row:
  a fresh row would reset the clock and hide the recurrence, which is precisely the
  thing an auditor is looking for
- **close** — a POA&M whose finding no longer appears

The due date is derived from severity at open time — 15 / 30 / 90 / 180 / 365 days
for critical through info — and **never recalculated**. The commitment was made on a
date. Silently moving it would be the most dishonest thing this code could do.

Reconciliation always compares against the newest observed scan, not the scan just
ingested. That's deliberate: a late-arriving backfill of an old scan must not be
able to reopen or close commitments based on stale data.

---

## The correlation — the actual product

Two sources that disagree:

- **Nessus** answers *"what is broken on this host, right now."* Continuous.
- **eMASS** answers *"what did the assessor say about this system's controls."*
  Periodic, and in this data five weeks stale.

They drift apart, and **the gap is the product**. Nessus plugins map many-to-many
onto NIST 800-53 controls (`plugin_control`), which is what makes the two joinable
at all.

The assessor marks a control Non-Compliant only where they saw **high or critical**
evidence — that isn't laziness, it's how triage works; nobody fails a control over
an informational finding. But it means medium and low evidence never reaches the
compliance record while continuous monitoring keeps seeing it. **The contradictions
fall out of that asymmetry rather than being planted.**

Five verdicts:

| Verdict | Meaning |
|---|---|
| **CONTRADICTED** | Marked Compliant, scanner disagrees. The package describes a system that no longer exists. |
| **not assessable** | *No plugin maps to this control.* The scanner cannot speak to it either way. |
| corroborated | Marked Non-Compliant, scanner agrees. Working as intended. |
| unevidenced | Non-Compliant, evidence sources exist, nothing found. Remediated and the paperwork is stale — or it was never technical. |
| verified clean | Compliant, sources exist, they found nothing. The only row you can ignore. |

**The distinction between "not assessable" and "verified clean" is the one to defend.**
The first version collapsed both to `clean`, which meant AC-2, AU-6, IA-5 and SI-4 —
all procedural controls no scanner will ever see — were reported to an Authorizing
Official as though something had checked them. Nothing had. A dashboard that cannot
tell *"we looked and it was fine"* from *"we never looked"* is worse than no dashboard,
because it manufactures confidence.

Run it and note what the summary actually says: of ten controls, one is contradicted,
four are unverifiable, five are known-bad, and **not one is both claimed compliant and
actually verified.**

`[13]` reports the mirror-image gap: findings that map to no tracked control at all.
Either the mapping is incomplete or the authorisation package is.

---

## Two things worth being able to say

**Partition boundaries must be pinned to UTC.**
`scanned_at` is `timestamptz`, and a bare date literal in a partition bound is
resolved in the *server's* timezone. On a machine set to Pacific, `FOR VALUES FROM
('2026-08-01')` puts the boundary at 07:00 UTC — so a scan taken at 03:00 UTC on
the 1st silently lands in July's partition. The first version of this code had that
bug. Fixed by writing the bounds as `'2026-08-01 00:00:00+00'`. Verify with:

```sql
SET timezone = 'UTC';
SELECT relname, pg_get_expr(relpartbound, oid) FROM pg_class WHERE relname LIKE 'finding_%';
```

**Idempotency needs deterministic keys, not just an `ON CONFLICT`.**
The first version derived `scanned_at` from `DateTimeOffset.UtcNow` and `scan_run_id`
from `Guid.NewGuid()`. Running the program twice therefore produced timestamps minutes
apart — different primary keys, so nothing collided and every row inserted a second
time. The `ON CONFLICT DO NOTHING` was working perfectly and protecting nothing,
because it was never asked a question it could answer.

Fixed by anchoring the scan dates to a fixed instant and deriving `scan_run_id` as an
MD5 of `source|timestamp`. The lesson generalises: **replay safety is a property of
your keys, not of your conflict clause.** A pipeline that gets re-driven — and they
all get re-driven — needs identity that survives the restart.

**The GIN index is correctly ignored at this size.**
`EXPLAIN` on the containment query shows a `Seq Scan`, not an index scan — because
1,730 rows fit in a couple of pages and the planner is right that scanning is
cheaper. Set `enable_seqscan = off` and it switches to `Bitmap Index Scan on
raw_finding_payload_gin`, which confirms the index is valid and usable; it just
isn't worth using yet. Knowing the difference between *"the index is broken"* and
*"the planner declined it"* is most of what index debugging is.

Partition pruning **is** already working — filtering on an August date scans only
`finding_2026_08` and skips July entirely.

---

## The queries

- **By severity** — current open findings, latest scan only.
- **Delta** — `ROW_NUMBER() OVER (ORDER BY scanned_at DESC)` picks the last two
  runs without hardcoding dates; a `FULL OUTER JOIN` classifies each finding as
  new / resolved / still open.
- **Aging** — how long each currently-open finding has been open. This is POA&M
  aging, the number that actually matters to an AO.
- **Trend** — `LAG()` over an aggregate for run-over-run change in high+critical.
  A window function over a `COUNT(*) FILTER (…)` is the idiom to know.

---

## C# notes for a Java developer

- `record` ≈ Java record. Value equality, positional constructor.
- `await using` ≈ try-with-resources for `IAsyncDisposable`.
- `"""…"""` raw string literals ≈ Java text blocks. Same thing, same reason.
- `?` on a type (`string?`, `long?`) is nullable-reference / nullable-value.
- `[…]` collection expressions are C# 12 — `new List<T>()` still works.
- `switch` expressions (`x switch { 4 => "critical", _ => "info" }`) are the
  concise form; you'll see them everywhere in modern C#.
- `x switch`, `_ =>` default case, `,` separated — not `case`/`break`.
- LINQ (`.Where().Select().OrderBy()`) is the Streams API with better ergonomics.

---

## Where this would go next

- **Parse real SCAP/XCCDF** instead of generating findings. The landing table
  already tolerates whatever shape shows up, which was the point of it.
- **Control inheritance** — common controls provided by the hosting enclave are
  inherited rather than assessed per-system, and the correlation currently has no
  concept of that. It would change which contradictions are real.
- **ATO expiry and reauthorisation windows**, so the register can answer "what
  blocks reauthorisation in ninety days" rather than only "what is overdue now."
- **A third source**: STIG checklist results, which overlap the scanner
  imperfectly and would make the correlation genuinely three-way.
- Swap the console output for a minimal ASP.NET Core endpoint returning JSON.
