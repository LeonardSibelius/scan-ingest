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

## The payoff

This project ingests both sources, tracks what has been promised and by when, and
reports the contradictions. This is the output that matters:

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

Five terms, and the rest of this file reads normally:

| Term | What it means |
|---|---|
| **RMF** | Risk Management Framework. NIST SP 800-37 — the process a federal system walks to get and keep permission to run. |
| **ATO** | Authority to Operate. That permission. No ATO, no production system. |
| **Control** | One security requirement from the NIST SP 800-53 catalogue, e.g. `SC-8`, "Transmission Confidentiality and Integrity". |
| **POA&M** | Plan of Action and Milestones. The register of known gaps — each with an owner and a date they promised to fix it by. |
| **eMASS** | The Department of Defense system of record holding all of the above for a given system. |

The scanner here is modelled on **Nessus**, the vulnerability scanner most widely
used in this space. A *finding* is one problem on one machine.

**New to this?** Start with [**OVERVIEW.md**](OVERVIEW.md) — a plain-language map
with diagrams of the tables and how data is produced (no cybersecurity background
assumed). Then [**TUTORIAL.md**](TUTORIAL.md) walks through the whole thing in
small steps — install it, run it, then follow one critical finding from raw
scanner output all the way to an overdue report, querying the database yourself at
each stage.

---

## Setup and run

You need the **.NET 8 SDK** and a **PostgreSQL server**. On Windows both install
from `winget`; on macOS or Linux use your usual package manager, or run Postgres
in Docker.

```bash
winget install Microsoft.DotNet.SDK.8      # no admin needed
winget install PostgreSQL.PostgreSQL.17    # needs admin — installs a service
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

Then, from the repository root in a fresh terminal so PATH picks up `dotnet`:

```bash
dotnet run
```

First run restores packages, creates the `scanprep` database, and prints thirteen
sections of output. **Running it again changes nothing** — verified by running it
twice and diffing row counts, not by assertion.

## Reading one report at a time

`dotnet run` prints all thirteen sections at once, which is no use when you are
trying to understand a single query. **`reports.ps1`** is a menu — it shows the
SQL, then runs it:

```bash
.\reports.ps1              # the menu
.\reports.ps1 -List        # list the reports, run nothing
.\reports.ps1 -Report 9    # run one and exit
```

The menu is built by parsing **`queries.sql`** — the same file the program reads.
There is no second copy of the SQL. `queries.sql` also stands alone if you would
rather work in psql directly; every query is read-only:

```bash
psql -U postgres -d scanprep -f queries.sql
```

### One copy of the report SQL, two readers

`queries.sql` is not a copy of anything. **It is where the report SQL lives.** The
C# reads it through `SqlLibrary.Get("...")`; the PowerShell menu parses the same
file. Edit a query there and both change.

**What that buys:**

- **The file runs as-is.** Any block pastes straight into a database console and
  runs — nothing to substitute first. This is why no query takes a parameter, and
  why `WorstOverdueAsync` writes `LIMIT 10` as a literal.
- **One copy.** The program and the menu cannot disagree, because there is no
  second thing to disagree with.

**What it costs:** a misspelled query name is a runtime crash, not a compile error —
the compiler cannot check a string against a file it never reads. Thirteen tests
(`dotnet test ScanIngest.Tests`) buy that back: every name the code looks up is
checked at build time against what the file defines, in both directions.

---

## How it's built

Six weekly scans of forty hosts, generated with realistic change from week to week —
findings persist, get remediated, and reappear. Each scan lands as raw `jsonb`, is
projected into a partitioned fact table, and is reconciled against a POA&M register
that opens, closes, and reopens commitments. A synthetic eMASS export provides the
second source, and the two are correlated.

The whole flow, in one line:

```
Generator → Ingest → finding → Poam.Sync → poam
                        ↓
     Controls (eMASS export + plugin↔control map) → correlation
```

Every file owns one subject, and the source is heavily commented — each method
carries a summary, and the non-obvious SQL is annotated line by line. Method-level
detail lives in the code; this is the map:

| File | What it owns |
|---|---|
| `Program.cs` | The sequence: bootstrap, ingest six scans, prove idempotency, print the reports. |
| `Generator.cs` | Stands in for Nessus. Invents findings, remembers the open set between scans. Touches no database. |
| `Ingest.cs` | The two-stage load: `COPY` into the landing table, then `INSERT … SELECT` into the fact table. |
| `Schema.cs` | All the DDL, with the design reasoning in the comments. |
| `Poam.cs` | The commitment register: opens, closes and reopens POA&Ms against each scan. |
| `Controls.cs` | The second source (eMASS export) and the correlation between it and the scanner. |
| `Findings.cs` | The five scan reports. |
| `SqlLibrary.cs` | Reads `queries.sql` and hands out a query by name. |
| `Models.cs` | Every record type — the shapes rows take. |
| `queries.sql` | Every report as plain, runnable SQL. The single source. |

Two `// C#:` conventions in the comments: ordinary comments explain **why**; lines
prefixed `// C#:` explain **what a piece of syntax means**, written for someone who
knows Java and is reading C# for the first time. If you write C# already, the
`// C#:` lines are prefixed so you can skip them at a glance.

---

## The design decisions worth defending

**1. A `jsonb` landing table.**
Nessus output is nested and its shape drifts between plugin versions. Forcing it
into columns on the way in means every scanner update breaks ingest. Land it raw,
project it on read: flexibility on ingest, discipline on query. *(A GIN index sits
on the payload. At 1,730 rows the planner correctly ignores it and sequential-scans
instead — `EXPLAIN` proves the index is valid but not yet worth using. Knowing the
difference between "the index is broken" and "the planner declined it" is most of
what index debugging is.)*

**2. Binary `COPY`, then a separate normalise step.**
`COPY` is roughly an order of magnitude faster than row-by-row `INSERT`, but it
**cannot express `ON CONFLICT`**. That is the whole reason for two stages: you can
have bulk speed or conflict handling in one statement, not both. The landing table
isn't ceremony — it's what makes fast *and* idempotent possible at once.

**3. Range partitioning by scan date.**
Findings accumulate per host, per plugin, per scan, forever. Monthly partitions
keep queries bounded and turn retention into a `DETACH PARTITION` instead of an
hour-long `DELETE`. *(The UTC offset on each boundary literal is load-bearing.
`scanned_at` is `timestamptz`, and a bare date literal in a partition bound is
resolved in the server's timezone — on a Pacific machine, `FOR VALUES FROM
('2026-08-01')` puts the boundary at 07:00 UTC, so a 03:00-UTC scan silently lands
in the wrong month. This was a real bug; fixed by writing `'2026-08-01 00:00:00+00'`.)*

**4. The primary key is the idempotency guarantee — and the key must be deterministic.**
`PRIMARY KEY (scanned_at, host, plugin_id)`. Scans get re-run and re-delivered, and
a pipeline that double-counts on replay quietly corrupts every number downstream —
where downstream is a POA&M an Authorizing Official signs.

But `ON CONFLICT` only protects you if replays produce the *same* keys. An early
version derived `scanned_at` from `UtcNow` and `scan_run_id` from `Guid.NewGuid()`,
so two runs minutes apart made different keys, nothing collided, and every row
inserted twice — the conflict clause working perfectly and protecting nothing.
Fixed by anchoring the dates to a fixed instant and deriving `scan_run_id` as an
MD5 of `source|timestamp`. **Replay safety is a property of your keys, not of your
conflict clause.** Section `[3]` of the output proves it: re-ingest the last scan,
row count doesn't move.

---

## The POA&M register

A finding is an **observation** — the scanner saw this, here, then; nobody is
accountable for it. A POA&M is a **commitment** — a named person accepted a gap and
promised a date. That difference drives the modelling:

| | `finding` | `poam` |
|---|---|---|
| keyed by | `(scanned_at, host, plugin_id)` | `(host, plugin_id)` |
| partitioned | yes, by scan month | no |
| lifetime | one scan | outlives every scan that observed it |

Reconciliation runs after **every** ingest, with three transitions:

- **open** — a finding in the latest scan with no POA&M yet. Its clock starts from
  when the problem was *first observed*, not from today, so a long-standing gap does
  not look fresh the moment someone finally writes it down.
- **reopen** — a closed item whose finding came back. Deliberately an `UPDATE` of
  the existing row, never a new one: a fresh row would reset the clock and hide the
  recurrence, which is precisely what an auditor is looking for — the fix did not hold.
- **close** — a POA&M whose finding no longer appears, dated to the *scan's* date,
  not `now()`. The scan is the evidence.

The due date is derived from severity at open time — 15 / 30 / 90 / 180 / 365 days
for critical through info — and **never recalculated**. The commitment was made on a
date; silently moving it would be the most dishonest thing this code could do.

Reconciliation always compares against the newest observed scan, not the scan just
ingested, so a late backfill of an old scan cannot reopen or close commitments on
stale data.

Each open commitment also carries a **ROM** (Rough Order of Magnitude) — a rough
effort estimate in hours, set from severity at open time like the due date.
Summed over the open register, it answers "roughly how much work is the backlog,"
which is one of the things a continuous-monitoring product is expected to report.

*(This is still a minimal register: it tracks the lifecycle a machine can
maintain — what, who, opened, due, effort, closed. The written plan and the
milestones that give "Plan of Action and Milestones" its name are free text a
human authors in eMASS. A pipeline can open, date, estimate and close a
commitment; it cannot write the plan.)*

---

## The correlation — the actual product

Two sources that disagree:

- **Nessus** answers *"what is broken on this host, right now."* Continuous.
- **eMASS** answers *"what did the assessor say about this system's controls."*
  Periodic, and in this data five weeks stale.

They drift apart, and **the gap is the product.** Nessus plugins map many-to-many
onto NIST 800-53 controls (`plugin_control`), which is what makes the two joinable
at all — one talks about hosts and plugins, the other about controls.

The assessor marks a control Non-Compliant only where they saw **high or critical**
evidence. That isn't laziness, it's how triage works — nobody fails a control over
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
An early version collapsed both to `clean`, which meant AC-2, AU-6, IA-5 and SI-4 —
all procedural controls no scanner will ever see — were reported to an Authorizing
Official as though something had checked them. Nothing had. A dashboard that cannot
tell *"we looked and it was fine"* from *"we never looked"* is worse than no
dashboard, because it manufactures confidence.

A final report covers the mirror-image gap: findings that map to no tracked control
at all. Either the mapping is incomplete or the authorisation package is.

---

## C# notes for a Java developer

- `record` ≈ Java record. Value equality, positional constructor.
- `await using` ≈ try-with-resources for `IAsyncDisposable`.
- `"""…"""` raw string literals ≈ Java text blocks.
- `?` on a type (`string?`, `long?`) is a nullable reference / value.
- `[…]` collection expressions are C# 12 — `new List<T>()` still works.
- `x switch { 4 => "critical", _ => "info" }` is a switch *expression* — `_` is the
  default, commas separate arms, no `case`/`break`.

## Where this would go next

- **Parse real SCAP/XCCDF** instead of generating findings. The landing table
  already tolerates whatever shape shows up, which was the point of it.
- **Control inheritance** — controls provided by the hosting enclave are inherited
  rather than assessed per-system, and the correlation has no concept of that yet.
- **ATO expiry and reauthorisation windows**, so the register can answer "what
  blocks reauthorisation in ninety days," not only "what is overdue now."
- **A third source**: STIG checklist results, which overlap the scanner imperfectly
  and would make the correlation genuinely three-way.
- Swap the console output for a minimal ASP.NET Core endpoint returning JSON.
