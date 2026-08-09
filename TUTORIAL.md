# Tutorial

A guided walk through this project, in small steps. No prior knowledge of security
compliance, C#, or Postgres is assumed — where a step needs one of those, it says so.

You will spend most of it querying the database directly rather than reading code,
because the point of the code is the shape of the data it produces. Each step ends
with a pointer into the source, so you can read the comment that explains what you
just saw.

**Total time:** about an hour, or 25 minutes if you stop after Part 3.

If you only want to *see* the reports rather than understand the data underneath
them, do Part 1 and then skip straight to **Part 6** — it runs each report and
shows you the SQL that produced it.

---

## Part 1 — Get it running

### Step 1 — Install the two things you need

The **.NET 8 SDK** compiles and runs the program. **PostgreSQL** stores the data.

On Windows:

```bash
winget install Microsoft.DotNet.SDK.8
```

```bash
winget install PostgreSQL.PostgreSQL.17
```

On macOS or Linux, install `dotnet` from Microsoft's site and Postgres from your
package manager or Docker.

Note the superuser password the Postgres installer asks for. This tutorial assumes
it is `postgres`.

**Then close your terminal and open a new one.** Installers change your `PATH`,
and an already-open terminal will not see it.

Check both landed:

```bash
dotnet --version
```

You should get something like `8.0.423`.

---

### Step 2 — Run the program

From the repository root:

```bash
dotnet run
```

The first run takes a minute — it downloads two libraries, creates a database
called `scanprep`, builds the tables, and then does its work. Later runs are fast.

**You should see** thirteen numbered sections scroll past, ending with `done.`

If it fails with a connection error, jump to **Troubleshooting** at the bottom.

---

### Step 3 — Understand what you just watched

Those thirteen sections are three separate stories. You do not need to follow them yet,
just know the shape:

| Sections | Story |
|---|---|
| `[1]`–`[3]` | **Loading.** Six weekly scans go into the database. Then the same scan is loaded a second time to prove nothing doubles. |
| `[4]`–`[7]` | **What the scanner sees.** How many problems, what changed since last week, how long things have been broken. |
| `[8]`–`[13]` | **What it means.** Who promised to fix what and by when — and where the security paperwork disagrees with the scanner. |

The interesting one is the third. The first two are how you earn the right to it.

> **Thirteen sections is a lot at once, and there is no way to ask the program for
> just one.** That is what `reports.ps1` is for, and **Part 6** at the end covers
> it. Come back to it whenever the firehose gets tiring — it runs any single report
> and shows you the SQL that produced it.

---

## Part 2 — Look inside the database

### Step 4 — Open a database session

Everything from here happens at the Postgres prompt.

**Run ONE of the following — whichever matches your machine.** They do the same
thing; the Windows one just needs the full path, because the installer does not
put `psql` on your `PATH`.

**On Windows** (PowerShell):

```bash
$env:PGPASSWORD='postgres'; & "C:\Program Files\PostgreSQL\17\bin\psql.exe" -U postgres -d scanprep
```

**On macOS or Linux:**

```bash
psql -U postgres -d scanprep
```

Your prompt changes to `scanprep=#`. **Leave this window open** — the rest of the
tutorial pastes queries into it. Open a second terminal when you need to run
`dotnet run` again.

#### Reading the prompt

From here on you are talking to the database, not to your shell. Shell commands
typed here will not work. The prompt tells you what psql is waiting for:

| Prompt | Meaning |
|---|---|
| `scanprep=#` | Ready for a new statement. This is the normal state. |
| `scanprep-#` | Mid-statement — it is waiting for you to finish and add a `;`. |
| `scanprep'#` | You have an unclosed quote. |
| `scanprep(#` | You have an unclosed bracket. |

**If you end up on any prompt other than `=#` and you did not mean to, press
Ctrl+C.** That discards whatever is half-typed and returns you to `=#`. Nothing is
harmed — the most common cause is pasting something that is not SQL.

Two more things: every SQL statement ends with a semicolon, and `\q` quits.

> **A warning you can ignore on Windows.** psql may print *"Console code page (437)
> differs from Windows code page (1252)"*. It is cosmetic — it only affects how
> accented characters display, and there are none in this data.

---

### Step 5 — See what tables exist

```sql
\dt
```

**You should see** nine relations:

```
 public | control         | table
 public | control_status  | table
 public | finding         | partitioned table
 public | finding_2026_07 | table
 public | finding_2026_08 | table
 public | plugin_control  | table
 public | poam            | table
 public | raw_finding     | table
 public | scan_run        | table
```

**What this shows.** Three groups. `scan_run`, `raw_finding` and `finding` are the
scanner data. `poam` is the commitments. `control`, `control_status` and
`plugin_control` are the compliance side.

Notice `finding` says **partitioned table**, and that `finding_2026_07` and
`finding_2026_08` sit beside it. That is one logical table physically split by
month. Step 12 comes back to it.

**In the source:** `Schema.cs` → the `Ddl` string. Every table above is created
there, and each carries a comment explaining why it is shaped the way it is.

---

### Step 6 — Look at raw scanner output

The scanner's output lands in `raw_finding` completely untouched, as JSON:

```sql
SELECT jsonb_pretty(payload) FROM raw_finding LIMIT 1;
```

**You should see** something like:

```
 {
     "cve": "CVE-2017-0143",
     "host": "host-005.mil",
     "severity": 4,
     "plugin_id": 97833,
     "plugin_name": "SMBv1 Remote Code Execution"
 }
```

**What this shows.** One problem, on one machine. `severity: 4` is critical.
`plugin_id` identifies the specific check that found it — a *plugin* is one test
the scanner knows how to run, and its number never changes, which is what lets you
track the same problem week after week.

Nothing here has been validated or reshaped. That is deliberate: real scanner
output is messy and changes shape between versions, so it is stored as-is first
and interpreted second.

**In the source:** `Ingest.cs` → `IngestAsync`, the section marked **STAGE 1**.
The comment there explains why this landing table exists at all — it comes down to
one limitation in Postgres's fast-loading command.

---

## Part 3 — Follow one problem all the way through

This is the spine of the tutorial. We will take a single critical problem and
follow it from raw scanner output to an overdue report.

### Step 7 — Meet the problem

`host-005.mil` has SMBv1 enabled — the vulnerability behind the WannaCry outbreak.
Here it is in structured form:

```sql
SELECT scanned_at::date AS scan, host, plugin_name, severity
FROM finding
WHERE host = 'host-005.mil' AND plugin_id = 97833
ORDER BY scanned_at;
```

**You should see six rows:**

```
    scan    |     host     |         plugin_name         | severity
------------+--------------+-----------------------------+----------
 2026-07-03 | host-005.mil | SMBv1 Remote Code Execution |        4
 2026-07-10 | host-005.mil | SMBv1 Remote Code Execution |        4
 2026-07-17 | host-005.mil | SMBv1 Remote Code Execution |        4
 2026-07-24 | host-005.mil | SMBv1 Remote Code Execution |        4
 2026-07-31 | host-005.mil | SMBv1 Remote Code Execution |        4
 2026-08-07 | host-005.mil | SMBv1 Remote Code Execution |        4
```

**What this shows.** The same problem, found six weeks running. Nobody fixed it.

This is why the database keeps every scan instead of overwriting. One row would
tell you the problem exists. Six rows tell you it has been ignored for five weeks,
which is a completely different fact and the one that matters.

**In the source:** `Ingest.cs` → **STAGE 2**. The JSON from Step 6 became these
typed columns there. `->>` pulls a field out of the JSON as text, and the casts
like `::int` are the first point where malformed data would fail loudly.

---

### Step 8 — See the commitment it created

A finding is an observation. Nobody is accountable for an observation. So the
program turns it into a **POA&M** — a Plan of Action and Milestones entry, which
is a named person promising a date:

```sql
SELECT host, plugin_id, severity, owner, opened_on, due_on, closed_on
FROM poam
WHERE host = 'host-005.mil' AND plugin_id = 97833;
```

**You should see one row:**

```
     host     | plugin_id | severity |   owner    | opened_on  |   due_on   | closed_on
--------------+-----------+----------+------------+------------+------------+-----------
 host-005.mil |     97833 |        4 | ISSO-Alpha | 2026-07-03 | 2026-07-18 |
```

**What this shows.** Four things:

- **`owner`** — an ISSO, Information System Security Officer. The accountable person.
- **`opened_on`** — 3 July, the date the problem was *first observed*. Not the date
  somebody got around to writing it down.
- **`due_on`** — 18 July. Fifteen days later, because critical findings get a
  fifteen-day deadline.
- **`closed_on`** — empty. Still open.

The latest scan is 7 August. This commitment is **twenty days past its deadline.**

**In the source:** `Poam.cs` → `SyncAsync`. Read the summary comment above it:
it explains the three transitions (open, reopen, close) and why the due date is
computed once and never recalculated.

---

### Step 9 — See it in the overdue report

That single row is what the report at the end of the program is built from:

```sql
SELECT owner, host, plugin_name,
       to_char(due_on, 'YYYY-MM-DD') AS due,
       (SELECT max(scanned_at)::date FROM scan_run) - due_on AS days_late
FROM poam
WHERE closed_on IS NULL
  AND due_on < (SELECT max(scanned_at)::date FROM scan_run)
  AND severity = 4
ORDER BY days_late DESC;
```

**You should see** seven overdue criticals, including `host-005.mil` at 20 days.

**What this shows.** Notice `(SELECT max(scanned_at) FROM scan_run)` rather than
today's date. Lateness is measured against the last time anyone actually *looked*.
If the scanner has been down for three weeks, nothing has been observed for three
weeks, and counting those as overdue days would be inventing evidence.

**In the source:** `Poam.cs` → `WorstOverdueAsync`. The comment on `StatusAsync`
just above it spells out the "as of" reasoning.

---

### Step 10 — See one that got fixed

Not everything stays broken:

```sql
SELECT host, plugin_id, severity, owner, opened_on, due_on, closed_on
FROM poam
WHERE closed_on IS NOT NULL
LIMIT 3;
```

**You should see** rows with a `closed_on` date filled in.

**What this shows.** When a finding stops appearing in the scan, its commitment is
closed — and dated to the *scan* that stopped reporting it, not to when the program
happened to run. The scan is the evidence.

Count how many of each you have:

```sql
SELECT count(*) AS total,
       count(*) FILTER (WHERE closed_on IS NULL) AS still_open
FROM poam;
```

You should get **450 total, 276 still open**. So 174 problems were remediated over
the six weeks.

**In the source:** `Poam.cs` → `SyncAsync`, the section marked **CLOSE**. Note the
comment about `NOT EXISTS` rather than `NOT IN` — that one is a genuine trap.

---

## Part 4 — The two mechanisms worth understanding

### Step 11 — Prove that reloading changes nothing

A real pipeline gets re-run: a job retries, someone re-delivers a file, a deploy
replays yesterday. If that duplicates data, every number downstream is wrong.

Count the rows:

```sql
SELECT count(*) FROM finding;
```

You should get **1730**. Now, in your *other* terminal — not the psql one:

```bash
dotnet run
```

Then back at the psql prompt, count again:

```sql
SELECT count(*) FROM finding;
```

**Still 1730.** Nothing moved.

**What this shows.** Every row was offered to the database a second time and every
one was rejected as a duplicate. This works because a finding's identity is
`(scan date, host, plugin)` — the database itself refuses a second copy.

**In the source:** `Ingest.cs` → **STAGE 2**, the `ON CONFLICT DO NOTHING` line.
And read the `Program.cs` comment about `DeterministicRunId`: the first version of
this program used random ids and a clock reading, which meant nothing ever
*collided* and re-running silently doubled everything. The conflict rule was
working perfectly and protecting nothing.

---

### Step 12 — See the partitioning

```sql
SELECT tableoid::regclass AS partition, count(*)
FROM finding GROUP BY 1 ORDER BY 1;
```

**You should see:**

```
    partition    | count
-----------------+-------
 finding_2026_07 |  1454
 finding_2026_08 |   276
```

**What this shows.** You queried `finding`, but the rows physically live in two
separate monthly tables. Postgres routes them on write and searches only the
relevant ones on read.

Prove that second part:

```sql
EXPLAIN (COSTS OFF) SELECT count(*) FROM finding
WHERE scanned_at >= '2026-08-01 00:00:00+00';
```

**You should see** only `finding_2026_08` in the plan. July was skipped entirely
without being read.

This matters because scan data grows forever, and because deleting old data becomes
detaching one table rather than a `DELETE` that runs for an hour.

**In the source:** `Schema.cs` → `EnsurePartitionAsync`. Read the comment about the
`+00` on the boundary literals — leaving it off put month boundaries at local
midnight, which quietly filed scans into the wrong month.

---

### Step 13 — Find the contradiction

Now the part the whole project exists for.

The database holds a second, completely separate source: a **control assessment**,
where a human reviewed the system against a list of security requirements and
recorded a verdict for each.

```sql
SELECT control_id, compliance FROM control_status ORDER BY control_id;
```

**You should see** ten controls, each marked `Compliant` or `Non-Compliant`.

Now compare that against what the scanner actually found. `CM-6` is
"Configuration Settings":

```sql
SELECT compliance FROM control_status WHERE control_id = 'CM-6';
```

It says **Compliant**. But:

```sql
SELECT f.plugin_name, f.severity, count(*) AS findings
FROM finding f
JOIN scan_run r ON r.scan_run_id = f.scan_run_id
JOIN plugin_control pc ON pc.plugin_id = f.plugin_id
WHERE pc.control_id = 'CM-6'
  AND r.scanned_at = (SELECT max(scanned_at) FROM scan_run)
GROUP BY 1, 2;
```

**You should see:**

```
         plugin_name          | severity | findings
------------------------------+----------+----------
 TCP/IP Timestamps Supported  |        1 |       13
 HTTP Server Type and Version |        0 |       17
```

**Thirty live findings against a control the paperwork says is satisfied.**

**What this shows — and this is the whole idea.** Look at the severities: 1 and 0.
Low and informational. The assessor was not lying or careless. Assessors triage,
and nobody fails a security control over an informational finding.

But the scanner does not triage. It reports everything, every week, forever. So
low-severity evidence never reaches the compliance record while continuous
monitoring keeps seeing it — and the two drift apart *without anyone doing anything
wrong.*

That gap is not a data-quality problem to be cleaned up. It is the product.

**In the source:** `Controls.cs` → `GenerateExportAsync` creates the assessment and
its comment explains the `severity >= 3` triage line. `CorrelateAsync` finds the
disagreements and documents all five possible verdicts.

---

### Step 14 — The subtler finding

Run this:

```sql
SELECT c.control_id, cs.compliance, count(pc.plugin_id) AS evidence_sources
FROM control c
JOIN control_status cs ON cs.control_id = c.control_id
LEFT JOIN plugin_control pc ON pc.control_id = c.control_id
GROUP BY 1, 2 ORDER BY 3, 1;
```

**You should see** four controls — `AC-2`, `AU-6`, `IA-5`, `SI-4` — with
**zero evidence sources**, all marked Compliant.

**What this shows.** No scanner check maps to those controls at all. They are
procedural: account management, audit review, authenticator management, system
monitoring. A vulnerability scanner cannot see any of them, ever.

So "Compliant" there does not mean *checked and fine*. It means **nothing checked
it.** The program reports those as `not assessable` rather than `verified clean`,
because a dashboard that cannot tell "we looked and it was fine" from "we never
looked" manufactures confidence.

The first version of this code collapsed both into "clean". That was a bug, and a
worse one than a crash would have been.

**In the source:** `Controls.cs` → `CorrelateAsync`, the `coverage` CTE and the
`CASE` expression that uses it.

---

## Part 5 — Break it on purpose

The fastest way to understand a rule is to remove it and watch what goes wrong.
Each of these is reversible.

### Step 15 — Change a deadline

Open `Poam.cs` and find `SlaCase` near the top. Change the critical deadline from
15 days to 60:

```
WHEN 4 THEN 15    -- critical
```

becomes

```
WHEN 4 THEN 60    -- critical
```

Rebuild the world from scratch — in a terminal that is **not** your psql session:

```bash
dotnet run
```

Look at section `[8]`. **Critical overdue drops from 7 to 0**, because a 60-day
deadline on a problem first seen five weeks ago has not arrived yet.

Nothing else moves. The findings are identical; only the promise changed.

**Put it back to 15 when you are done.**

---

### Step 16 — Reproduce the doubling bug

Open `Ingest.cs`, find **STAGE 2** near the bottom, and delete this one line —
the whole line, so the SQL around it stays lined up:

```
            ON CONFLICT DO NOTHING
```

Wipe the database and run:

```bash
$env:PGPASSWORD='postgres'; & "C:\Program Files\PostgreSQL\17\bin\psql.exe" -U postgres -c "DROP DATABASE IF EXISTS scanprep;"
```

```bash
dotnet run
```

**What you should see.** Sections `[1]` and `[2]` succeed completely — all six
scans load without complaint. Then section `[3]` crashes:

```
[3] idempotency — re-ingesting the last scan
Unhandled exception. Npgsql.PostgresException (0x80004005):
  23505: duplicate key value violates unique constraint "finding_2026_08_pkey"
```

**What this shows.** Three things, and the third is the point.

**First**, the six scans loaded fine. Six different scans contain no duplicates
between them, so nothing collided. The bug only appears on *replay*.

**Second**, the constraint that stopped it is named `finding_2026_08_pkey` — the
primary key of the **August partition**, not of `finding` itself. That is
partitioning made visible: each partition enforces the key on its own rows.

**Third, and this is the lesson:** `ON CONFLICT DO NOTHING` was never what
prevented duplicates. **The primary key prevents duplicates.** The conflict clause
only decides whether the database's refusal arrives as a crash or as a shrug.
Delete it and the data is still protected — just noisily.

Which is exactly why the original bug was so quiet. The protection was in place and
working, but random run ids meant every replayed row looked *new*, so the key was
never asked a question it could answer. The guard was fine; nothing ever reached it.

**Put the line back**, then wipe and rebuild:

```bash
dotnet run
```

---

### Step 17 — Start over cleanly

At any point, to wipe everything and rebuild from scratch:

```sql
\q
```

```bash
$env:PGPASSWORD='postgres'; & "C:\Program Files\PostgreSQL\17\bin\psql.exe" -U postgres -c "DROP DATABASE IF EXISTS scanprep;"
```

```bash
dotnet run
```

The program recreates the database, the tables, and all the data. Nothing in it is
precious — the data is generated fresh from a fixed seed every time, which is why
your numbers match the ones in this tutorial exactly.

---

## Part 6 — Run the reports one at a time

Everything so far has been you writing SQL by hand. This part is the opposite:
ten prepared reports, each of which shows you its own SQL before it runs.

### Step 18 — Open the menu

From the repository root, in a **PowerShell** window — not the psql prompt:

```bash
.\reports.ps1
```

**You should see:**

```
==============================================================================
  scan-ingest reports
  database: scanprep
==============================================================================
   1. TotalFactRowsAsync     The simplest one. Every finding, every scan.
   2. BySeverityAsync        Open findings by severity, LATEST SCAN ONLY.
   3. TrendAsync             High+critical per scan, with the change since...
   4. DeltaAsync             New / resolved / still-open, comparing the two...
   5. AgingAsync             How long currently-open findings have been open...
   6. StatusAsync            Open commitments per severity, and how many blew...
   7. ByOwnerAsync           Load per accountable owner...
   8. WorstOverdueAsync      The list an Authorizing Official actually asks for...
   9. CorrelateAsync         THE POINT OF THE WHOLE PROJECT...
  10. UncoveredAsync         The mirror-image gap...

   A. run every report
   Q. quit
```

Type a number and press Enter.

**What you get.** Three things, in order: the description, **the SQL**, then the
results. That middle part is the point — the query and its output on screen
together, so you can see which line produced which column.

`Q` quits. `A` runs all ten.

---

### Step 19 — Read one properly

Type **`2`**.

`BySeverityAsync` is the simplest real query in the project, and everything else
in the file is built on the shape it uses:

```sql
WITH latest AS (
    SELECT scan_run_id FROM scan_run ORDER BY scanned_at DESC LIMIT 1
)
SELECT f.severity, COUNT(*)
FROM finding f
JOIN latest l ON l.scan_run_id = f.scan_run_id
GROUP BY f.severity
```

The `latest` block picks **one** scan run. The `JOIN` to it then throws away every
finding that belongs to a different scan — **a join to a one-row table is a filter
wearing a join's clothes.**

Prove it matters. Back at the psql prompt, run it without the filter:

```sql
SELECT severity, COUNT(*) FROM finding GROUP BY severity ORDER BY severity DESC;
```

You get **99 criticals** instead of 13. That 99 is not a fact about anything — it
is the same handful of problems counted once per scan. In a table that keeps
history, an unfiltered total is meaningless, and every query in this project opens
with a `latest` block because of it.

---

### Step 20 — Then read the one that matters

Type **`9`**.

`CorrelateAsync` is what the whole project exists to produce, and this is the
clearest look at how the verdict is actually derived — the `CASE` expression is
right there above its own output.

Trace one row. Find `CM-6` in the results, then find these lines in the SQL:

```sql
WHEN cv.control_id IS NULL                               THEN 'not assessable'
WHEN cs.compliance = 'Compliant'     AND ce.findings > 0 THEN 'CONTRADICTED'
```

`CM-6` has evidence sources, so the first test fails. It is marked `Compliant` and
has 30 live findings, so the second one hits. **That is the entire mechanism by
which this system catches a lie**, and it is four lines of `CASE`.

---

### Step 21 — Two shortcuts worth knowing

See what is available without entering the menu:

```bash
.\reports.ps1 -List
```

Run one report and exit — handy once you know the numbers:

```bash
.\reports.ps1 -Report 9
```

> **Where the SQL actually lives.** The menu has no copy of it. It parses
> **`queries.sql`** when it starts, which is the same SQL the C# runs, labelled
> with the method each one came from. Edit that file and the menu changes. If you
> would rather work in psql directly, `psql -U postgres -d scanprep -f queries.sql`
> runs all ten.

---

## Where to go next

- **`README.md`** has the design reasoning: why the landing table exists, why the
  commitment register is keyed differently from the findings table, and what the
  two bugs were.
- The **"A walk through the code"** section of the README lists every method and
  what it does.
- The source files themselves are commented throughout, including notes for readers
  coming from Java on the C# idioms used.

---

## Troubleshooting

**`dotnet: command not found`** — the installer changed your `PATH` but your
terminal was already open. Close it and open a new one.

**`28P01: password authentication failed`** — your Postgres superuser password is
not `postgres`. Point the program at the right one:

```bash
$env:SCANPREP_CONN = "Host=localhost;Port=5432;Username=postgres;Password=YOURPASSWORD"
```

**`Connection refused`** — Postgres is not running. On Windows, check the
`postgresql-x64-17` service is started. On macOS/Linux, `pg_ctl status` or
`systemctl status postgresql`.

**Numbers do not match this tutorial** — you probably have data from an earlier
run with different code. Do Step 17.

**`psql` is not found on Windows** — it is not added to `PATH` by the installer.
Use the full path shown in Step 4, or add `C:\Program Files\PostgreSQL\17\bin` to
your `PATH`. `reports.ps1` finds it on its own and does not need this.

**`reports.ps1 cannot be loaded because running scripts is disabled`** — Windows
blocks unsigned scripts by default. Allow them for your own account:

```bash
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

**The report menu prints but does not respond** — it needs a real terminal. If you
piped anything into it, or are running it from an editor's output pane, use
`.\reports.ps1 -List` and `.\reports.ps1 -Report N` instead.

**The psql prompt shows `-#` and nothing I type works** — psql is waiting for you
to finish a statement. Usually you pasted something that is not SQL, or left off a
semicolon. Press **Ctrl+C** to discard it and get back to `scanprep=#`.

**`syntax error at or near "psql"`** — you pasted a shell command into the database
prompt. The psql session and your shell are two different things; `dotnet run` and
`psql` belong in a shell, everything after Step 4 belongs at the `scanprep=#`
prompt. Keep two terminals open.
