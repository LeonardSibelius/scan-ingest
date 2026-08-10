-- =============================================================================
-- queries.sql — every report in this project.
--
-- This is not a copy of the SQL the program runs. It IS that SQL. Exactly two
-- pieces of code open this file:
--
--     reports.ps1     the PowerShell menu — re-reads it before every menu turn
--     SqlLibrary.cs   parses it once, then hands out a query when asked by name
--
-- Edit a query here and both of them change.
--
-- Nothing else touches it, and the C# reaches it at four removes:
--
--     Program.cs
--        calls Findings.cs, Poam.cs, Controls.cs
--          which call SqlLibrary.Get("BySeverityAsync")
--            which reads this file
--
-- So Program.cs never mentions queries.sql, and neither does any report method
-- mention a file path. Each one knows a NAME — the same name written in the
-- header block below it.
--
--
-- WHAT IS IN HERE, AND WHAT IS NOT
--
-- Reads only. All ten blocks below are SELECTs, and nothing in this file changes
-- any data. The writes — INSERT, UPDATE, DELETE, COPY, CREATE — are all in the
-- C#: Schema.cs, Ingest.cs, Poam.cs, Controls.cs, PluginCatalog.cs.
--
-- That split is not housekeeping. Every write in this project takes parameters,
-- because it puts different values in each time — and a parameter placeholder is
-- precisely what this file cannot hold. psql has no value to substitute for one,
-- so a single @name anywhere below would make `psql -f queries.sql` fail to
-- parse. It is the same constraint that makes WorstOverdueAsync write LIMIT 10
-- as a literal.
--
-- So the writes could not live here even if that were wanted. What the rule buys
-- is that anything in this file can be pasted into a console and run without
-- reading it first to find out what it does.
--
--
-- THE COMMENT BLOCKS BELOW ARE NOT DECORATION
--
-- Postgres throws them away. The two parsers live on them. Every report must
-- look exactly like this:
--
--     -- ============================
--     -- SomeFile.cs -> MethodName        <- the name, and the menu heading
--     -- one or more lines of prose       <- the menu description
--     -- ============================
--     SELECT ... ;                        <- everything up to the next block
--
-- The rules of equals signs are the brackets. The arrow line is what makes a
-- block a report rather than just a header — this banner has no arrow line,
-- which is the only reason it is not report number one.
--
-- The spaces around the arrow are load-bearing. Lose one and that report
-- silently disappears from the menu: no error, no warning, just a shorter list.
-- ScanIngest.Tests exists to catch precisely that.
--
--
-- Run them all at once:
--     psql -U postgres -d scanprep -f queries.sql
--
-- Or open a session and paste one at a time:
--     psql -U postgres -d scanprep
--
-- On Windows, psql is not on your PATH. The full path is:
--     "C:\Program Files\PostgreSQL\17\bin\psql.exe"
--
-- Read-only, all of it. Paste anything below into a console without checking
-- first to see what it does.
-- =============================================================================


-- =============================================================================
-- Findings.cs -> TotalFactRowsAsync
-- The simplest one. Every finding, every scan.
-- =============================================================================
SELECT COUNT(*) FROM finding;


-- =============================================================================
-- Findings.cs -> BySeverityAsync
-- Open findings by severity, LATEST SCAN ONLY.
--
-- The `latest` block finds the newest scan and holds its id. Joining to it keeps
-- only that scan's rows. Drop the block and the join, and the same problems get
-- counted once for every scan they appear in — six times over.
-- =============================================================================
WITH latest AS (
    SELECT scan_run_id
    FROM scan_run
    ORDER BY scanned_at DESC
    LIMIT 1
)
SELECT f.severity AS Severity, COUNT(*) AS N
FROM finding f
JOIN latest l ON l.scan_run_id = f.scan_run_id
GROUP BY f.severity
ORDER BY f.severity DESC;


-- =============================================================================
-- Findings.cs -> TrendAsync
-- High+critical per scan, with the change since the previous scan.
--
-- Deliberately does NOT filter to one scan — the question is how the number
-- moved across all six. LAG() reads a value from the previous row: here, the
-- previous scan's high+critical count. Subtract that from this scan's, and you
-- have the change.
-- =============================================================================
SELECT scanned_at AS ScannedAt,
       COUNT(*) FILTER (WHERE severity >= 3) AS HighCrit,
       LAG(COUNT(*) FILTER (WHERE severity >= 3))
           OVER (ORDER BY scanned_at) AS Prev,
       COUNT(*) FILTER (WHERE severity >= 3)
         - LAG(COUNT(*) FILTER (WHERE severity >= 3))
           OVER (ORDER BY scanned_at) AS Delta
FROM finding
GROUP BY scanned_at
ORDER BY scanned_at;


-- =============================================================================
-- Findings.cs -> DeltaAsync
-- New / resolved / still-open, comparing the two most recent scans.
--
-- The OVER keyword makes ROW_NUMBER() a "window function". Where GROUP BY folds
-- rows together into one summary, a window function keeps every row and lets each
-- one see the others around it. ORDER BY inside the OVER says in what order.
--
-- Here that means: keep all six scans, line them up newest-first, and hand each
-- one a number. ROW_NUMBER() numbers them — the latest is 1, the one before it
-- is 2. Then rn = 1 and rn = 2 below pick those two, so this always compares
-- "this scan" against "the one before it" without naming any dates.
--
-- FULL OUTER JOIN lines the two scans up side by side and keeps a row even when
-- one side is empty. In this week only = "new"; last week only = "resolved";
-- both = "still open". A plain (inner) join keeps only rows in BOTH, so it could
-- never show new or resolved.
-- =============================================================================
WITH runs AS (
    SELECT scan_run_id,
           ROW_NUMBER() OVER (ORDER BY scanned_at DESC) AS rn
    FROM scan_run
),
cur AS (
    SELECT f.host, f.plugin_id
    FROM finding f JOIN runs r ON r.scan_run_id = f.scan_run_id
    WHERE r.rn = 1
),
prev AS (
    SELECT f.host, f.plugin_id
    FROM finding f JOIN runs r ON r.scan_run_id = f.scan_run_id
    WHERE r.rn = 2
)
SELECT CASE
           WHEN p.host IS NULL THEN 'new'
           WHEN c.host IS NULL THEN 'resolved'
           ELSE 'still open'
       END AS status,
       COUNT(*) AS n
FROM cur c
FULL OUTER JOIN prev p
  ON c.host = p.host AND c.plugin_id = p.plugin_id
GROUP BY 1
ORDER BY 1;


-- =============================================================================
-- Findings.cs -> AgingAsync
-- How long currently-open findings have been open, averaged per severity.
--
-- Age needs TWO dates, which is why there are two CTEs. `latest` is the ruler's
-- zero mark — the newest scan, i.e. "now". `first_seen` is where each problem
-- started: MIN(scanned_at) per (host, plugin), the EARLIEST scan that saw it. A
-- problem open since July appears in all six scans; MIN grabs the first.
--
-- Age is therefore measured from when the problem was FIRST SEEN, not from when
-- this program loaded the row. Measuring from load time would tell you how long
-- ago the pipeline ran, not how long the machine has had the problem.
--
-- The epoch line turns "now minus first-seen" into a number of days:
--   scanned_at - first_seen        gives an INTERVAL, which prints as "35 days"
--   EXTRACT(EPOCH FROM ...)         gives its length in SECONDS (a real number)
--   / 86400                         seconds -> days (86400 = 60*60*24)
-- The detour through seconds is needed because you cannot AVG() an interval that
-- prints as words; you can only average a number.
-- =============================================================================
WITH latest AS (
    SELECT scan_run_id, scanned_at
    FROM scan_run ORDER BY scanned_at DESC LIMIT 1
),
first_seen AS (
    SELECT host, plugin_id, MIN(scanned_at) AS first_seen
    FROM finding
    GROUP BY host, plugin_id
)
SELECT f.severity AS Severity,
       COUNT(*)   AS N,
       ROUND(AVG(
           EXTRACT(EPOCH FROM (l.scanned_at - fs.first_seen)) / 86400
       )::numeric, 1) AS AvgDaysOpen
FROM finding f
JOIN latest l      ON l.scan_run_id = f.scan_run_id
JOIN first_seen fs ON fs.host = f.host AND fs.plugin_id = f.plugin_id
GROUP BY f.severity
ORDER BY f.severity DESC;


-- =============================================================================
-- Poam.cs -> StatusAsync
-- Open commitments per severity, and how many blew their deadline.
--
-- asof is a one-row CTE holding the newest scan date. "Overdue" is measured
-- against THAT, not against today. If the scanner has not run for three weeks,
-- nothing has been checked for three weeks — and counting those three weeks as
-- overdue would invent lateness that no scan supports.
--
-- SlaDays shows the promise next to the performance: 13 open, deadline 15 days,
-- 7 already past it. MAX(CASE ...) looks strange wrapping a per-severity constant,
-- but the rows are grouped by severity, so every row in a group yields the same
-- number; MAX just lifts that one value out of the group. Any aggregate would do.
--
-- A note on reading the result: only criticals and highs ever show as overdue
-- here, because this data spans 35 days and a medium's deadline is 90. "0 overdue
-- mediums" means the window is short, NOT that mediums are being kept on time.
-- =============================================================================
WITH asof AS (SELECT MAX(scanned_at)::date AS d FROM scan_run)
SELECT p.severity AS Severity,
       COUNT(*)   AS Open,
       COUNT(*) FILTER (WHERE p.due_on < (SELECT d FROM asof)) AS Overdue,
       MAX(CASE p.severity
               WHEN 4 THEN 15 WHEN 3 THEN 30 WHEN 2 THEN 90
               WHEN 1 THEN 180 ELSE 365 END) AS SlaDays
FROM poam p
WHERE p.closed_on IS NULL
GROUP BY p.severity
ORDER BY p.severity DESC;


-- =============================================================================
-- Poam.cs -> ByOwnerAsync
-- Load per accountable owner. Not "how broken is the system" but "who is
-- carrying it, and who is drowning".
--
-- Almost the same query as StatusAsync above. Same table, same open filter, same
-- overdue count, same asof CTE — the ONLY real change is GROUP BY p.owner instead
-- of GROUP BY p.severity. That one word is the "per what?" of the report: per
-- severity gives a risk view, per owner gives an accountability view. The rows
-- are the same; only the buckets differ.
--
-- ORDER BY 3 DESC, 1 sorts by COLUMN NUMBER, not name: column 3 (overdue), biggest
-- first, then column 1 (owner) alphabetically to break ties. Overdue leads rather
-- than open because overdue is the column that needs a conversation — the busiest
-- owner may be fine; the one missing deadlines is the one to call.
-- =============================================================================
WITH asof AS (SELECT MAX(scanned_at)::date AS d FROM scan_run)
SELECT p.owner   AS Owner,
       COUNT(*)  AS Open,
       COUNT(*) FILTER (WHERE p.due_on < (SELECT d FROM asof)) AS Overdue
FROM poam p
WHERE p.closed_on IS NULL
GROUP BY p.owner
ORDER BY 3 DESC, 1;


-- =============================================================================
-- Poam.cs -> WorstOverdueAsync
-- The list an Authorizing Official actually asks for: names, machines,
-- deadlines, days late.
--
-- The row limit is a literal, not a parameter. This one file is the single copy
-- of the SQL that BOTH psql and the C# program read, so it has to satisfy both. A
-- @limit placeholder would work for the program but psql has nothing to fill it
-- with — psql -f queries.sql would fail to parse — and there is no separate copy
-- to give psql instead. A literal works everywhere.
-- =============================================================================
WITH asof AS (SELECT MAX(scanned_at)::date AS d FROM scan_run)
SELECT p.owner                                   AS Owner,
       p.host                                    AS Host,
       p.plugin_id                               AS PluginId,
       p.plugin_name                             AS PluginName,
       p.severity                                AS Severity,
       to_char(p.due_on, 'YYYY-MM-DD')           AS DueOn,
       ((SELECT d FROM asof) - p.due_on)::int    AS DaysOverdue
FROM poam p
WHERE p.closed_on IS NULL
  AND p.due_on < (SELECT d FROM asof)
ORDER BY p.severity DESC, DaysOverdue DESC
LIMIT 10;


-- =============================================================================
-- Controls.cs -> CorrelateAsync
-- THE POINT OF THE WHOLE PROJECT: where the scanner and the compliance record
-- disagree.
--
-- Four CTEs feed one verdict. latest_scan and latest_export pick which scan and
-- which assessment to compare; control_evidence counts the findings against each
-- control; and coverage counts how many scanner plugins can speak to each control
-- at all. That last one is the whole trick.
--
-- Five verdicts, and `not assessable` is kept distinct from `verified clean`.
-- Both have zero findings, so on the finding count alone they look identical —
-- but they are opposite facts: "we looked and it was fine" versus "nothing could
-- look". coverage is what tells them apart. A control with no plugins mapped to it
-- never appears in coverage, so the LEFT JOIN leaves its sources NULL, COALESCE
-- turns that into 0, and the CASE tests `sources = 0` FIRST — before anything
-- else — and stops at 'not assessable'. Reporting such a control as clean would
-- manufacture confidence for an Authorizing Official that nothing supports.
-- =============================================================================
WITH latest_scan AS (
    SELECT scan_run_id FROM scan_run ORDER BY scanned_at DESC LIMIT 1
),
latest_export AS (
    SELECT export_id
    FROM control_status
    ORDER BY exported_at DESC, export_id
    LIMIT 1
),
coverage AS (
    SELECT control_id, COUNT(*) AS sources
    FROM plugin_control
    GROUP BY control_id
),
control_evidence AS (
    SELECT pc.control_id,
           COUNT(*)               AS findings,
           MAX(f.severity)        AS worst_severity,
           COUNT(DISTINCT f.host) AS hosts_affected
    FROM finding f
    JOIN latest_scan ls    ON ls.scan_run_id = f.scan_run_id
    JOIN plugin_control pc ON pc.plugin_id = f.plugin_id
    GROUP BY pc.control_id
)
SELECT cs.control_id                       AS ControlId,
       c.title                             AS Title,
       cs.compliance                       AS Compliance,
       COALESCE(ce.findings, 0)            AS Findings,
       ce.worst_severity                   AS WorstSeverity,
       COALESCE(ce.hosts_affected, 0)      AS HostsAffected,
       COALESCE(cv.sources, 0)             AS EvidenceSources,
       CASE
           WHEN COALESCE(cv.sources, 0) = 0
                THEN 'not assessable'
           WHEN cs.compliance = 'Compliant'     AND ce.findings > 0
                THEN 'CONTRADICTED'
           WHEN cs.compliance = 'Non-Compliant' AND ce.findings > 0
                THEN 'corroborated'
           WHEN cs.compliance = 'Non-Compliant'
                THEN 'unevidenced'
           ELSE 'verified clean'
       END                                 AS Verdict
FROM control_status cs
JOIN latest_export le ON le.export_id = cs.export_id
JOIN control c        ON c.control_id = cs.control_id
LEFT JOIN coverage cv         ON cv.control_id = cs.control_id
LEFT JOIN control_evidence ce ON ce.control_id = cs.control_id
ORDER BY
    CASE
        WHEN cs.compliance = 'Compliant' AND ce.findings > 0 THEN 0
        WHEN COALESCE(cv.sources, 0) = 0 THEN 1
        WHEN cs.compliance = 'Non-Compliant' AND ce.findings > 0 THEN 2
        WHEN cs.compliance = 'Non-Compliant' THEN 3
        ELSE 4
    END,
    COALESCE(ce.worst_severity, 0) DESC,
    COALESCE(ce.findings, 0) DESC;


-- =============================================================================
-- Controls.cs -> UncoveredAsync
-- The mirror-image gap: findings from plugins that map to NO tracked control.
-- Either the mapping is incomplete or the authorisation package is.
--
-- The exact opposite of CorrelateAsync's coverage check. That one found CONTROLS
-- no scanner can see; this finds FINDINGS no control can file. Together they check
-- coverage from both ends. In this data the two rows are the scanner's own
-- housekeeping plugins (Nessus SYN scanner, Scan Information) — correctly unmapped.
-- A real critical showing up here would be a genuine gap: the scanner reporting a
-- risk the paperwork has nowhere to put.
--
-- NOT EXISTS is an ANTI-JOIN — keep a finding only if NO matching plugin_control
-- row exists for its plugin. A normal join keeps rows that HAVE a match; this
-- keeps rows that do not. The SELECT 1 is idiomatic: inside EXISTS the columns are
-- ignored, only whether a row exists matters.
--
-- NOT EXISTS rather than NOT IN, deliberately: NOT IN against a set containing any
-- NULL returns nothing at all, silently. Same choice as the close logic in Poam.cs.
-- =============================================================================
WITH latest_scan AS (
    SELECT scan_run_id FROM scan_run ORDER BY scanned_at DESC LIMIT 1
)
SELECT f.plugin_id     AS PluginId,
       f.plugin_name   AS PluginName,
       MAX(f.severity) AS Severity,
       COUNT(*)        AS Findings
FROM finding f
JOIN latest_scan ls ON ls.scan_run_id = f.scan_run_id
WHERE NOT EXISTS (
    SELECT 1 FROM plugin_control pc WHERE pc.plugin_id = f.plugin_id
)
GROUP BY f.plugin_id, f.plugin_name
ORDER BY MAX(f.severity) DESC, COUNT(*) DESC;
