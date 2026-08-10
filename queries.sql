-- =============================================================================
-- queries.sql — every report in this project.
--
-- This is not a copy of the SQL the program runs. It IS that SQL. Two separate
-- programs read this one file:
--
--     reports.ps1     the PowerShell menu — re-reads it before every menu turn
--     SqlLibrary.cs   which the C# calls to fetch a query by name
--
-- Edit a query here and both of them change.
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
-- The `latest` CTE picks one scan; the join to it filters everything else out.
-- Drop those two pieces and you get the same problems counted six times over.
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
-- moved across all six. LAG() reaches back to the previous grouped row.
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
-- ROW_NUMBER() picks the last two runs without hardcoding any dates.
-- FULL OUTER JOIN is what makes all three categories fall out of one query:
-- an inner join would only ever show findings present in BOTH scans.
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
-- Measured from FIRST OBSERVATION, not from when the row was inserted — that
-- would measure the pipeline instead of the estate.
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
-- "As of" is the date of the most recent SCAN, not today. If the scanner has
-- not run for three weeks, nothing has been observed for three weeks, and
-- ageing against wall-clock time would invent overdue days nothing supports.
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
-- The row limit is a literal rather than a parameter, deliberately. This file
-- has to run under psql as well as through the C#, and psql cannot parse a
-- parameter placeholder it has no value for.
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
-- Five verdicts. `not assessable` is kept distinct from `verified clean`
-- because a control no scanner can see was never checked, and reporting it as
-- clean manufactures confidence for an Authorizing Official.
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
