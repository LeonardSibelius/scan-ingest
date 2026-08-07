using Dapper;
using Npgsql;

namespace ScanIngest;

// =============================================================================
// Reports.cs — the read side.
//
// Dapper is a micro-ORM: you write the SQL, it maps result columns onto your
// types by name. For reporting work that is exactly the right level of
// abstraction. The SQL *is* the logic here — every report is a question about
// how the data changed over time, and expressing that through an ORM's object
// graph would mean writing the same query badly and then hiding it.
//
// Every method follows the same shape:
//
//     public static async Task<IEnumerable<TRow>> XAsync(NpgsqlConnection conn) =>
//         await conn.QueryAsync<TRow>("""...SQL...""");
//
// C# notes for that signature:
//   - `static` class + static methods: no state, just functions over a connection.
//   - `=>` on a method is an expression body — the method is one expression.
//   - `"""..."""` is a raw string literal, C#'s text block. No escaping needed,
//     which is why the SQL reads like SQL.
//   - `Task<T>` is Java's CompletableFuture<T>; `async`/`await` is the language
//     doing the continuation-passing for you.
//   - `QueryAsync<T>` is a Dapper extension method on IDbConnection — the
//     `using Dapper;` above is what makes it appear on NpgsqlConnection.
// =============================================================================

public static class Reports
{
    /// <summary>
    /// Open findings grouped by severity, for the most recent scan only.
    ///
    /// The "latest" CTE is a pattern repeated throughout this file: order the
    /// scan runs by date, take one, and join everything else to it. Selecting a
    /// run by date rather than hardcoding one means the report is correct
    /// whenever it runs and whatever data is present.
    /// </summary>
    /// <returns>One row per severity present, worst first.</returns>
    public static async Task<IEnumerable<SeverityRow>> BySeverityAsync(NpgsqlConnection conn) =>
        await conn.QueryAsync<SeverityRow>("""
            -- Pick the most recent scan run.
            WITH latest AS (
                SELECT scan_run_id
                FROM scan_run
                ORDER BY scanned_at DESC
                LIMIT 1
            )
            -- Count its findings per severity. The join to `latest` is what
            -- restricts this to one scan instead of the whole history.
            SELECT f.severity AS Severity, COUNT(*) AS N
            FROM finding f
            JOIN latest l ON l.scan_run_id = f.scan_run_id
            GROUP BY f.severity
            ORDER BY f.severity DESC
            """);

    /// <summary>
    /// Classifies every finding across the two most recent scans as new,
    /// resolved, or still open. This is the core continuous-monitoring question:
    /// a snapshot tells you the size of the problem, but only the delta tells you
    /// whether anyone is making progress.
    ///
    /// Two techniques worth understanding here:
    ///
    /// ROW_NUMBER() OVER (ORDER BY scanned_at DESC) numbers the scan runs newest
    /// first, so rn=1 is the current scan and rn=2 the previous one. Picking them
    /// this way means no dates are hardcoded and no assumption is made about the
    /// scan interval.
    ///
    /// FULL OUTER JOIN is what makes all three categories fall out of one query.
    /// An inner join would only ever show findings present in both scans — the
    /// "still open" bucket — and silently lose the two interesting ones. With a
    /// full outer join, a NULL on the previous side means the finding is new, and
    /// a NULL on the current side means it was resolved.
    /// </summary>
    public static async Task<IEnumerable<DeltaRow>> DeltaAsync(NpgsqlConnection conn) =>
        await conn.QueryAsync<DeltaRow>("""
            -- Number the scans newest-first so we can name "current" and "previous"
            -- without knowing any actual dates.
            WITH runs AS (
                SELECT scan_run_id,
                       ROW_NUMBER() OVER (ORDER BY scanned_at DESC) AS rn
                FROM scan_run
            ),
            -- The identity of a finding, for comparison purposes, is (host, plugin).
            -- Severity and name are properties of the plugin, not of the occurrence.
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
            -- FULL OUTER JOIN keeps rows that exist on only one side, and the
            -- NULLs it produces are what identify which side they came from.
            SELECT CASE
                       WHEN p.host IS NULL THEN 'new'         -- absent last time
                       WHEN c.host IS NULL THEN 'resolved'    -- absent this time
                       ELSE 'still open'                      -- present in both
                   END AS Status,
                   COUNT(*) AS N
            FROM cur c
            FULL OUTER JOIN prev p
              ON c.host = p.host AND c.plugin_id = p.plugin_id
            GROUP BY 1
            ORDER BY 1
            """);

    /// <summary>
    /// How long the currently-open findings have been open, averaged per severity.
    ///
    /// This is the aging question, and it matters because "twelve criticals" is
    /// not one fact. Twelve criticals found yesterday is a bad week. Twelve
    /// criticals open for ninety days is a broken remediation process, and it is
    /// the second one an Authorizing Official will ask about.
    ///
    /// The `first_seen` CTE computes, for every (host, plugin) pair ever observed,
    /// the earliest scan that reported it. Ageing is then measured from that
    /// point to the latest scan — not from when the row was inserted, which would
    /// measure the pipeline rather than the problem.
    /// </summary>
    public static async Task<IEnumerable<AgingRow>> AgingAsync(NpgsqlConnection conn) =>
        await conn.QueryAsync<AgingRow>("""
            WITH latest AS (
                SELECT scan_run_id, scanned_at
                FROM scan_run ORDER BY scanned_at DESC LIMIT 1
            ),
            -- Earliest observation of each distinct problem, across all history.
            -- This is why the fact table keeps every scan rather than overwriting:
            -- without history there is no such thing as an age.
            first_seen AS (
                SELECT host, plugin_id, MIN(scanned_at) AS first_seen
                FROM finding
                GROUP BY host, plugin_id
            )
            SELECT f.severity AS Severity,
                   COUNT(*)   AS N,
                   -- EXTRACT(EPOCH FROM interval) gives seconds; /86400 gives days.
                   -- Cast to numeric before ROUND because ROUND(double, int) does
                   -- not exist in Postgres — a genuinely common trip-up.
                   ROUND(AVG(
                       EXTRACT(EPOCH FROM (l.scanned_at - fs.first_seen)) / 86400
                   )::numeric, 1) AS AvgDaysOpen
            FROM finding f
            JOIN latest l      ON l.scan_run_id = f.scan_run_id
            JOIN first_seen fs ON fs.host = f.host AND fs.plugin_id = f.plugin_id
            GROUP BY f.severity
            ORDER BY f.severity DESC
            """);

    /// <summary>
    /// High-and-critical count per scan, with the change from the scan before it.
    ///
    /// The idiom worth taking away: LAG() applied to an aggregate. Postgres
    /// evaluates GROUP BY first, then window functions over the grouped rows, so
    /// `LAG(COUNT(*) FILTER (...)) OVER (ORDER BY scanned_at)` means "the count
    /// from the previous group". No self-join, no subquery.
    ///
    /// FILTER (WHERE ...) is the SQL-standard way to conditionally aggregate —
    /// cleaner than COUNT(CASE WHEN ... THEN 1 END) and it reads as what it is.
    ///
    /// The first row's Prev and Delta are NULL: there is no earlier scan. That is
    /// correct behaviour, not a gap to be COALESCEd away — the caller prints a
    /// dash, because "no change recorded" and "change of zero" are different
    /// statements and conflating them would be a small lie.
    /// </summary>
    public static async Task<IEnumerable<TrendRow>> TrendAsync(NpgsqlConnection conn) =>
        await conn.QueryAsync<TrendRow>("""
            SELECT scanned_at AS ScannedAt,
                   COUNT(*) FILTER (WHERE severity >= 3) AS HighCrit,
                   -- Previous scan's count, via a window over the grouped rows.
                   LAG(COUNT(*) FILTER (WHERE severity >= 3))
                       OVER (ORDER BY scanned_at) AS Prev,
                   -- And the difference. NULL on the first row, by design.
                   COUNT(*) FILTER (WHERE severity >= 3)
                     - LAG(COUNT(*) FILTER (WHERE severity >= 3))
                       OVER (ORDER BY scanned_at) AS Delta
            FROM finding
            GROUP BY scanned_at
            ORDER BY scanned_at
            """);

    /// <summary>
    /// Total rows in the fact table, across every scan.
    ///
    /// Used by the idempotency check in Program.cs: take it before a re-ingest,
    /// take it after, and assert nothing moved. A count is a crude invariant, but
    /// it is the exact one that would have caught the replay bug this pipeline
    /// originally shipped with.
    /// </summary>
    public static async Task<long> TotalFactRowsAsync(NpgsqlConnection conn) =>
        await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM finding");
}
