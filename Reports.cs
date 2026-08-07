using Dapper;
using Npgsql;

namespace ScanIngest;

/// <summary>
/// The read side, via Dapper. Dapper is a micro-ORM: you write the SQL, it maps
/// the result columns onto your types by name. For reporting work that is exactly
/// the right level of abstraction — the SQL *is* the logic, and hiding it behind
/// an ORM buys nothing and costs clarity.
///
/// Every query here is a window-function query, because "what changed since the
/// last scan" is the entire question in continuous monitoring.
/// </summary>
public static class Reports
{
    /// Current open findings by severity, for the most recent scan.
    public static async Task<IEnumerable<SeverityRow>> BySeverityAsync(NpgsqlConnection conn) =>
        await conn.QueryAsync<SeverityRow>("""
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
            ORDER BY f.severity DESC
            """);

    /// New / resolved / still-open between the two most recent scans.
    /// ROW_NUMBER() picks the last two runs without hardcoding dates.
    public static async Task<IEnumerable<DeltaRow>> DeltaAsync(NpgsqlConnection conn) =>
        await conn.QueryAsync<DeltaRow>("""
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
                   END AS Status,
                   COUNT(*) AS N
            FROM cur c
            FULL OUTER JOIN prev p
              ON c.host = p.host AND c.plugin_id = p.plugin_id
            GROUP BY 1
            ORDER BY 1
            """);

    /// How long have currently-open findings been open? This is POA&M aging —
    /// the number an Authorizing Official actually cares about.
    public static async Task<IEnumerable<AgingRow>> AgingAsync(NpgsqlConnection conn) =>
        await conn.QueryAsync<AgingRow>("""
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
            JOIN latest l     ON l.scan_run_id = f.scan_run_id
            JOIN first_seen fs ON fs.host = f.host AND fs.plugin_id = f.plugin_id
            GROUP BY f.severity
            ORDER BY f.severity DESC
            """);

    /// High+critical count per scan, with the run-over-run change via LAG().
    /// A window function over an aggregate — the idiom worth knowing.
    public static async Task<IEnumerable<TrendRow>> TrendAsync(NpgsqlConnection conn) =>
        await conn.QueryAsync<TrendRow>("""
            SELECT scanned_at AS ScannedAt,
                   COUNT(*) FILTER (WHERE severity >= 3) AS HighCrit,
                   LAG(COUNT(*) FILTER (WHERE severity >= 3))
                       OVER (ORDER BY scanned_at) AS Prev,
                   COUNT(*) FILTER (WHERE severity >= 3)
                     - LAG(COUNT(*) FILTER (WHERE severity >= 3))
                       OVER (ORDER BY scanned_at) AS Delta
            FROM finding
            GROUP BY scanned_at
            ORDER BY scanned_at
            """);

    public static async Task<long> TotalFactRowsAsync(NpgsqlConnection conn) =>
        await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM finding");
}
