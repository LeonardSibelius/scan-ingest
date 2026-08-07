using Dapper;
using Npgsql;

namespace ScanIngest;

/// <summary>
/// Reconciles the POA&amp;M register against the most recent scan.
///
/// Three transitions, and all three matter:
///   OPEN    — a finding in the latest scan with no POA&amp;M yet.
///   REOPEN  — a finding that was closed and has come back. Not a new item;
///             the same commitment, broken. Closing and re-opening as a fresh
///             row would reset the clock and hide the recurrence.
///   CLOSE   — a POA&amp;M whose finding no longer appears. Remediated.
///
/// The due date is derived from severity at open time and never recalculated,
/// because the commitment was made on a date and moving it silently would be
/// the single most dishonest thing this code could do.
/// </summary>
public static class Poam
{
    /// Remediation SLA in days, by severity. Tunable per-programme in reality.
    public const string SlaCase = """
        CASE severity
            WHEN 4 THEN 15    -- critical
            WHEN 3 THEN 30    -- high
            WHEN 2 THEN 90    -- medium
            WHEN 1 THEN 180   -- low
            ELSE 365          -- informational
        END
        """;

    public static async Task<PoamSyncResult> SyncAsync(NpgsqlConnection conn)
    {
        await using var tx = await conn.BeginTransactionAsync();

        // --- OPEN and REOPEN, in one upsert. ---
        // Owner is assigned deterministically from the host so the same system
        // always lands with the same ISSO. In production this is a lookup against
        // the system inventory, not a hash.
        // Not `const` — it interpolates SlaCase, which is a method call result.
        string openSql = $"""
            WITH latest AS (
                SELECT scan_run_id, scanned_at
                FROM scan_run ORDER BY scanned_at DESC LIMIT 1
            ),
            first_seen AS (
                SELECT host, plugin_id, MIN(scanned_at)::date AS opened_on
                FROM finding GROUP BY host, plugin_id
            )
            INSERT INTO poam
                (host, plugin_id, plugin_name, severity, owner, opened_on, due_on)
            SELECT f.host,
                   f.plugin_id,
                   f.plugin_name,
                   f.severity,
                   'ISSO-' || (ARRAY['Alpha','Bravo','Charlie','Delta','Echo','Foxtrot'])
                       [ mod(abs(hashtext(f.host)::bigint), 6) + 1 ],
                   fs.opened_on,
                   fs.opened_on + ({SlaCase.Replace("severity", "f.severity")})
            FROM finding f
            JOIN latest l      ON l.scan_run_id = f.scan_run_id
            JOIN first_seen fs ON fs.host = f.host AND fs.plugin_id = f.plugin_id
            ON CONFLICT ON CONSTRAINT poam_natural_key DO UPDATE
                SET closed_on = NULL
                WHERE poam.closed_on IS NOT NULL
            """;

        // Count opens and reopens separately by checking the register first.
        var beforeOpen = await conn.ExecuteScalarAsync<int>(
            "SELECT count(*)::int FROM poam", transaction: tx);
        var beforeClosed = await conn.ExecuteScalarAsync<int>(
            "SELECT count(*)::int FROM poam WHERE closed_on IS NOT NULL", transaction: tx);

        await conn.ExecuteAsync(openSql, transaction: tx);

        var afterOpen = await conn.ExecuteScalarAsync<int>(
            "SELECT count(*)::int FROM poam", transaction: tx);
        var afterClosed = await conn.ExecuteScalarAsync<int>(
            "SELECT count(*)::int FROM poam WHERE closed_on IS NOT NULL", transaction: tx);

        var opened   = afterOpen - beforeOpen;
        var reopened = beforeClosed - afterClosed;

        // --- CLOSE anything the latest scan no longer reports. ---
        const string closeSql = """
            WITH latest AS (
                SELECT scan_run_id, scanned_at
                FROM scan_run ORDER BY scanned_at DESC LIMIT 1
            ),
            current_findings AS (
                SELECT f.host, f.plugin_id
                FROM finding f JOIN latest l ON l.scan_run_id = f.scan_run_id
            )
            UPDATE poam p
            SET closed_on = (SELECT scanned_at::date FROM latest)
            WHERE p.closed_on IS NULL
              AND NOT EXISTS (
                  SELECT 1 FROM current_findings c
                  WHERE c.host = p.host AND c.plugin_id = p.plugin_id
              )
            """;

        var closed = await conn.ExecuteAsync(closeSql, transaction: tx);

        await tx.CommitAsync();
        return new PoamSyncResult(opened, reopened, closed);
    }

    /// Open items and how many have blown their due date, by severity.
    public static async Task<IEnumerable<PoamStatusRow>> StatusAsync(NpgsqlConnection conn) =>
        await conn.QueryAsync<PoamStatusRow>($"""
            WITH asof AS (SELECT MAX(scanned_at)::date AS d FROM scan_run)
            SELECT p.severity AS Severity,
                   COUNT(*)   AS Open,
                   COUNT(*) FILTER (WHERE p.due_on < (SELECT d FROM asof)) AS Overdue,
                   MAX({SlaCase.Replace("severity", "p.severity")}) AS SlaDays
            FROM poam p
            WHERE p.closed_on IS NULL
            GROUP BY p.severity
            ORDER BY p.severity DESC
            """);

    /// The worst offenders — what an AO actually asks to see.
    public static async Task<IEnumerable<PoamItemRow>> WorstOverdueAsync(
        NpgsqlConnection conn, int limit = 10) =>
        await conn.QueryAsync<PoamItemRow>("""
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
            LIMIT @limit
            """, new { limit });

    /// Overdue load per owner — the accountability view.
    public static async Task<IEnumerable<OwnerLoadRow>> ByOwnerAsync(NpgsqlConnection conn) =>
        await conn.QueryAsync<OwnerLoadRow>("""
            WITH asof AS (SELECT MAX(scanned_at)::date AS d FROM scan_run)
            SELECT p.owner   AS Owner,
                   COUNT(*)  AS Open,
                   COUNT(*) FILTER (WHERE p.due_on < (SELECT d FROM asof)) AS Overdue
            FROM poam p
            WHERE p.closed_on IS NULL
            GROUP BY p.owner
            ORDER BY 3 DESC, 1
            """);
}
