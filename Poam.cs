using Dapper;
using Npgsql;

namespace ScanIngest;

// =============================================================================
// Poam.cs — the commitment register.
//
// Everything in Ingest.cs and Reports.cs deals in OBSERVATIONS: the scanner saw
// this, on this machine, on this date. Observations are facts about the world and
// nobody is accountable for them.
//
// A POA&M — Plan of Action and Milestones — is a COMMITMENT: a named person has
// accepted a gap and promised a date. That difference drives everything here:
//
//                     finding                     poam
//   keyed by     (scanned_at, host, plugin)  (host, plugin)
//   partitioned  yes, by scan month          no
//   lifetime     one scan                    outlives every scan that saw it
//
// A finding belongs to the scan that produced it. A commitment belongs to the
// problem, and survives every scan in between — which is why it cannot be
// partitioned by scan date and cannot be keyed on one.
// =============================================================================

public static class Poam
{
    /// <summary>
    /// Remediation deadline in days, by severity — the service level the
    /// programme has committed to. Held as a SQL fragment rather than a C#
    /// lookup because it is needed inside several queries, and computing it in
    /// C# would mean pulling every row back to apply it.
    ///
    /// Real values are set per-programme and are frequently more aggressive than
    /// these; the shape is what matters. Callers interpolate it after rewriting
    /// the bare column name to a qualified one — see the <c>.Replace</c> calls.
    /// </summary>
    public const string SlaCase = """
        CASE severity
            WHEN 4 THEN 15    -- critical
            WHEN 3 THEN 30    -- high
            WHEN 2 THEN 90    -- medium
            WHEN 1 THEN 180   -- low
            ELSE 365          -- informational
        END
        """;

    /// <summary>
    /// Reconciles the register against the most recent scan. Called after every
    /// ingest, not once at the end — a register that is only correct at the end
    /// of a batch is a register that was wrong for the whole batch.
    ///
    /// Three transitions, and all three carry meaning:
    ///
    ///   OPEN    A finding in the latest scan with no commitment against it yet.
    ///           Its clock starts from when the problem was FIRST observed, not
    ///           from today — otherwise a long-standing gap would look fresh the
    ///           moment somebody finally wrote it down.
    ///
    ///   REOPEN  A closed commitment whose finding has come back. Deliberately an
    ///           UPDATE of the existing row rather than a new one. A fresh row
    ///           would reset the clock and erase the recurrence, and a recurrence
    ///           is exactly what an auditor is looking for — it means the fix did
    ///           not hold, which is a different and worse fact than a new finding.
    ///
    ///   CLOSE   A commitment whose finding no longer appears. Remediated.
    ///
    /// The due date is computed once, at open time, and never recalculated. The
    /// commitment was made on a date. Silently moving a deadline because severity
    /// was re-rated or policy changed would be the most dishonest thing this code
    /// could do, and it is the kind of thing that happens by accident when the
    /// due date is derived on read instead of stored on write.
    /// </summary>
    /// <returns>Counts of what moved, so the caller can show the register living.</returns>
    public static async Task<PoamSyncResult> SyncAsync(NpgsqlConnection conn)
    {
        // One transaction for the whole reconciliation. A crash between the open
        // pass and the close pass would leave the register describing a state
        // that never existed.
        await using var tx = await conn.BeginTransactionAsync();

        // ---------------------------------------------------------------------
        // OPEN and REOPEN — one upsert handles both.
        // ---------------------------------------------------------------------
        // C# note: this is `string`, not `const string`, because it interpolates
        // SlaCase.Replace(...) — a method call, which is not a compile-time
        // constant. `const` here is a compile error, and a slightly cryptic one.
        string openSql = $"""
            WITH latest AS (
                SELECT scan_run_id, scanned_at
                FROM scan_run ORDER BY scanned_at DESC LIMIT 1
            ),
            -- When each problem was FIRST seen, across all history. This is the
            -- clock start, and it is why the fact table keeps every scan.
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
                   -- Owner assigned deterministically from the hostname, so the
                   -- same machine always lands with the same ISSO across runs.
                   -- In production this is a join against the system inventory;
                   -- a hash stands in for that here. hashtext() is cast to bigint
                   -- before abs() because hashtext can return int's minimum value,
                   -- whose absolute value overflows int.
                   'ISSO-' || (ARRAY['Alpha','Bravo','Charlie','Delta','Echo','Foxtrot'])
                       [ mod(abs(hashtext(f.host)::bigint), 6) + 1 ],
                   fs.opened_on,
                   -- Deadline = first observation + the SLA for this severity.
                   fs.opened_on + ({SlaCase.Replace("severity", "f.severity")})
            FROM finding f
            JOIN latest l      ON l.scan_run_id = f.scan_run_id
            JOIN first_seen fs ON fs.host = f.host AND fs.plugin_id = f.plugin_id
            -- The conflict target is the natural key (host, plugin_id). DO UPDATE
            -- with a WHERE clause makes this a reopen ONLY for rows that were
            -- closed; a still-open commitment conflicts and is left completely
            -- untouched, preserving its original owner and due date.
            ON CONFLICT ON CONSTRAINT poam_natural_key DO UPDATE
                SET closed_on = NULL
                WHERE poam.closed_on IS NOT NULL
            """;

        // Opens and reopens both come out of that single statement, so its row
        // count cannot distinguish them. Counting the register before and after
        // separates them: total growth is opens, and the fall in closed rows is
        // reopens. Cheap, and it keeps the upsert as one statement rather than
        // splitting it into two that could disagree.
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

        // ---------------------------------------------------------------------
        // CLOSE — anything the latest scan no longer reports.
        // ---------------------------------------------------------------------
        // Closed as of the SCAN's date, not today's. The evidence of remediation
        // is the scan; dating the closure to when the job happened to run would
        // put a false precision on it.
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
              -- NOT EXISTS rather than NOT IN: NOT IN against a set containing
              -- any NULL evaluates to NULL and quietly matches nothing at all.
              AND NOT EXISTS (
                  SELECT 1 FROM current_findings c
                  WHERE c.host = p.host AND c.plugin_id = p.plugin_id
              )
            """;

        var closed = await conn.ExecuteAsync(closeSql, transaction: tx);

        await tx.CommitAsync();
        return new PoamSyncResult(opened, reopened, closed);
    }

    /// <summary>
    /// Open commitments per severity, and how many have blown their deadline.
    ///
    /// "As of" is the date of the most recent SCAN, not <c>now()</c>. If the
    /// scanner has not run for three weeks then nothing has been observed for
    /// three weeks, and ageing commitments against wall-clock time would invent
    /// overdue days that no evidence supports.
    /// </summary>
    public static async Task<IEnumerable<PoamStatusRow>> StatusAsync(NpgsqlConnection conn) =>
        await conn.QueryAsync<PoamStatusRow>(SqlLibrary.Get("StatusAsync"));

    /// <summary>
    /// The worst overdue items, with enough context to act: owner, machine,
    /// problem, deadline, and how late. This is the list an Authorizing Official
    /// actually asks for — not a count, but names and dates.
    /// </summary>
    /// <remarks>
    /// The row limit is a literal in the SQL rather than a parameter. It used to
    /// be one — but queries.sql is now the single source for both this and psql,
    /// and a placeholder there breaks `psql -f queries.sql`. Nothing ever passed
    /// anything but the default, so the flexibility was costing more than it was
    /// worth. If it needs to vary, the SQL moves back into the code.
    /// </remarks>
    public static async Task<IEnumerable<PoamItemRow>> WorstOverdueAsync(NpgsqlConnection conn) =>
        await conn.QueryAsync<PoamItemRow>(SqlLibrary.Get("WorstOverdueAsync"));
    // C#: `new { limit }` is an ANONYMOUS OBJECT — a throwaway type with one
    // C#: property called `limit`, created on the spot. Dapper reads the property
    // C#: names and binds them to the @names in the SQL. Java has no equivalent;
    // C#: you would pass a Map or use positional parameters.

    /// <summary>
    /// Open and overdue load per accountable owner. The accountability view: not
    /// "how broken is the system" but "who is carrying it, and who is drowning".
    /// Sorted by overdue count, because that is the column that needs a
    /// conversation.
    /// </summary>
    public static async Task<IEnumerable<OwnerLoadRow>> ByOwnerAsync(NpgsqlConnection conn) =>
        await conn.QueryAsync<OwnerLoadRow>(SqlLibrary.Get("ByOwnerAsync"));
}
