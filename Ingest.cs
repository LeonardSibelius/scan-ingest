using System.Text.Json;
using Npgsql;
using NpgsqlTypes;

namespace ScanIngest;

// =============================================================================
// Ingest.cs — puts one scan into the database.
//
// WHERE THIS SITS
//
// NessusImport.cs reads the findings out of a scanner export. This file stores
// them. Neither one crosses into the other: the parser holds no database
// connection, and nothing in here parses anything — the findings arrive as a
// parameter.
//
// That boundary is the reason this file has never had to change. It does not
// know whether a list of findings came from a bundled sample export, a live ACAS
// feed, or some future scanner that is not Nessus at all. Give it Finding
// records and a ScanRun and it stores them; everything else is somebody else's
// problem.
//
// HOW ONE SCAN GETS LOADED
//
// In two steps, into two different tables, for one specific reason.
//
//   STEP 1   COPY every finding into raw_finding, exactly as it arrived.
//   STEP 2   Read them back out and INSERT them into finding, the real table,
//            skipping any that are already there.
//
// WHY NOT ONE STEP
//
// Two things are wanted at once, and no single statement offers both.
//
//   FAST         COPY is Postgres's bulk loader. It streams rows straight in
//                without parsing a separate statement for each one, which is far
//                quicker than inserting rows one at a time.
//
//   RE-RUNNABLE  ON CONFLICT DO NOTHING is an option on INSERT. It says: if this
//                row is already here, skip it quietly rather than fail. That is
//                what makes re-loading the same scan harmless.
//
// COPY has no ON CONFLICT clause. Hence two tables. raw_finding is a scratch pad
// with no keys and no rules (a "landing table", in the usual jargon),
// so COPY can pour into it at full speed.
// Then one ordinary INSERT moves the data across into `finding` — and an INSERT
// is allowed to say ON CONFLICT DO NOTHING.
//
// Speed on the way in, safety on the way across.
//
// WHY THE LANDING COLUMN IS JSONB
//
// raw_finding stores each finding as one jsonb blob rather than as typed columns,
// for the same reason a landing table exists at all: to accept whatever the
// scanner sends without deciding its shape yet. A real export carries dozens of
// fields that change between versions; a single json column takes all of them,
// and stage 2 pulls out only the five this project uses.
//
// jsonb and not json — Postgres has both. `json` keeps the raw text and re-parses
// it on every read. `jsonb` parses once, on the way in, into a binary form that
// is fast to read and can be indexed. Stage 2 reads back into this data with ->>,
// and there is a GIN index on it (see Schema.cs), so jsonb is the one that fits.
// The rule of thumb: `json` if you only ever store it, `jsonb` if you read INTO
// it.
// =============================================================================

public static class Ingest
{
    /// <summary>
    /// Loads one scan. Safe to call repeatedly with the same run — the second
    /// call inserts nothing and reports zero.
    /// </summary>
    /// <param name="run">
    /// Scan metadata. Its <c>ScanRunId</c> must be deterministic for replay
    /// safety — see the note in Program.cs about what a random id would do here.
    /// </param>
    /// <returns>
    /// How many rows actually landed in the fact table. Zero on a replay, which
    /// is the signal the idempotency check in Program.cs looks for.
    /// </returns>
    // C#: `async` says this method contains `await`. It is required whenever it does.
    // C#: `Task<int>` is Java's CompletableFuture<Integer> — an int that arrives later.
    // C#: `IReadOnlyList<T>` is a list the method promises not to modify.
    // C#: The `Async` name suffix is convention, not syntax.
    public static async Task<int> IngestAsync(
        NpgsqlConnection conn, ScanRun run, IReadOnlyList<Finding> findings)
    {
        // The fact table is partitioned by month, and Postgres will reject an
        // insert whose date falls outside every existing partition. Create the
        // one this scan needs before doing anything else.
        await Schema.EnsurePartitionAsync(conn, run.ScannedAt);

        // Everything below is one transaction: either the whole scan lands or
        // none of it does. A half-ingested scan would make the delta reports
        // report remediation that never happened.
        //
        // C#: `await x` = "do x, then carry on". It frees the thread while waiting
        // C#: rather than blocking it. Read it as an ordinary sequential call.
        // C#: `using` = Java's try-with-resources: clean up when scope exits.
        // C#: `await using` = the cleanup itself is async.
        // C#: No braces here, so "scope" means the rest of the method.
        //
        // The transaction rolls back on dispose if never committed, so an
        // exception anywhere below cleans up without an explicit catch.
        await using var tx = await conn.BeginTransactionAsync();

        // ---------------------------------------------------------------------
        // Register the scan run itself.
        // ---------------------------------------------------------------------
        // ON CONFLICT DO NOTHING makes a replay harmless: the run already exists,
        // nothing changes, and we carry on to re-derive everything downstream.
        // C#: `"""..."""` is a raw string literal — Java's text block. Everything
        // C#: between the triple quotes is taken literally, no escaping needed,
        // C#: which is why the SQL below reads exactly like SQL.
        // C#: WITH parentheses, `await using (...)` scopes to the braces that follow.
        await using (var cmd = new NpgsqlCommand("""
            INSERT INTO scan_run (scan_run_id, scanned_at, source)
            VALUES (@id, @at, @src)
            ON CONFLICT (scan_run_id) DO NOTHING
            """, conn, tx))
        {
            // Parameters, never string concatenation. This matters more here than
            // in most places: the values come out of a scanner file, which is an
            // untrusted document. Interpolate scanner output into SQL and you have
            // handed whoever can write that file a shell.
            cmd.Parameters.AddWithValue("id",  run.ScanRunId);
            cmd.Parameters.AddWithValue("at",  run.ScannedAt);
            cmd.Parameters.AddWithValue("src", run.Source);
            await cmd.ExecuteNonQueryAsync();
        }

        // ---------------------------------------------------------------------
        // Clear this run's landing rows before re-copying.
        // ---------------------------------------------------------------------
        // The landing table has no natural key — it is an append-only record of
        // "what arrived" — so COPY into it cannot deduplicate itself. Deleting
        // this run's rows first is what makes the whole method idempotent rather
        // than just the fact-table half of it.
        await using (var cmd = new NpgsqlCommand(
            "DELETE FROM raw_finding WHERE scan_run_id = @id", conn, tx))
        {
            cmd.Parameters.AddWithValue("id", run.ScanRunId);
            await cmd.ExecuteNonQueryAsync();
        }

        // ---------------------------------------------------------------------
        // STAGE 1 — binary COPY into the jsonb landing table.
        // ---------------------------------------------------------------------
        // Npgsql's binary importer is the .NET equivalent of psql's \copy. It
        // streams rows over the wire in Postgres's own binary format, skipping
        // both SQL parsing and text encoding per row, and runs roughly an order
        // of magnitude faster than row-by-row INSERT.
        await using (var writer = await conn.BeginBinaryImportAsync(
            "COPY raw_finding (scan_run_id, payload) FROM STDIN (FORMAT BINARY)"))
        {
            foreach (var f in findings)
            {
                // The JSON keys are built explicitly rather than by serialising
                // the Finding record with a naming policy. These keys are a
                // contract: stage 2 extracts them by name with ->>, and a
                // serializer convention change would break that join silently,
                // producing NULLs rather than an error.
                // C#: `new Dictionary<K,V> { ["key"] = value, ... }` is a map built
                // C#: inline. Java 9+ writes Map.of("host", f.Host, ...).
                // C#: `object?` means "any type, and it may be null" — needed here
                // C#: because the values are a mix of strings, ints and nulls.
                var json = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["host"]        = f.Host,
                    ["plugin_id"]   = f.PluginId,
                    ["plugin_name"] = f.PluginName,
                    ["severity"]    = f.Severity,
                    ["cve"]         = f.Cve,
                });

                // Binary COPY is positional: one StartRow, then one Write per
                // column in the order named in the COPY statement above. The
                // NpgsqlDbType tells the driver how to encode each value.
                await writer.StartRowAsync();
                await writer.WriteAsync(run.ScanRunId, NpgsqlDbType.Uuid);
                await writer.WriteAsync(json,          NpgsqlDbType.Jsonb);
            }

            // CompleteAsync flushes and commits the copy operation. Skipping it
            // — including by throwing before reaching it — discards everything
            // written, which is the correct failure mode but a surprising one if
            // you have not met it before.
            await writer.CompleteAsync();
        }

        // ---------------------------------------------------------------------
        // STAGE 2 — project jsonb into the typed fact table.
        // ---------------------------------------------------------------------
        // ->> extracts a JSON field AS TEXT (-> would return jsonb), so numeric
        // fields need an explicit cast. That cast is also the first point where
        // malformed scanner output would fail loudly, which is where you want it:
        // the landing table accepts anything, the fact table accepts only what
        // typechecks.
        //
        // ON CONFLICT DO NOTHING is the idempotency guarantee. The fact table's
        // primary key is (scanned_at, host, plugin_id) — re-ingesting the same
        // scan collides on every row and inserts none. ExecuteNonQueryAsync then
        // returns 0, which is what the caller reports.
        int inserted;
        await using (var cmd = new NpgsqlCommand("""
            INSERT INTO finding
                (scanned_at, scan_run_id, host, plugin_id, plugin_name, severity, cve)
            SELECT r.scanned_at,
                   rf.scan_run_id,
                   rf.payload ->> 'host',
                   (rf.payload ->> 'plugin_id')::int,
                   rf.payload ->> 'plugin_name',
                   (rf.payload ->> 'severity')::smallint,
                   rf.payload ->> 'cve'
            FROM raw_finding rf
            -- scanned_at lives on the run, not on each finding's payload. Joining
            -- for it keeps the scan's timestamp in exactly one place.
            JOIN scan_run r ON r.scan_run_id = rf.scan_run_id
            WHERE rf.scan_run_id = @id
            ON CONFLICT DO NOTHING
            """, conn, tx))
        {
            cmd.Parameters.AddWithValue("id", run.ScanRunId);
            inserted = await cmd.ExecuteNonQueryAsync();
        }

        await tx.CommitAsync();
        return inserted;
    }
}
