using System.Text.Json;
using Npgsql;
using NpgsqlTypes;

namespace ScanIngest;

/// <summary>
/// The two-stage load that every serious ingest pipeline ends up with:
///
///   1. COPY the raw payload into a landing table, fast and without judgement.
///   2. Project it into the normalised fact table with ON CONFLICT DO NOTHING.
///
/// Stage 1 is fast because COPY is fast. Stage 2 is safe because the fact table's
/// primary key does the deduplication. COPY itself cannot express ON CONFLICT,
/// which is exactly why the landing table exists — it is not ceremony.
/// </summary>
public static class Ingest
{
    public static async Task<int> IngestAsync(
        NpgsqlConnection conn, ScanRun run, IReadOnlyList<Finding> findings)
    {
        await Schema.EnsurePartitionAsync(conn, run.ScannedAt);

        await using var tx = await conn.BeginTransactionAsync();

        // --- Register the run. Re-running is harmless. ---
        await using (var cmd = new NpgsqlCommand("""
            INSERT INTO scan_run (scan_run_id, scanned_at, source)
            VALUES (@id, @at, @src)
            ON CONFLICT (scan_run_id) DO NOTHING
            """, conn, tx))
        {
            cmd.Parameters.AddWithValue("id",  run.ScanRunId);
            cmd.Parameters.AddWithValue("at",  run.ScannedAt);
            cmd.Parameters.AddWithValue("src", run.Source);
            await cmd.ExecuteNonQueryAsync();
        }

        // --- Clear any prior landing rows for this run, so re-ingest is clean. ---
        await using (var cmd = new NpgsqlCommand(
            "DELETE FROM raw_finding WHERE scan_run_id = @id", conn, tx))
        {
            cmd.Parameters.AddWithValue("id", run.ScanRunId);
            await cmd.ExecuteNonQueryAsync();
        }

        // --- Stage 1: binary COPY into the jsonb landing table. ---
        // Npgsql's binary importer is the .NET equivalent of psql's \copy, and it
        // is roughly an order of magnitude faster than row-by-row INSERT.
        await using (var writer = await conn.BeginBinaryImportAsync(
            "COPY raw_finding (scan_run_id, payload) FROM STDIN (FORMAT BINARY)"))
        {
            foreach (var f in findings)
            {
                // Build the JSON explicitly rather than relying on a naming policy —
                // these keys have to match the ->> extractions in stage 2.
                var json = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["host"]        = f.Host,
                    ["plugin_id"]   = f.PluginId,
                    ["plugin_name"] = f.PluginName,
                    ["severity"]    = f.Severity,
                    ["cve"]         = f.Cve,
                });

                await writer.StartRowAsync();
                await writer.WriteAsync(run.ScanRunId, NpgsqlDbType.Uuid);
                await writer.WriteAsync(json,          NpgsqlDbType.Jsonb);
            }

            await writer.CompleteAsync();
        }

        // --- Stage 2: project jsonb into the typed fact table, idempotently. ---
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
