using Npgsql;

namespace ScanIngest;

/// <summary>
/// Creates the database and schema. Everything here is idempotent — run it as
/// many times as you like. That matters: in a ConMon pipeline the bootstrap runs
/// on every deploy, and a schema step that only works once is a schema step that
/// will page somebody at 3am.
/// </summary>
public static class Schema
{
    /// Connects to the maintenance database and creates ours if it isn't there.
    public static async Task EnsureDatabaseAsync(string adminConnString, string dbName)
    {
        await using var conn = new NpgsqlConnection(adminConnString);
        await conn.OpenAsync();

        await using var check = new NpgsqlCommand(
            "SELECT 1 FROM pg_database WHERE datname = @name", conn);
        check.Parameters.AddWithValue("name", dbName);

        if (await check.ExecuteScalarAsync() is null)
        {
            // CREATE DATABASE cannot be parameterised, so quote the identifier.
            await using var create = new NpgsqlCommand(
                $"CREATE DATABASE \"{dbName.Replace("\"", "\"\"")}\"", conn);
            await create.ExecuteNonQueryAsync();
            Console.WriteLine($"  created database {dbName}");
        }
    }

    private const string Ddl = """
        -- One row per scan execution.
        CREATE TABLE IF NOT EXISTS scan_run (
            scan_run_id uuid        PRIMARY KEY,
            scanned_at  timestamptz NOT NULL,
            source      text        NOT NULL,
            ingested_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT scan_run_natural_key UNIQUE (source, scanned_at)
        );

        -- LANDING TABLE. The scanner's payload lands here untouched, as jsonb.
        -- Nessus output is nested and its shape drifts between plugin versions,
        -- so we do not force it into columns on the way in. Schema flexibility on
        -- ingest, schema discipline on read.
        CREATE TABLE IF NOT EXISTS raw_finding (
            id          bigserial   PRIMARY KEY,
            scan_run_id uuid        NOT NULL REFERENCES scan_run(scan_run_id),
            ingested_at timestamptz NOT NULL DEFAULT now(),
            payload     jsonb       NOT NULL
        );

        CREATE INDEX IF NOT EXISTS raw_finding_run_idx
            ON raw_finding (scan_run_id);

        -- GIN index makes containment queries over the raw payload usable,
        -- e.g. payload @> '{"severity": 4}'.
        CREATE INDEX IF NOT EXISTS raw_finding_payload_gin
            ON raw_finding USING gin (payload);

        -- NORMALISED FACT TABLE, range-partitioned by scan date.
        -- Findings accumulate per host, per plugin, per scan, forever. Partitioning
        -- by month keeps queries bounded and makes retention a DETACH rather than
        -- a very long DELETE.
        --
        -- The primary key is the idempotency guarantee: re-ingesting the same scan
        -- collides and is discarded rather than double-counted.
        CREATE TABLE IF NOT EXISTS finding (
            scanned_at  timestamptz NOT NULL,
            scan_run_id uuid        NOT NULL,
            host        text        NOT NULL,
            plugin_id   int         NOT NULL,
            plugin_name text        NOT NULL,
            severity    smallint    NOT NULL,
            cve         text,
            PRIMARY KEY (scanned_at, host, plugin_id)
        ) PARTITION BY RANGE (scanned_at);

        CREATE INDEX IF NOT EXISTS finding_host_plugin_idx
            ON finding (host, plugin_id);

        -- THE POA&M REGISTER. Findings are observations; a POA&M is a commitment.
        -- One row per (host, plugin) gap, with an owner who is accountable and a
        -- date they promised. This is the artifact an Authorizing Official reads,
        -- and the reason the numbers upstream have to be exactly right.
        --
        -- Note it is NOT partitioned and NOT keyed on scan date: a POA&M outlives
        -- the scan that discovered it. That difference — observations partitioned
        -- by time, commitments keyed by identity — is the whole modelling decision.
        CREATE TABLE IF NOT EXISTS poam (
            poam_id     bigserial PRIMARY KEY,
            host        text     NOT NULL,
            plugin_id   int      NOT NULL,
            plugin_name text     NOT NULL,
            severity    smallint NOT NULL,
            owner       text     NOT NULL,
            opened_on   date     NOT NULL,
            due_on      date     NOT NULL,
            closed_on   date,
            CONSTRAINT poam_natural_key UNIQUE (host, plugin_id)
        );

        CREATE INDEX IF NOT EXISTS poam_open_due_idx
            ON poam (due_on) WHERE closed_on IS NULL;

        -- ================= SECOND SOURCE: the compliance side =================
        -- Nessus tells you what is broken on a host. eMASS tells you what the
        -- assessor SAID about the system's controls. They are produced by
        -- different people on different cadences and they disagree — and the
        -- disagreement is the product.

        -- NIST SP 800-53 controls tracked in this system's RMF package.
        CREATE TABLE IF NOT EXISTS control (
            control_id text PRIMARY KEY,     -- 'SC-8'
            title      text NOT NULL,
            family     text NOT NULL         -- 'SC'
        );

        -- Which scanner plugins constitute evidence for which control.
        -- Many-to-many on purpose: one plugin can bear on several controls, and
        -- a control is evidenced by many plugins. Some controls have no technical
        -- evidence at all — they are procedural, and no scanner will ever see them.
        CREATE TABLE IF NOT EXISTS plugin_control (
            plugin_id  int  NOT NULL,
            control_id text NOT NULL REFERENCES control(control_id),
            PRIMARY KEY (plugin_id, control_id)
        );

        -- An eMASS control-status export. One row per control per export.
        CREATE TABLE IF NOT EXISTS control_status (
            export_id   uuid        NOT NULL,
            exported_at timestamptz NOT NULL,
            control_id  text        NOT NULL REFERENCES control(control_id),
            compliance  text        NOT NULL,
            assessed_by text,
            PRIMARY KEY (exported_at, control_id)
        );
        """;

    public static async Task EnsureSchemaAsync(NpgsqlConnection conn)
    {
        await using var cmd = new NpgsqlCommand(Ddl, conn);
        await cmd.ExecuteNonQueryAsync();
    }

    /// Creates the monthly partition covering <paramref name="when"/>, if absent.
    public static async Task EnsurePartitionAsync(NpgsqlConnection conn, DateTimeOffset when)
    {
        var start = new DateTimeOffset(when.Year, when.Month, 1, 0, 0, 0, TimeSpan.Zero);
        var end   = start.AddMonths(1);
        var name  = $"finding_{start:yyyy_MM}";

        // The offset on these literals is NOT optional. `scanned_at` is timestamptz,
        // and a bare date literal is resolved in the *server's* timezone — so on a
        // machine set to Pacific the boundary lands at 07:00 UTC, and a scan taken
        // at 03:00 UTC on the 1st falls into the previous month's partition.
        // Pin the bounds to UTC and the partitions mean the same thing everywhere.
        var sql = $"""
            CREATE TABLE IF NOT EXISTS {name}
                PARTITION OF finding
                FOR VALUES FROM ('{start:yyyy-MM-dd} 00:00:00+00')
                            TO ('{end:yyyy-MM-dd} 00:00:00+00');
            """;

        await using var cmd = new NpgsqlCommand(sql, conn);
        await cmd.ExecuteNonQueryAsync();
    }
}
