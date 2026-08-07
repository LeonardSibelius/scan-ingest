using Npgsql;

namespace ScanIngest;

// =============================================================================
// Schema.cs — the database, its tables, and its partitions.
//
// Everything in this file is idempotent: run it a hundred times and the hundredth
// run is a no-op. That is not tidiness, it is a requirement. Schema bootstrap
// runs on every deploy of a pipeline like this, and a step that only works
// against an empty database is a step that fails on every deploy after the first.
//
// The schema is the argument this project is really making, so the DDL below
// carries most of the reasoning. Three tables matter:
//
//   raw_finding   what the scanner said, untouched, as jsonb
//   finding       what we can typecheck, partitioned by scan month
//   poam          what somebody promised, keyed by problem rather than by scan
// =============================================================================

public static class Schema
{
    /// <summary>
    /// Creates the application database if it does not already exist.
    ///
    /// This one connects to the <c>postgres</c> maintenance database rather than
    /// ours, for the obvious reason that you cannot connect to a database in
    /// order to create it.
    /// </summary>
    /// <param name="adminConnString">Connection string pointing at <c>postgres</c>.</param>
    public static async Task EnsureDatabaseAsync(string adminConnString, string dbName)
    {
        await using var conn = new NpgsqlConnection(adminConnString);
        await conn.OpenAsync();

        // Existence check first. CREATE DATABASE has no IF NOT EXISTS form —
        // unlike almost every other CREATE in Postgres — so this has to be a
        // look-then-leap rather than a single statement.
        await using var check = new NpgsqlCommand(
            "SELECT 1 FROM pg_database WHERE datname = @name", conn);
        check.Parameters.AddWithValue("name", dbName);

        // C# note: `is null` rather than `== null`. Pattern matching, and it
        // cannot be subverted by an overloaded equality operator.
        if (await check.ExecuteScalarAsync() is null)
        {
            // CREATE DATABASE cannot take a parameter — the database name is an
            // identifier, not a value, and parameters only ever substitute
            // values. So it has to be interpolated, which means quoting it
            // properly: wrap in double quotes and double any embedded quote.
            // That is the identifier-escaping rule, and it is the only safe way
            // to build a statement like this.
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

    /// <summary>
    /// Applies the whole DDL block above in one round trip. Every statement in it
    /// is <c>CREATE ... IF NOT EXISTS</c>, so this is safe on an existing
    /// database and cheap on a fresh one.
    /// </summary>
    public static async Task EnsureSchemaAsync(NpgsqlConnection conn)
    {
        // Npgsql will happily execute a multi-statement command, so the entire
        // schema goes over the wire once instead of statement by statement.
        await using var cmd = new NpgsqlCommand(Ddl, conn);
        await cmd.ExecuteNonQueryAsync();
    }

    /// <summary>
    /// Creates the monthly partition covering <paramref name="when"/>, if it does
    /// not already exist. Called before every ingest, because Postgres rejects an
    /// insert whose partition key falls outside every defined partition — there
    /// is no default landing place unless you declare one.
    ///
    /// A production system would create partitions ahead of time on a schedule
    /// rather than on the write path. Doing it inline here keeps the demo to one
    /// command with no cron.
    /// </summary>
    public static async Task EnsurePartitionAsync(NpgsqlConnection conn, DateTimeOffset when)
    {
        // Truncate to the first instant of the month, in UTC. TimeSpan.Zero is
        // the offset — this is deliberately NOT local midnight, see below.
        var start = new DateTimeOffset(when.Year, when.Month, 1, 0, 0, 0, TimeSpan.Zero);
        var end   = start.AddMonths(1);
        var name  = $"finding_{start:yyyy_MM}";   // e.g. finding_2026_08

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
