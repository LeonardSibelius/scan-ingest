// =============================================================================
// scan-ingest — a small continuous-monitoring (ConMon) pipeline.
// Launch with:  dotnet run
//
// It loads what a vulnerability scanner found across six weekly scans, tracks
// each problem as a commitment with an owner and a deadline, and compares all of
// it against a human assessor's control assessment to find where the two
// disagree.
//
// Three things it is NOT, because the phrase "continuous monitoring" gets used
// to mean more than this:
//
//   It is batch, not real time. Six weekly scans, loaded in one go.
//
//   It does not replace the manual assessment. It compares against it — and
//   that comparison is the entire point. If the assessment went away there
//   would be nothing to correlate, and the most valuable row this program can
//   produce is precisely the one where a human said "compliant" and the scanner
//   disagrees.
//
//   It is not a long enough window to exercise the SLA table. The six scans
//   span FIVE WEEKS — 2026-07-03 to 2026-08-07, seven days apart — so nothing
//   in the database can be more than 35 days old. Criticals (15-day deadline)
//   and highs (30-day) can therefore go overdue; mediums need 90 days, lows
//   180, informational 365, and the data simply does not reach that far.
//
//   Which means "no overdue mediums" in these reports says the window is
//   short, not that mediums are getting fixed. Worth knowing before quoting a
//   number off this: a demo whose time span is shorter than its own deadlines
//   will always look better than the thing it is demonstrating.
//
// This file runs top to bottom, once: set up the database, loop six times
// loading a scan and reconciling the commitments, prove that reloading changes
// nothing, then ask the database ten questions and print the answers.
// =============================================================================

using Npgsql;
using ScanIngest;

// C#: TOP-LEVEL STATEMENTS. No class here and no Main method — the compiler
// C#: generates them around this file. Java always needs the full
// C#: `public class X { public static void main(String[] a) { ... } }`.
// C#: Because of that wrapper, `await` works directly at file level below,
// C#: even though there is no `async` keyword in sight.

const string DbName = "scanprep";

// Connection string comes from the environment if set, otherwise a local default.
// Never hardcode credentials in a real one — this is a scratch database.
//
// C#: `??` is the null-coalescing operator: "use the left side, unless it is
// C#: null, in which case use the right". Java 9+ writes Objects.requireNonNullElse.
var baseConn = Environment.GetEnvironmentVariable("SCANPREP_CONN")
               ?? "Host=localhost;Port=5432;Username=postgres;Password=postgres";

var adminConn = $"{baseConn};Database=postgres";
var appConn   = $"{baseConn};Database={DbName}";

Console.WriteLine("scan-ingest — a small ConMon pipeline in C# and Postgres");
Console.WriteLine(new string('=', 62));

// ---------------------------------------------------------------- bootstrap
Console.WriteLine("\n[1] schema");
await Schema.EnsureDatabaseAsync(adminConn, DbName);

await using var conn = new NpgsqlConnection(appConn);
await conn.OpenAsync();
await Schema.EnsureSchemaAsync(conn);
Console.WriteLine("  landing table (jsonb), partitioned fact table, indexes — ready");

// ------------------------------------------------------------------ ingest
Console.WriteLine("\n[2] ingest — six weekly scans, reconciling the POA&M register after each");
Console.WriteLine($"  {"scan",-12} {"raw",6} {"facts",8}   POA&M  open / reopen / close");

var generator = new Generator();
var runs      = new List<ScanRun>();

// Anchor the scan dates to a FIXED point, not UtcNow. With UtcNow, two runs of
// this program minutes apart produce timestamps that differ by minutes — and
// since scanned_at is part of the fact table's primary key, nothing collides and
// every row inserts a second time. Re-running would silently double the data.
//
// Deterministic timestamps and deterministic run ids mean running the program
// again changes nothing — which is what "idempotent" has to mean for a pipeline
// that gets re-run.
var startedAt = new DateTimeOffset(2026, 7, 3, 9, 0, 0, TimeSpan.Zero);

// C#: A LOCAL FUNCTION — a method declared inside another scope, here at file
// C#: level. Java has no equivalent; you would write a private static method.
// C#: `static` on it means it captures nothing from the surrounding code.
// C#: `{at:O}` formats the date in round-trip form (2026-07-03T09:00:00.0000000+00:00),
// C#: which is unambiguous — it matters, because this string becomes an identifier.
static Guid DeterministicRunId(string source, DateTimeOffset at)
{
    var bytes = System.Security.Cryptography.MD5.HashData(
        System.Text.Encoding.UTF8.GetBytes($"{source}|{at:O}"));
    return new Guid(bytes);
}

for (var week = 0; week < 6; week++)
{
    var scannedAt = startedAt.AddDays(week * 7);
    // C#: NAMED ARGUMENTS — `ScanRunId:` labels which parameter each value is for.
    // C#: Optional, but it makes a three-argument constructor readable at the call
    // C#: site. Java has no equivalent.
    var run = new ScanRun(
        ScanRunId: DeterministicRunId("acas-nessus", scannedAt),
        ScannedAt: scannedAt,
        Source:    "acas-nessus");

    var findings = generator.NextScan(first: week == 0);
    var inserted = await Ingest.IngestAsync(conn, run, findings);

    // Reconcile the commitment register on every ingest, not once at the end.
    // Reconciling after every scan is what actually exercises the close and
    // reopen paths — a register updated only at the end would never see a
    // finding come back.
    var sync = await Poam.SyncAsync(conn);
    runs.Add(run);

    Console.WriteLine(
        $"  {run.ScannedAt:yyyy-MM-dd} {findings.Count,7} {inserted,8}"
        + $"   +{sync.Opened,-4} ~{sync.Reopened,-4} -{sync.Closed}");
}

Console.WriteLine($"  total fact rows: {await Findings.TotalFactRowsAsync(conn)}");

// ------------------------------------------------------- idempotency check
// Re-ingest the final scan verbatim. If the primary key is doing its job, the
// row count does not move. This is the claim worth being able to demonstrate:
// scans get re-run and re-delivered, and a pipeline that double-counts on
// replay will quietly corrupt every number downstream.
Console.WriteLine("\n[3] idempotency — re-ingesting the last scan");

// C#: `runs[^1]` is the LAST element — `^` counts from the end, so `^1` is final
// C#: and `^2` the one before. Java: runs.get(runs.size() - 1).
var before  = await Findings.TotalFactRowsAsync(conn);
var replay  = await Ingest.IngestAsync(conn, runs[^1], generator.NextScanReplay());
var after   = await Findings.TotalFactRowsAsync(conn);

Console.WriteLine($"  before {before}, re-inserted {replay}, after {after}"
                  + (before == after ? "   OK — no double counting" : "   MISMATCH"));

// ----------------------------------------------------------------- reports
Console.WriteLine("\n[4] open findings by severity — latest scan");
foreach (var r in await Findings.BySeverityAsync(conn))
    Console.WriteLine($"  {r.Label,-9} {r.N,6}");

Console.WriteLine("\n[5] change since previous scan");
foreach (var r in await Findings.DeltaAsync(conn))
    Console.WriteLine($"  {r.Status,-11} {r.N,6}");

Console.WriteLine("\n[6] POA&M aging — how long has each open finding been open");
Console.WriteLine($"  {"severity",-9} {"count",6} {"avg days",10}");
foreach (var r in await Findings.AgingAsync(conn))
    Console.WriteLine($"  {r.Label,-9} {r.N,6} {r.AvgDaysOpen,10:F1}");

Console.WriteLine("\n[7] high+critical trend, run over run  (LAG window function)");
Console.WriteLine($"  {"scan date",-12} {"high+crit",10} {"change",8}");
foreach (var r in await Findings.TrendAsync(conn))
{
    var delta = r.Delta is null ? "  —" : (r.Delta > 0 ? $"+{r.Delta}" : $"{r.Delta}");
    Console.WriteLine($"  {r.ScannedAt:yyyy-MM-dd}   {r.HighCrit,10} {delta,8}");
}

// -------------------------------------------------------------------- POA&M
// Findings are observations. A POA&M is a commitment — an owner and a date.
// This is where the pipeline stops describing the estate and starts holding
// people to something.
Console.WriteLine("\n[8] open POA&Ms against remediation SLA");
Console.WriteLine($"  {"severity",-9} {"open",6} {"overdue",8} {"SLA days",9}");
foreach (var r in await Poam.StatusAsync(conn))
    Console.WriteLine($"  {r.Label,-9} {r.Open,6} {r.Overdue,8} {r.SlaDays,9}");

Console.WriteLine("\n[9] overdue load by owner");
Console.WriteLine($"  {"owner",-16} {"open",6} {"overdue",8}");
foreach (var o in await Poam.ByOwnerAsync(conn))
    Console.WriteLine($"  {o.Owner,-16} {o.Open,6} {o.Overdue,8}");

Console.WriteLine("\n[10] worst overdue items — what an AO asks to see");
Console.WriteLine($"  {"owner",-14} {"host",-16} {"severity",-9} {"due",-11} {"late",5}  plugin");
foreach (var i in await Poam.WorstOverdueAsync(conn))
    Console.WriteLine(
        $"  {i.Owner,-14} {i.Host,-16} {i.Label,-9} {i.DueOn,-11} {i.DaysOverdue,5}  {i.PluginName}");

// ------------------------------------------------- second source + correlation
// Everything above reads one source. This is where it becomes a correlation
// engine: the scanner's view of the estate against the assessor's view of the
// controls, and the places they disagree.
Console.WriteLine("\n[11] second source — eMASS control-status export");
// Plugins first: plugin_control has a foreign key pointing at the plugin
// catalogue, so the catalogue has to exist before any mapping can reference it.
var pluginCount = await PluginCatalog.SeedAsync(conn);
await Controls.SeedCatalogAsync(conn);
Console.WriteLine($"  plugin catalog: {pluginCount} checks");
var exported = await Controls.GenerateExportAsync(
    conn, new Guid("7f9d2c10-0000-4000-8000-000000000001"));
Console.WriteLine($"  control catalog seeded, {exported} control statuses exported");
Console.WriteLine("  (assessment dated to the FIRST scan — five weeks stale, which is how real ones usually are)");

Console.WriteLine("\n[12] correlation — scanner vs. compliance record");
Console.WriteLine(
    $"  {"control",-7} {"eMASS says",-14} {"sources",7} {"findings",8} {"hosts",6}  verdict");
foreach (var c in await Controls.CorrelateAsync(conn))
{
    // Only two verdicts get called out. CONTRADICTED is the one worth finding;
    // "not assessable" is worth naming so it is never mistaken for clean.
    string flag;

    if (c.Verdict == "CONTRADICTED")
    {
        flag = "  <-- " + c.Title;
    }
    else if (c.Verdict == "not assessable")
    {
        flag = "  (" + c.Title + " — no scanner can see this)";
    }
    else
    {
        flag = "";
    }
    Console.WriteLine(
        $"  {c.ControlId,-7} {c.Compliance,-14} {c.EvidenceSources,7} {c.Findings,8} "
        + $"{c.HostsAffected,6}  {c.Verdict}{flag}");
}

Console.WriteLine("\n[13] coverage gap — findings that map to no tracked control");
foreach (var u in await Controls.UncoveredAsync(conn))
    Console.WriteLine($"  plugin {u.PluginId,-7} {u.Findings,5} findings   {u.PluginName}");

Console.WriteLine("\ndone.");
