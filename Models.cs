namespace ScanIngest;

// =============================================================================
// Models.cs — every type that crosses a boundary in this program.
//
// Two kinds of type live here:
//
//   1. DOMAIN types (Finding, ScanRun) — what the pipeline moves around.
//   2. REPORT ROW types (everything below the divider) — the shape of a single
//      row coming back from a query. Dapper materialises these directly.
//
// THE DAPPER CONTRACT, because it explains every `AS SomeName` in the SQL:
// Dapper matches a result column to a constructor parameter by name, ignoring
// case and underscores. Postgres folds unquoted identifiers to lower case, so a
// column aliased `AS AvgDaysOpen` arrives as `avgdaysopen` and still binds to the
// `AvgDaysOpen` parameter. If a name does not match, that parameter is silently
// left at its default — which is why the aliases in the SQL are not decoration.
// =============================================================================


// -----------------------------------------------------------------------------
// Shared helpers
// -----------------------------------------------------------------------------

/// <summary>
/// Turns a severity number into the word for it.
/// </summary>
/// <remarks>
/// One place, deliberately. The same five numbers mean the same five things
/// wherever they appear — on a report row, in the console output, in a log line.
/// Written out four times, adding a sixth severity means remembering all four,
/// and the one that gets missed is the one nobody looks at.
/// </remarks>
public static class SeverityText
{
    public static string Label(int severity)
    {
        switch (severity)
        {
            case 4:  return "critical";
            case 3:  return "high";
            case 2:  return "medium";
            case 1:  return "low";
            default: return "info";
        }
    }
}


// -----------------------------------------------------------------------------
// Domain types
// -----------------------------------------------------------------------------

/// <summary>
/// One problem, on one machine, as reported by the scanner.
///
/// C# note: `record` is the same idea as a Java 14+ record — a positional
/// constructor, value equality, and immutability by default. Value equality
/// matters here: two Findings with identical fields are equal, which is what
/// lets a HashSet deduplicate them in the generator.
/// </summary>
/// <param name="Host">The machine the finding was observed on.</param>
/// <param name="PluginId">
/// Scanner plugin that produced it. A plugin is one specific check — "is SMBv1
/// enabled" — and its id is stable across scans, which is what makes a finding
/// trackable over time.
/// </param>
/// <param name="Severity">0 info, 1 low, 2 medium, 3 high, 4 critical.</param>
/// <param name="Cve">
/// Public vulnerability identifier, where one exists. Nullable because most
/// findings are configuration weaknesses rather than named vulnerabilities —
/// the `?` is C#'s nullable reference type, roughly Java's Optional but enforced
/// by the compiler rather than wrapped at runtime.
/// </param>
public record Finding(
    string Host,
    int    PluginId,
    string PluginName,
    short  Severity,
    string? Cve);

/// <summary>
/// One execution of the scanner across the whole estate. Every Finding belongs
/// to exactly one ScanRun, and comparing consecutive runs is where nearly all
/// the value in continuous monitoring comes from.
/// </summary>
/// <param name="ScanRunId">
/// Derived deterministically from source + timestamp rather than randomly — see
/// the comment in Program.cs. A random id here would make every replay look like
/// a brand-new scan, and every row would insert a second time.
/// </param>
/// <param name="Source">
/// Which system produced this data. Currently only "acas-nessus", but the field
/// exists because the correlation half of this program adds a second source, and
/// retro-fitting a source column onto a fact table is miserable.
/// </param>
public record ScanRun(
    Guid           ScanRunId,
    DateTimeOffset ScannedAt,
    string         Source);


// -----------------------------------------------------------------------------
// Report rows — scan findings
// -----------------------------------------------------------------------------

/// <summary>How many open findings at each severity, in the latest scan.</summary>
public record SeverityRow(short Severity, long N)
{
    /// <summary>Severity as a word rather than a number, for display.</summary>
    public string Label
    {
        get { return SeverityText.Label(Severity); }
    }
}

/// <summary>
/// Findings classified against the previous scan: "new", "resolved" or
/// "still open". <see cref="N"/> is how many fall into that bucket.
/// </summary>
public record DeltaRow(string Status, long N);

/// <summary>
/// How long findings at each severity have been open, averaged. This is the
/// aging question — a critical open for ninety days is a very different fact
/// from a critical found yesterday, even though both are "one critical".
/// </summary>
public record AgingRow(short Severity, long N, decimal AvgDaysOpen)
{
    /// <summary>Severity as a word rather than a number, for display.</summary>
    public string Label
    {
        get { return SeverityText.Label(Severity); }
    }
}

/// <summary>
/// High-and-critical count for one scan, alongside the previous scan's count and
/// the difference. <see cref="Prev"/> and <see cref="Delta"/> are nullable
/// because the earliest scan has nothing before it to compare against — SQL's
/// LAG() returns NULL there, and `long?` is how that arrives in C#.
/// </summary>
public record TrendRow(DateTime ScannedAt, long HighCrit, long? Prev, long? Delta);


// -----------------------------------------------------------------------------
// Report rows — the POA&M register
// -----------------------------------------------------------------------------

/// <summary>
/// What one reconciliation pass changed. Returned per scan so the ingest loop can
/// show the register moving rather than just its final state.
/// </summary>
public record PoamSyncResult(int Opened, int Reopened, int Closed);

/// <summary>
/// Open commitments at one severity, how many have blown their deadline, and what
/// that deadline is. <see cref="SlaDays"/> is carried so the report can show the
/// promise next to the performance without the caller hardcoding the policy.
/// </summary>
public record PoamStatusRow(short Severity, long Open, long Overdue, int SlaDays)
{
    /// <summary>Severity as a word rather than a number, for display.</summary>
    public string Label
    {
        get { return SeverityText.Label(Severity); }
    }
}

/// <summary>Open and overdue counts for one accountable owner.</summary>
public record OwnerLoadRow(string Owner, long Open, long Overdue);

/// <summary>
/// A single overdue commitment, with enough context to act on it: who owns it,
/// which machine, what the problem is, and how late.
/// </summary>
/// <param name="DueOn">
/// Formatted as text in SQL rather than returned as a date. Deliberate: Npgsql's
/// mapping for `date` has changed across versions (DateTime vs DateOnly), and
/// this row only ever gets printed. Formatting where the ambiguity is avoids
/// carrying it into C#.
/// </param>
public record PoamItemRow(
    string Owner,
    string Host,
    int    PluginId,
    string PluginName,
    short  Severity,
    string DueOn,
    int    DaysOverdue)
{
    /// <summary>Severity as a word rather than a number, for display.</summary>
    public string Label
    {
        get { return SeverityText.Label(Severity); }
    }
}


// -----------------------------------------------------------------------------
// Report rows — correlation between the two sources
// -----------------------------------------------------------------------------

/// <summary>
/// One security control, as the compliance record describes it, next to what the
/// scanner actually found — and the verdict on whether those two agree.
/// </summary>
/// <param name="Compliance">What the assessor recorded: Compliant or Non-Compliant.</param>
/// <param name="Findings">Live findings mapping to this control, in the latest scan.</param>
/// <param name="EvidenceSources">
/// How many scanner plugins are even *capable* of speaking to this control.
/// Zero is the important case: it means the scanner has no opinion and never
/// will, which is not the same as the control being clean. Keeping this on the
/// row is what lets the verdict tell those two apart.
/// </param>
/// <param name="Verdict">
/// CONTRADICTED, not assessable, corroborated, unevidenced, or verified clean.
/// Computed in SQL because it is a property of the data, not of the display.
/// </param>
public record CorrelationRow(
    string ControlId,
    string Title,
    string Compliance,
    long   Findings,
    short? WorstSeverity,
    long   HostsAffected,
    long   EvidenceSources,
    string Verdict);

/// <summary>
/// A scanner plugin that is reporting findings but maps to no tracked control —
/// the mirror image of a control with no evidence. Either the mapping is
/// incomplete or the authorisation package is.
/// </summary>
public record UncoveredRow(int PluginId, string PluginName, short Severity, long Findings);
