namespace ScanIngest;

// C# `record` — like a Java 14+ record. Value equality, concise constructor,
// immutable by default. This is the shape a scanner hands us per finding.
public record Finding(
    string Host,
    int    PluginId,
    string PluginName,
    short  Severity,      // 0 info, 1 low, 2 medium, 3 high, 4 critical
    string? Cve);

// A single execution of a scan across the estate.
public record ScanRun(
    Guid           ScanRunId,
    DateTimeOffset ScannedAt,
    string         Source);

// ---- Report row shapes. Dapper maps columns to these by name. ----

public record SeverityRow(short Severity, long N)
{
    public string Label => Severity switch
    {
        4 => "critical",
        3 => "high",
        2 => "medium",
        1 => "low",
        _ => "info"
    };
}

public record DeltaRow(string Status, long N);

public record AgingRow(short Severity, long N, decimal AvgDaysOpen);

public record TrendRow(DateTime ScannedAt, long HighCrit, long? Prev, long? Delta);

// ---- POA&M register ----

public record PoamSyncResult(int Opened, int Reopened, int Closed);

public record PoamStatusRow(short Severity, long Open, long Overdue, int SlaDays)
{
    public string Label => Severity switch
    {
        4 => "critical", 3 => "high", 2 => "medium", 1 => "low", _ => "info"
    };
}

public record OwnerLoadRow(string Owner, long Open, long Overdue);

public record PoamItemRow(
    string Owner,
    string Host,
    int    PluginId,
    string PluginName,
    short  Severity,
    string DueOn,
    int    DaysOverdue);

// ---- Correlation between the scanner and the compliance record ----

public record CorrelationRow(
    string ControlId,
    string Title,
    string Compliance,
    long   Findings,
    short? WorstSeverity,
    long   HostsAffected,
    long   EvidenceSources,
    string Verdict);

public record UncoveredRow(int PluginId, string PluginName, short Severity, long Findings);
