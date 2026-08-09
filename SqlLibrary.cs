using System.Text.RegularExpressions;

namespace ScanIngest;

// =============================================================================
// SqlLibrary.cs — one copy of the report SQL, loaded from queries.sql.
//
// WHY THIS EXISTS
//
// The report SQL used to be written twice: once as raw string literals inside
// the C#, and once as plain text in queries.sql so that a human (and
// reports.ps1) could run it directly. Two copies with nothing connecting them,
// guarded by a test that compared them and failed when they diverged.
//
// The test worked — it caught three real differences the day it was written. But
// a test that stops two copies drifting is a smaller idea than not having two
// copies. queries.sql is now the only place the report SQL lives, and both the
// program and the PowerShell menu read it.
//
// WHAT THIS COSTS
//
// It is not a free win, and the tradeoff is worth understanding:
//
//   LOST   The SQL no longer sits next to the record type it fills. In
//          Findings.cs you used to see the query and `SeverityRow` within a few
//          lines of each other.
//
//   LOST   A misspelled query name is no longer a compile error. It is a
//          runtime failure — which is why Get() throws something a human can act
//          on, and why a test asserts that every name the code asks for exists.
//
//   GAINED One copy. No possibility of drift, in either direction, ever.
//
// Most teams keep SQL in the code and accept the duplication. This project went
// the other way because it is meant to be read, and one copy is easier to read
// than two plus a test explaining why there are two.
// =============================================================================

public static class SqlLibrary
{
    // Parsed once on first use and held for the life of the process. The file
    // does not change while the program runs.
    private static readonly Lazy<Dictionary<string, string>> Queries = new(Load);

    /// <summary>
    /// Returns the SQL for a named report — the method name as it appears in
    /// queries.sql, e.g. <c>"BySeverityAsync"</c>.
    /// </summary>
    /// <exception cref="KeyNotFoundException">
    /// Thrown with the list of names that DO exist, because the failure this
    /// guards against is a typo, and a message that just says "not found" leaves
    /// you grepping.
    /// </exception>
    public static string Get(string name)
    {
        if (Queries.Value.TryGetValue(name, out var sql)) return sql;

        throw new KeyNotFoundException(
            $"No SQL named '{name}' in queries.sql. Available: " +
            string.Join(", ", Queries.Value.Keys.OrderBy(k => k)));
    }

    /// <summary>Every report name defined in queries.sql.</summary>
    public static IReadOnlyCollection<string> Names => Queries.Value.Keys;

    /// <summary>
    /// Reads queries.sql and splits it into named reports.
    ///
    /// The file's shape, which reports.ps1 parses identically:
    ///
    ///     -- ==========================
    ///     -- Findings.cs -> BySeverityAsync
    ///     -- a description
    ///     -- ==========================
    ///     SELECT ... ;
    ///
    /// A rule line opens or closes a header block; the `File.cs -> Method` line
    /// names the report; everything after the closing rule is its SQL.
    /// </summary>
    private static Dictionary<string, string> Load()
    {
        // The .csproj copies queries.sql next to the binary, so it is found the
        // same way whether run via `dotnet run` or from a published folder.
        var path = Path.Combine(AppContext.BaseDirectory, "queries.sql");

        if (!File.Exists(path))
            throw new FileNotFoundException(
                $"queries.sql was not found at {path}. It is copied there by the " +
                "build; if it is missing, the .csproj is no longer copying it.", path);

        var result   = new Dictionary<string, string>(StringComparer.Ordinal);
        string? name = null;
        var     sql  = new List<string>();
        var  inHeader = false;

        void Bank()
        {
            if (name is not null && sql.Any(l => l.Trim().Length > 0))
                result[name] = string.Join("\n", sql).Trim();
        }

        foreach (var line in File.ReadLines(path))
        {
            if (Regex.IsMatch(line, @"^-- =+$"))
            {
                if (inHeader) inHeader = false;                       // header ends
                else { Bank(); name = null; sql.Clear(); inHeader = true; }
                continue;
            }

            if (inHeader)
            {
                var m = Regex.Match(line, @"^--\s+\S+\.cs\s+->\s+(\S+)\s*$");
                if (m.Success) name = m.Groups[1].Value;
            }
            else if (name is not null)
            {
                sql.Add(line);
            }
        }
        Bank();

        return result;
    }
}
