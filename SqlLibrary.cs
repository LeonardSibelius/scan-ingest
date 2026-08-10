using System.Text.RegularExpressions;

namespace ScanIngest;

// =============================================================================
// SqlLibrary.cs — fetches a named query out of queries.sql.
//
// queries.sql holds the report SQL, and it is the only place that SQL exists.
// This class reads that file once, splits it into named blocks, and hands one
// back: Get("BySeverityAsync") returns the SELECT under that heading.
//
// reports.ps1 parses the same file by the same rules, so the C# program and the
// PowerShell menu run identical SQL by construction. The format itself is
// documented in the banner at the top of queries.sql.
//
// THE TRADEOFF
//
// Keeping SQL in a data file instead of in string literals is not a free win:
//
//   COST   The SQL does not sit beside the record type it fills. Understanding
//          BySeverityAsync means opening two files rather than one.
//
//   COST   A misspelled query name is a RUNTIME failure, not a compile error.
//          The compiler cannot check a string against a file it never reads.
//          That is why Get() throws a message listing the names that DO exist,
//          and why SqlSyncTests asserts in both directions: every name the code
//          asks for is in the file, and every block in the file is asked for.
//
//   GAIN   One copy. The program and the menu cannot disagree, because there is
//          no second thing to disagree with.
//
//   GAIN   The file runs as-is. Any block can be pasted straight into a database
//          console with no substitution, which is why no query takes parameters.
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

        // Sorted so the message reads the same way every time. A dictionary hands
        // its keys back in whatever order it pleases.
        var available = new List<string>(Queries.Value.Keys);
        available.Sort();

        throw new KeyNotFoundException(
            $"No SQL named '{name}' in queries.sql. Available: " +
            string.Join(", ", available));
    }

    /// <summary>Every report name defined in queries.sql.</summary>
    public static IReadOnlyCollection<string> Names
    {
        get { return Queries.Value.Keys; }
    }

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

        // Records the block just finished, if it is worth recording. A named
        // block with nothing but blank lines under it is a header, not a query.
        void Bank()
        {
            if (name is null) return;

            var hasSql = false;

            foreach (var line in sql)
            {
                if (line.Trim().Length > 0)
                {
                    hasSql = true;
                    break;
                }
            }

            if (hasSql) result[name] = string.Join("\n", sql).Trim();
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
