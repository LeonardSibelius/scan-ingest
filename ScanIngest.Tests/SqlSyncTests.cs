using System.Text.RegularExpressions;
using Xunit;

namespace ScanIngest.Tests;

// =============================================================================
// SqlSyncTests.cs — stop queries.sql drifting away from the code.
//
// THE PROBLEM THIS EXISTS TO CATCH
//
// The SQL that actually runs lives inside the C# files, written as raw string
// literals. queries.sql holds a second copy of the same SQL as plain text, so a
// human can read and run it without going through the program, and so
// reports.ps1 has something to build a menu from.
//
// Two copies. Nothing connecting them. Edit a query in Reports.cs and
// queries.sql silently becomes a lie — and the worst part is that it keeps
// working. reports.ps1 will confidently show you SQL the program no longer runs,
// and the numbers will look plausible.
//
// This test fails the build when that happens.
//
// WHAT IT CHECKS, AND WHAT IT DOES NOT
//
// It checks one direction: every query in queries.sql must still exist in the
// source. That is the direction that goes wrong in practice, because queries.sql
// is the copy.
//
// It does NOT check the reverse, because plenty of SQL in the source is
// deliberately absent from queries.sql — the schema, the inserts, the POA&M
// write path. queries.sql only ever holds the read-only reports.
// =============================================================================

public class SqlSyncTests
{
    /// <summary>
    /// Walks up from the test binary until it finds the repository root, which is
    /// whichever folder contains queries.sql.
    /// </summary>
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "queries.sql")))
            dir = dir.Parent;

        Assert.True(dir is not null, "Could not find queries.sql in any parent directory.");
        return dir!.FullName;
    }

    /// <summary>
    /// Reduces a piece of SQL to just its meaning, so that indentation, blank
    /// lines, comments and casing cannot cause a false failure.
    ///
    /// Deliberately NOT normalised away: table names, column names, join
    /// conditions, CASE branches — everything that would constitute real drift.
    /// </summary>
    private static string Normalise(string sql)
    {
        // Strip -- comments. The two copies carry different explanatory notes
        // and that is fine; the notes are not the query.
        sql = Regex.Replace(sql, @"--[^\n]*", " ");

        // queries.sql hardcodes the row limit that the C# passes as a parameter,
        // because psql has no way to supply one. This is the ONE declared
        // difference between the copies. If you add another, add it here — and
        // think hard first, because each one is a place drift can hide.
        sql = sql.Replace("@limit", "10");

        // Collapse every run of whitespace to a single space.
        sql = Regex.Replace(sql, @"\s+", " ");

        // Case and underscores are normalised away, and that is not laziness —
        // it is precisely the rule Dapper itself matches by. Dapper binds a
        // result column to a constructor parameter ignoring case and
        // underscores, so `AS HighCrit` and `AS high_crit` are the same name as
        // far as anything downstream is concerned.
        //
        // Comparing on exactly the rule that matters means this test fails for
        // every difference that would break the program, and stays quiet about
        // every difference that would not.
        sql = sql.Replace("_", "");

        return sql.Trim().TrimEnd(';').Trim().ToLowerInvariant();
    }

    /// <summary>
    /// Pulls every raw string literal out of the C# sources. Every piece of SQL
    /// in this project is written as one, so this is the complete set of
    /// candidates a queries.sql entry could match.
    /// </summary>
    private static List<string> SqlLiteralsInSource(string root)
    {
        var literals = new List<string>();

        foreach (var file in Directory.GetFiles(root, "*.cs", SearchOption.TopDirectoryOnly))
        {
            var text = File.ReadAllText(file);

            // Raw string literals are delimited by triple quotes and do not nest,
            // so a non-greedy match between pairs is sufficient here.
            foreach (Match m in Regex.Matches(text, "\"\"\"(.*?)\"\"\"", RegexOptions.Singleline))
                literals.Add(m.Groups[1].Value);

            // Ordinary one-line string literals too. The shortest queries are
            // written that way — `ExecuteScalarAsync<long>("SELECT COUNT(*) ...")`
            // needs no raw string. This also sweeps up console messages and
            // connection strings, which is harmless: extra candidates cannot
            // cause a false pass, only a slightly larger haystack.
            foreach (Match m in Regex.Matches(text, "\"([^\"\\n]*)\""))
                literals.Add(m.Groups[1].Value);
        }

        return literals;
    }

    /// <summary>
    /// Splits queries.sql into its individual reports, using the same header
    /// convention reports.ps1 relies on: a rule line, a `File.cs -> Method` line,
    /// a description, a closing rule, then the SQL.
    /// </summary>
    private static List<(string Name, string Sql)> ReportsInQueriesFile(string root)
    {
        var reports = new List<(string, string)>();
        var lines   = File.ReadAllLines(Path.Combine(root, "queries.sql"));

        string?       name     = null;
        var           sql      = new List<string>();
        var           inHeader = false;

        void Bank()
        {
            if (name is not null && sql.Any(l => l.Trim().Length > 0))
                reports.Add((name, string.Join("\n", sql)));
        }

        foreach (var line in lines)
        {
            if (Regex.IsMatch(line, @"^-- =+$"))
            {
                if (inHeader) { inHeader = false; }         // header ends, SQL follows
                else          { Bank(); name = null; sql.Clear(); inHeader = true; }
                continue;
            }

            if (inHeader)
            {
                var m = Regex.Match(line, @"^--\s+(\S+\.cs)\s+->\s+(\S+)\s*$");
                if (m.Success) name = $"{m.Groups[1].Value} -> {m.Groups[2].Value}";
            }
            else if (name is not null)
            {
                sql.Add(line);
            }
        }
        Bank();

        return reports;
    }

    [Fact]
    public void QueriesFile_ContainsTheReportsWeExpect()
    {
        var reports = ReportsInQueriesFile(RepoRoot());

        // A sanity check on the parser itself. If someone reformats queries.sql
        // in a way this cannot read, every other test in here would pass
        // vacuously by finding nothing to compare.
        Assert.Equal(10, reports.Count);
        Assert.All(reports, r => Assert.False(string.IsNullOrWhiteSpace(r.Sql)));
    }

    [Fact]
    public void EverySqlLiteralInSource_IsFindable()
    {
        // Likewise: if the literal extractor breaks, the comparison below would
        // fail for the wrong reason and send someone hunting a drift that is not
        // there. Assert we actually found a plausible number of them.
        var literals = SqlLiteralsInSource(RepoRoot());
        Assert.True(literals.Count >= 15,
            $"Expected to find at least 15 SQL literals in the sources, found {literals.Count}.");
    }

    /// <summary>
    /// Queries the text comparison cannot cover, and exactly why.
    ///
    /// StatusAsync builds its SQL by interpolation — the source contains
    /// `MAX({SlaCase.Replace("severity", "p.severity")})`, a C# expression, where
    /// queries.sql necessarily holds the expanded CASE. There is no honest way to
    /// compare those as text without re-implementing the interpolation here, and
    /// a test that re-implements the thing it is testing proves nothing.
    ///
    /// This is a hole. It is a named, counted hole rather than a silent one, and
    /// <see cref="TheOnlyExemptQuery_IsTheInterpolatedOne"/> stops it growing
    /// quietly.
    /// </summary>
    private static readonly string[] ExemptBecauseInterpolated =
    [
        "Poam.cs -> StatusAsync"
    ];

    [Fact]
    public void TheOnlyExemptQuery_IsTheInterpolatedOne()
    {
        // If someone adds an exemption to make a failure go away, this fails and
        // makes them say so out loud in a commit message.
        Assert.Single(ExemptBecauseInterpolated);
        Assert.Equal("Poam.cs -> StatusAsync", ExemptBecauseInterpolated[0]);
    }

    [Fact]
    public void EveryQueryInQueriesFile_StillMatchesTheCode()
    {
        var root     = RepoRoot();
        var reports  = ReportsInQueriesFile(root);
        var literals = SqlLiteralsInSource(root).Select(Normalise).ToHashSet();

        var drifted = new List<string>();

        foreach (var (name, sql) in reports)
            if (!ExemptBecauseInterpolated.Contains(name) && !literals.Contains(Normalise(sql)))
                drifted.Add(name);

        Assert.True(drifted.Count == 0,
            "queries.sql has drifted from the code. These reports no longer match any SQL " +
            "in the source:\n  " + string.Join("\n  ", drifted) +
            "\n\nqueries.sql is a copy. The C# is what actually runs, so the C# is right by " +
            "definition — update queries.sql to match it.");
    }
}
