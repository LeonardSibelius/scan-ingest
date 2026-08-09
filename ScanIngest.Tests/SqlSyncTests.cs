using Xunit;

namespace ScanIngest.Tests;

// =============================================================================
// SqlSyncTests.cs — guard the seam between the code and queries.sql.
//
// WHAT THIS USED TO BE, AND WHY IT CHANGED
//
// The report SQL was once written twice — as raw string literals in the C#, and
// again as plain text in queries.sql for psql and reports.ps1. This file
// compared the two copies and failed when they drifted. It worked: it caught
// three real differences the day it was written.
//
// But a test that keeps two copies in step is a smaller idea than not having two
// copies. queries.sql is now the only place the report SQL lives, and both the
// program and the menu read it. There is nothing left to compare.
//
// WHAT REPLACES IT
//
// Moving the SQL out of the code traded a compile-time guarantee for a runtime
// one: a misspelled query name used to be a build error and is now a crash at
// whatever hour the program next runs. These tests buy that guarantee back —
// every name the code asks for is checked, at build time, against what the file
// actually defines.
// =============================================================================

public class SqlSyncTests
{
    /// <summary>
    /// Every query name the program looks up. If a call to
    /// <c>SqlLibrary.Get("...")</c> is added anywhere, add it here too — that is
    /// the cost of the SQL living outside the compiler's reach, and this list is
    /// what keeps that cost visible instead of surprising.
    /// </summary>
    private static readonly string[] NamesTheCodeAsksFor =
    [
        // Reports.cs
        "BySeverityAsync", "DeltaAsync", "AgingAsync", "TrendAsync", "TotalFactRowsAsync",
        // Poam.cs
        "StatusAsync", "ByOwnerAsync", "WorstOverdueAsync",
        // Controls.cs
        "CorrelateAsync", "UncoveredAsync",
    ];

    [Fact]
    public void QueriesFile_IsFoundAndParsed()
    {
        // If the .csproj stops copying queries.sql next to the binary, or the
        // header format changes so the parser reads nothing, every other test
        // here would pass vacuously by finding nothing to check.
        Assert.NotEmpty(SqlLibrary.Names);
        Assert.Equal(10, SqlLibrary.Names.Count);
    }

    [Theory]
    [InlineData("BySeverityAsync")]
    [InlineData("DeltaAsync")]
    [InlineData("AgingAsync")]
    [InlineData("TrendAsync")]
    [InlineData("TotalFactRowsAsync")]
    [InlineData("StatusAsync")]
    [InlineData("ByOwnerAsync")]
    [InlineData("WorstOverdueAsync")]
    [InlineData("CorrelateAsync")]
    [InlineData("UncoveredAsync")]
    public void EveryQueryTheCodeAsksFor_ExistsAndIsNotEmpty(string name)
    {
        // Reported as ten separate tests, so a failure names the missing query
        // rather than just saying "one of them is gone".
        var sql = SqlLibrary.Get(name);

        Assert.False(string.IsNullOrWhiteSpace(sql), $"'{name}' resolved to empty SQL.");
        Assert.Contains("select", sql, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void QueriesFile_DefinesNothingTheCodeDoesNotUse()
    {
        // The other direction. A query nobody calls is either dead weight or a
        // rename somebody half-finished, and both are worth noticing early.
        var orphaned = SqlLibrary.Names.Except(NamesTheCodeAsksFor).OrderBy(n => n).ToList();

        Assert.True(orphaned.Count == 0,
            "queries.sql defines queries that no code asks for:\n  " +
            string.Join("\n  ", orphaned) +
            "\n\nEither wire them up or delete them.");
    }

    [Fact]
    public void AskingForSomethingThatDoesNotExist_SaysWhatDoesExist()
    {
        // The failure mode this whole file exists to soften. When it does happen
        // at runtime, the message has to be actionable — "not found" alone would
        // leave someone grepping a file they may not know exists.
        var ex = Assert.Throws<KeyNotFoundException>(() => SqlLibrary.Get("NoSuchReport"));

        Assert.Contains("NoSuchReport", ex.Message);
        Assert.Contains("queries.sql", ex.Message);
        Assert.Contains("BySeverityAsync", ex.Message);   // lists what IS available
    }
}
