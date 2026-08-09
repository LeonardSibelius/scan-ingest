using Xunit;

namespace ScanIngest.Tests;

// =============================================================================
// SqlSyncTests.cs — guard the seam between the code and queries.sql.
//
// The report SQL lives in queries.sql, not in the C#. That buys one copy of it
// instead of two, and it costs a compile-time guarantee: the compiler cannot
// check a string like Get("BySeverityAsync") against a file it never reads. A
// typo there is not a build error. It is a crash at whatever hour the program
// next runs.
//
// These tests buy that guarantee back, at build time. Four checks:
//
//   The file is found and parses into exactly ten queries. Without this, every
//   other test here would pass vacuously by finding nothing to check.
//
//   Every name the code asks for is defined in the file, and resolves to
//   something that looks like SQL. One test per name, so a failure says WHICH.
//
//   Every name defined in the file is asked for by the code. A block nobody
//   calls is either dead SQL or a rename finished on one side only, and both
//   look exactly like a working file until something counts them.
//
//   Asking for a name that does not exist produces a message listing the names
//   that do. That is the runtime failure this file exists to soften, so when it
//   does happen the reader is not left grepping.
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
        // Findings.cs
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
