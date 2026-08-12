using Xunit;

namespace ScanIngest.Tests;

// =============================================================================
// NessusImportTests.cs — guard the Nessus .nessus parser.
//
// The parser is pure: XML in, ScanRun + Finding records out, no database. So it
// can be tested fast and offline. These checks cover the mapping (host, plugin,
// severity, cve), the two ways a scan time is read, and the two things a real
// file throws at you that must not crash the import: a malformed ReportItem and
// a host with no name.
//
// The later tests read the six checked-in exports in samples/weekly — the same
// files `dotnet run` loads — so the bundled data itself cannot rot unnoticed.
// They also pin the ordering guarantee: LoadAll must return oldest scan first,
// because every week-over-week report depends on it.
// =============================================================================

public class NessusImportTests
{
    // A compact but representative .nessus fragment. One good CVE finding, one
    // config finding with no CVE, one malformed item (non-numeric pluginID), and
    // a nameless host — the last two must be skipped, not throw.
    private const string SampleXml = """
        <NessusClientData_v2>
          <Report name="test">
            <ReportHost name="host-001.mil">
              <HostProperties>
                <tag name="HOST_START_TIMESTAMP">1786698000</tag>
              </HostProperties>
              <ReportItem port="445" severity="4" pluginID="97833" pluginName="SMBv1 Remote Code Execution">
                <cve>CVE-2017-0143</cve>
              </ReportItem>
              <ReportItem port="443" severity="2" pluginID="42873" pluginName="SSL Medium Strength Cipher Suites"/>
              <ReportItem port="443" severity="4" pluginID="BROKEN" pluginName="malformed - skipped"/>
            </ReportHost>
            <ReportHost>
              <ReportItem severity="1" pluginID="10107" pluginName="nameless host - skipped"/>
            </ReportHost>
          </Report>
        </NessusClientData_v2>
        """;

    private static readonly DateTimeOffset Fallback =
        new(2000, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Parse_KeepsOnlyWellFormedFindings()
    {
        var scan = NessusImport.ParseXml(SampleXml, Fallback);

        // Two valid findings survive: the malformed pluginID and the nameless
        // host are both dropped rather than crashing the parse.
        Assert.Equal(2, scan.Findings.Count);
    }

    [Fact]
    public void Parse_MapsEveryFieldOfACveFinding()
    {
        var scan = NessusImport.ParseXml(SampleXml, Fallback);

        var smb = scan.Findings.Single(f => f.PluginId == 97833);
        Assert.Equal("host-001.mil", smb.Host);
        Assert.Equal("SMBv1 Remote Code Execution", smb.PluginName);
        Assert.Equal((short)4, smb.Severity);
        Assert.Equal("CVE-2017-0143", smb.Cve);
    }

    [Fact]
    public void Parse_LeavesCveNullWhenThereIsNone()
    {
        var scan = NessusImport.ParseXml(SampleXml, Fallback);

        var ssl = scan.Findings.Single(f => f.PluginId == 42873);
        Assert.Null(ssl.Cve);
    }

    [Fact]
    public void Parse_ReadsScanTimeFromEpochTag()
    {
        var scan = NessusImport.ParseXml(SampleXml, Fallback);

        // 1786698000 == 2026-08-14T09:00:00Z. The fallback must NOT be used here.
        Assert.Equal(new DateTimeOffset(2026, 8, 14, 9, 0, 0, TimeSpan.Zero), scan.ScannedAt);
    }

    [Fact]
    public void Parse_UsesFallbackWhenNoTimestampInFile()
    {
        const string noTime = """
            <NessusClientData_v2><Report name="t">
              <ReportHost name="host-002.mil">
                <ReportItem severity="1" pluginID="10107" pluginName="HTTP Server Type and Version"/>
              </ReportHost>
            </Report></NessusClientData_v2>
            """;

        var scan = NessusImport.ParseXml(noTime, Fallback);

        Assert.Single(scan.Findings);
        Assert.Equal(Fallback, scan.ScannedAt);
    }

    private static string WeeklyDir =>
        Path.Combine(AppContext.BaseDirectory, "samples", "weekly");

    [Fact]
    public void ParseFile_ReadsTheFirstBundledWeeklyScan()
    {
        var path = Path.Combine(WeeklyDir, "scan-2026-07-03.nessus");
        Assert.True(File.Exists(path), $"sample not found at {path}");

        var scan = NessusImport.ParseFile(path, Fallback);

        // The first weekly export: 309 findings across the forty-host estate,
        // scanned 2026-07-03 at 09:00Z.
        Assert.Equal(309, scan.Findings.Count);
        Assert.Equal(40, scan.Findings.Select(f => f.Host).Distinct().Count());
        Assert.Equal(new DateTimeOffset(2026, 7, 3, 9, 0, 0, TimeSpan.Zero), scan.ScannedAt);
    }

    [Fact]
    public void LoadAll_ReturnsTheSixWeeklyScansOldestFirst()
    {
        // The whole bundled history. Ordering is load-bearing: every trend and
        // delta report compares a scan against the one before it.
        var scans = NessusImport.LoadAll(WeeklyDir, Fallback);

        Assert.Equal(6, scans.Count);
        Assert.Equal(1730, scans.Sum(s => s.Findings.Count));

        for (var i = 1; i < scans.Count; i++)
            Assert.True(scans[i].ScannedAt > scans[i - 1].ScannedAt,
                "scans must be ordered oldest first");

        // Seven days apart, 2026-07-03 through 2026-08-07.
        Assert.Equal(new DateTimeOffset(2026, 7, 3, 9, 0, 0, TimeSpan.Zero), scans[0].ScannedAt);
        Assert.Equal(new DateTimeOffset(2026, 8, 7, 9, 0, 0, TimeSpan.Zero), scans[^1].ScannedAt);
    }

    [Fact]
    public void LoadAll_OnASingleFile_ReturnsJustThatScan()
    {
        var path  = Path.Combine(WeeklyDir, "scan-2026-07-10.nessus");
        var scans = NessusImport.LoadAll(path, Fallback);

        Assert.Single(scans);
        Assert.Equal(294, scans[0].Findings.Count);
    }

    [Fact]
    public void LoadAll_OnAMissingPath_ReturnsEmptyRatherThanThrowing()
    {
        var scans = NessusImport.LoadAll(
            Path.Combine(AppContext.BaseDirectory, "no-such-folder"), Fallback);

        Assert.Empty(scans);
    }

    [Fact]
    public void DeterministicRunId_IsStableForTheSameScan()
    {
        // Same source + timestamp must always produce the same id — that is what
        // turns a re-import into a replay instead of a duplicate scan.
        var at = new DateTimeOffset(2026, 7, 3, 9, 0, 0, TimeSpan.Zero);

        Assert.Equal(
            NessusImport.DeterministicRunId("acas-nessus", at),
            NessusImport.DeterministicRunId("acas-nessus", at));

        Assert.NotEqual(
            NessusImport.DeterministicRunId("acas-nessus", at),
            NessusImport.DeterministicRunId("acas-nessus", at.AddDays(7)));
    }
}
