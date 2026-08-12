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
// The last test parses the checked-in samples/sample-scan.nessus, so the sample
// file itself cannot rot unnoticed.
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

    [Fact]
    public void ParseFile_ReadsTheCheckedInSample()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "samples", "sample-scan.nessus");
        Assert.True(File.Exists(path), $"sample not found at {path}");

        var scan = NessusImport.ParseFile(path, Fallback);

        // 3 hosts, 11 findings, 4 of them carrying a CVE, scan dated 2026-08-14.
        Assert.Equal(11, scan.Findings.Count);
        Assert.Equal(4, scan.Findings.Count(f => f.Cve is not null));
        Assert.Equal(new DateTimeOffset(2026, 8, 14, 9, 0, 0, TimeSpan.Zero), scan.ScannedAt);
    }
}
