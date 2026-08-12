using System.Globalization;
using System.Xml.Linq;
using Npgsql;

namespace ScanIngest;

// =============================================================================
// NessusImport.cs — reads a real Tenable Nessus .nessus export and turns it
// into the same Finding records Generator.cs invents.
//
// This is the piece the whole architecture was built to receive. Generator.cs
// is a stand-in for the scanner; this is the real thing. It parses Nessus's
// native .nessus file (which is XML) and produces a ScanRun plus a list of
// Finding records — the exact same types Ingest.IngestAsync already takes. So
// nothing downstream changes: raw_finding, finding, poam, and every report read
// the normalized rows and never learn whether they came from Generator or from
// a real scanner file. That is the point worth demonstrating.
//
// WHAT A .nessus FILE LOOKS LIKE
//
//   <NessusClientData_v2>
//     <Report name="...">
//       <ReportHost name="host-005.mil">
//         <HostProperties>
//           <tag name="HOST_START_TIMESTAMP">1786698000</tag>   (unix seconds)
//         </HostProperties>
//         <ReportItem pluginID="97833" pluginName="SMBv1..." severity="4" ...>
//           <cve>CVE-2017-0143</cve>
//         </ReportItem>
//         ... more ReportItems ...
//       </ReportHost>
//       ... more ReportHosts ...
//     </Report>
//   </NessusClientData_v2>
//
// The five fields this project uses map straight across:
//   host        = ReportHost @name
//   plugin_id   = ReportItem @pluginID
//   plugin_name = ReportItem @pluginName
//   severity    = ReportItem @severity   (0-4, the SAME scale this project uses)
//   cve         = first <cve> child, or null
//
// Nessus's severity is already 0=info .. 4=critical, so no remapping is needed —
// which is not a coincidence, it is why this project chose that scale.
//
// A real ReportItem carries dozens of other fields (port, cvss_base_score,
// solution, plugin_output, ...). This reads the five it needs and ignores the
// rest, exactly as Ingest's landing table does.
// =============================================================================

public static class NessusImport
{
    /// <summary>
    /// The result of parsing one .nessus file: the scan's timestamp and its findings.
    /// </summary>
    public sealed record ParsedScan(DateTimeOffset ScannedAt, IReadOnlyList<Finding> Findings);

    /// <summary>Parses a .nessus file from disk.</summary>
    public static ParsedScan ParseFile(string path, DateTimeOffset fallbackScannedAt)
        => Parse(XDocument.Load(path), fallbackScannedAt);

    /// <summary>
    /// Parses .nessus XML from a string. Split out so tests can run without a file
    /// on disk and without a database.
    /// </summary>
    public static ParsedScan ParseXml(string xml, DateTimeOffset fallbackScannedAt)
        => Parse(XDocument.Parse(xml), fallbackScannedAt);

    private static ParsedScan Parse(XDocument doc, DateTimeOffset fallbackScannedAt)
    {
        var findings   = new List<Finding>();
        var startTimes = new List<DateTimeOffset>();

        // C#: `.Descendants("ReportHost")` finds every ReportHost element anywhere
        // C#: below the root. LINQ-to-XML, part of the base library — no package.
        foreach (var host in doc.Descendants("ReportHost"))
        {
            var hostName = (string?)host.Attribute("name");
            if (string.IsNullOrWhiteSpace(hostName))
                continue;   // a host with no name is unusable; skip it

            var started = ReadHostStart(host);
            if (started is not null)
                startTimes.Add(started.Value);

            foreach (var item in host.Elements("ReportItem"))
            {
                // pluginID and severity are required and numeric. A ReportItem
                // missing either is malformed; skip it rather than crash the whole
                // import over one bad row.
                if (!int.TryParse((string?)item.Attribute("pluginID"), out var pluginId))
                    continue;
                if (!short.TryParse((string?)item.Attribute("severity"), out var severity))
                    continue;

                var pluginName = (string?)item.Attribute("pluginName") ?? "";

                // A ReportItem may list several <cve> children; the finding model
                // holds one, so take the first. Null when there is none — which is
                // most of them, because most findings are configuration weaknesses.
                var cve = item.Elements("cve").FirstOrDefault()?.Value;

                findings.Add(new Finding(hostName, pluginId, pluginName, severity, cve));
            }
        }

        // Sort for stable output, same reason Generator does: findings read in
        // file order still want a defined order once they are downstream.
        findings.Sort((a, b) =>
        {
            var byHost = string.CompareOrdinal(a.Host, b.Host);
            return byHost != 0 ? byHost : a.PluginId.CompareTo(b.PluginId);
        });

        // One scan_run has one timestamp. Use the earliest host start (when the
        // scan began); fall back to the caller's value if the file carries none.
        var scannedAt = startTimes.Count > 0 ? startTimes.Min() : fallbackScannedAt;

        return new ParsedScan(scannedAt, findings);
    }

    /// <summary>
    /// Reads a host's scan-start time from its HostProperties tags. Prefers the
    /// unix-epoch tag (unambiguous) and falls back to the human-readable one.
    /// Returns null if neither is present or parseable.
    /// </summary>
    private static DateTimeOffset? ReadHostStart(XElement host)
    {
        string? Tag(string name) => host
            .Elements("HostProperties")
            .Elements("tag")
            .FirstOrDefault(t => (string?)t.Attribute("name") == name)?.Value;

        // Nessus writes HOST_START_TIMESTAMP as unix seconds — the safe one.
        if (long.TryParse(Tag("HOST_START_TIMESTAMP"), out var epoch))
            return DateTimeOffset.FromUnixTimeSeconds(epoch);

        // Older files carry only HOST_START, a human-readable string. Parse it
        // loosely; if it does not parse, the caller's fallback is used instead.
        if (DateTimeOffset.TryParse(Tag("HOST_START"), CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal, out var parsed))
            return parsed;

        return null;
    }

    /// <summary>
    /// Parses a .nessus file and loads it through the existing ingest path — the
    /// same Ingest.IngestAsync that Generator's output goes through. This is the
    /// whole demonstration: a real scanner file reaching the pipeline with no
    /// change to storage or reporting.
    /// </summary>
    /// <returns>Rows that landed in the fact table (zero on a replay).</returns>
    public static async Task<int> ImportFileAsync(
        NpgsqlConnection conn, string path, string source = "nessus-file",
        DateTimeOffset? fallbackScannedAt = null)
    {
        var parsed = ParseFile(path, fallbackScannedAt ?? DateTimeOffset.UtcNow);

        var run = new ScanRun(
            ScanRunId: DeterministicRunId(source, parsed.ScannedAt),
            ScannedAt: parsed.ScannedAt,
            Source:    source);

        return await Ingest.IngestAsync(conn, run, parsed.Findings);
    }

    // Same derivation Program.cs uses for its run ids: a stable id from source +
    // timestamp, so re-importing the same file is a harmless replay rather than a
    // second scan. (Program.cs keeps its own copy; when this merges into
    // `dotnet run` the two can share one helper.)
    private static Guid DeterministicRunId(string source, DateTimeOffset at)
    {
        var bytes = System.Security.Cryptography.MD5.HashData(
            System.Text.Encoding.UTF8.GetBytes($"{source}|{at:O}"));
        return new Guid(bytes);
    }
}
