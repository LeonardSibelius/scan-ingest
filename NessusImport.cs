using System.Globalization;
using System.Xml.Linq;
using Npgsql;

namespace ScanIngest;

// =============================================================================
// NessusImport.cs — reads Tenable Nessus .nessus export files.
//
// This is where the project's data comes from. A .nessus file is what Nessus
// (and ACAS, the DoD deployment of it) writes when a scan finishes. This class
// parses those files into Finding records and hands them to Ingest.cs, which
// stores them. Nothing here touches the database directly except through Ingest.
//
// The repository ships six of them under samples/weekly — one per week,
// 2026-07-03 through 2026-08-07, across a forty-host estate. They are a real
// estate's worth of scan history: problems that persist from week to week, some
// remediated, some newly discovered. That evolution is the point. A single scan
// tells you what is broken today; six consecutive scans tell you what is getting
// fixed, what is being ignored, and what came back — which is what continuous
// monitoring actually means, and what every trend, delta, aging and POA&M report
// in this project is computed from.
//
// Point the program at your own directory of .nessus exports and it works the
// same way. Nothing in this file, or downstream of it, knows or cares whether a
// file came from this repository or from a live scanner.
//
// WHAT A .nessus FILE LOOKS LIKE
//
//   <NessusClientData_v2>
//     <Report name="...">
//       <ReportHost name="host-005.mil">
//         <HostProperties>
//           <tag name="HOST_START_TIMESTAMP">1783501200</tag>   (unix seconds)
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
    /// Which system produced the data, recorded on every scan_run. ACAS is the
    /// DoD's Nessus deployment, and this is the name the reports and docs use.
    /// </summary>
    public const string DefaultSource = "acas-nessus";

    /// <summary>One parsed .nessus file: when the scan ran, and what it found.</summary>
    public sealed record ParsedScan(string Path, DateTimeOffset ScannedAt, IReadOnlyList<Finding> Findings);

    /// <summary>What an ingest of one parsed scan did.</summary>
    public sealed record ImportResult(ScanRun Run, int Landed);

    /// <summary>
    /// Loads every .nessus file at <paramref name="pathOrDirectory"/> — a single
    /// file, or a directory of them — and returns them ordered oldest scan first.
    ///
    /// Ordering by the scan timestamp INSIDE each file, not by filename, is
    /// deliberate: the reports compare each scan against the one before it, so
    /// feeding them out of order would compute deltas backwards. A filename is a
    /// convention; the timestamp is the data.
    /// </summary>
    public static IReadOnlyList<ParsedScan> LoadAll(string pathOrDirectory, DateTimeOffset fallbackScannedAt)
    {
        var files = new List<string>();

        if (File.Exists(pathOrDirectory))
            files.Add(pathOrDirectory);
        else if (Directory.Exists(pathOrDirectory))
            files.AddRange(Directory.GetFiles(pathOrDirectory, "*.nessus"));

        var scans = new List<ParsedScan>();
        foreach (var file in files)
            scans.Add(ParseFile(file, fallbackScannedAt));

        scans.Sort((a, b) => a.ScannedAt.CompareTo(b.ScannedAt));
        return scans;
    }

    /// <summary>Parses one .nessus file from disk.</summary>
    public static ParsedScan ParseFile(string path, DateTimeOffset fallbackScannedAt)
        => Parse(XDocument.Load(path), path, fallbackScannedAt);

    /// <summary>
    /// Parses .nessus XML from a string. Split out so tests can run without a file
    /// on disk and without a database.
    /// </summary>
    public static ParsedScan ParseXml(string xml, DateTimeOffset fallbackScannedAt)
        => Parse(XDocument.Parse(xml), "(xml)", fallbackScannedAt);

    private static ParsedScan Parse(XDocument doc, string path, DateTimeOffset fallbackScannedAt)
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

        // Sort for stable output: findings read in file order still want a defined
        // order downstream, so the same file always serialises the same way.
        findings.Sort((a, b) =>
        {
            var byHost = string.CompareOrdinal(a.Host, b.Host);
            return byHost != 0 ? byHost : a.PluginId.CompareTo(b.PluginId);
        });

        // One scan_run has one timestamp. Use the earliest host start — when the
        // scan began — and fall back to the caller's value if the file carries none.
        var scannedAt = startTimes.Count > 0 ? startTimes.Min() : fallbackScannedAt;

        return new ParsedScan(path, scannedAt, findings);
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
    /// Stores one already-parsed scan through the standard ingest path.
    /// </summary>
    /// <returns>The scan run created, and how many rows landed (zero on a replay).</returns>
    public static async Task<ImportResult> IngestAsync(
        NpgsqlConnection conn, ParsedScan scan, string source = DefaultSource)
    {
        var run = new ScanRun(
            ScanRunId: DeterministicRunId(source, scan.ScannedAt),
            ScannedAt: scan.ScannedAt,
            Source:    source);

        var landed = await Ingest.IngestAsync(conn, run, scan.Findings);
        return new ImportResult(run, landed);
    }

    /// <summary>Parses one file and stores it. Convenience wrapper.</summary>
    public static async Task<ImportResult> ImportFileAsync(
        NpgsqlConnection conn, string path, string source = DefaultSource,
        DateTimeOffset? fallbackScannedAt = null)
    {
        var scan = ParseFile(path, fallbackScannedAt ?? DateTimeOffset.UtcNow);
        return await IngestAsync(conn, scan, source);
    }

    /// <summary>
    /// A stable scan id derived from source + timestamp rather than a random GUID.
    /// Re-importing the same file produces the same id, so the whole load becomes
    /// a harmless replay instead of a second copy of the scan. See the idempotency
    /// check in Program.cs, which demonstrates exactly that.
    /// </summary>
    public static Guid DeterministicRunId(string source, DateTimeOffset at)
    {
        var bytes = System.Security.Cryptography.MD5.HashData(
            System.Text.Encoding.UTF8.GetBytes($"{source}|{at:O}"));
        return new Guid(bytes);
    }
}
