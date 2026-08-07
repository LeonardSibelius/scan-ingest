namespace ScanIngest;

/// <summary>
/// Produces a sequence of synthetic scans with realistic churn: most findings
/// persist between runs, some get remediated, some appear. That churn is the
/// whole point — a single snapshot tells you nothing, and the interesting
/// queries are all about what changed.
///
/// Seeded, so every run of this program produces the same data.
/// </summary>
public sealed class Generator
{
    private readonly Random _rng = new(20260807);

    private readonly string[] _hosts =
        Enumerable.Range(1, 40).Select(i => $"host-{i:D3}.mil").ToArray();

    private readonly (int Id, string Name, short Severity)[] _plugins =
    [
        (10107, "HTTP Server Type and Version",              0),
        (11219, "Nessus SYN scanner",                        0),
        (19506, "Nessus Scan Information",                   0),
        (25220, "TCP/IP Timestamps Supported",               1),
        (10863, "SSL Certificate Information",               1),
        (51192, "SSL Certificate Cannot Be Trusted",         2),
        (57582, "SSL Self-Signed Certificate",               2),
        (42873, "SSL Medium Strength Cipher Suites",         2),
        (26928, "SSL Weak Cipher Suites Supported",          3),
        (78479, "SSLv3 Padding Oracle (POODLE)",             3),
        (73412, "OpenSSL Heartbeat Information Disclosure",  4),
        (97833, "SMBv1 Remote Code Execution",               4),
        (35291, "SSL Certificate Signed With Weak Hash",     2),
        (90317, "SSH Weak Algorithms Supported",             2),
        (12085, "Apache Tomcat Default Files",               1),
        (11213, "HTTP TRACE / TRACK Methods Allowed",        2),
        (58751, "SSL/TLS Suboptimal Renegotiation",          1),
        (20007, "SSL Version 2 and 3 Protocol Detection",     3),
        (15901, "SSL Certificate Expiry",                    3),
        (45411, "SSL Certificate with Wrong Hostname",       2),
    ];

    private readonly Dictionary<string, string?> _cves = new()
    {
        [ "73412" ] = "CVE-2014-0160",
        [ "97833" ] = "CVE-2017-0143",
        [ "78479" ] = "CVE-2014-3566",
        [ "26928" ] = "CVE-2013-2566",
    };

    // Findings currently open, carried between runs as (host, pluginIndex).
    private HashSet<(string Host, int PluginIdx)> _open = [];

    /// <summary>First run seeds a population; later runs churn it.</summary>
    public List<Finding> NextScan(bool first)
    {
        if (first)
        {
            _open = [];
            foreach (var host in _hosts)
            {
                // Each host starts with 4-11 findings.
                var count = _rng.Next(4, 12);
                while (_open.Count(o => o.Host == host) < count)
                    _open.Add((host, _rng.Next(_plugins.Length)));
            }
        }
        else
        {
            // Remediation is severity-weighted: criticals get fixed fast, info
            // findings linger for months. That is what a working POA&M process
            // looks like from the data side, and it is what makes the aging
            // report say something instead of flat-lining at one number.
            var resolved = _open.Where(o =>
            {
                var chance = _plugins[o.PluginIdx].Severity switch
                {
                    4 => 0.34,   // critical — someone is paged
                    3 => 0.24,   // high
                    2 => 0.13,   // medium
                    1 => 0.07,   // low
                    _ => 0.04    // informational — nobody is in a hurry
                };
                return _rng.NextDouble() < chance;
            }).ToList();

            foreach (var r in resolved) _open.Remove(r);

            // New findings appear: new hosts onboarded, new plugin feeds shipped.
            // Count the ones that are genuinely new — a random (host, plugin) pair
            // that is already open is not a new finding, it is a collision.
            var target = _rng.Next(30, 49);
            int added = 0, guard = 0;
            while (added < target && guard++ < 2000)
            {
                var candidate = (_hosts[_rng.Next(_hosts.Length)], _rng.Next(_plugins.Length));
                if (_open.Add(candidate)) added++;
            }
        }

        return Materialise();
    }

    /// <summary>
    /// Returns the current open set again, unchanged — the same findings the last
    /// call to <see cref="NextScan"/> produced. Used to prove that re-ingesting an
    /// identical scan does not create duplicate fact rows.
    /// </summary>
    public List<Finding> NextScanReplay() => Materialise();

    private List<Finding> Materialise() =>
        _open
            .Select(o =>
            {
                var p = _plugins[o.PluginIdx];
                _cves.TryGetValue(p.Id.ToString(), out var cve);
                return new Finding(o.Host, p.Id, p.Name, p.Severity, cve);
            })
            .OrderBy(f => f.Host).ThenBy(f => f.PluginId)
            .ToList();
}
