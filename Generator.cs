namespace ScanIngest;

// =============================================================================
// Generator.cs — synthetic scan data.
//
// This file exists because the interesting queries in this project are all about
// CHANGE, and change needs history. A single snapshot of "here are 300 problems"
// supports no useful question. Six weeks of scans where findings persist, get
// fixed, and come back supports every question in Reports.cs and Poam.cs.
//
// The generator is therefore not a stub. Getting the churn model wrong makes the
// reports lie, and it did on the first attempt: with a flat remediation rate the
// aging report showed every severity averaging the same number of days, which is
// not what any real remediation programme looks like.
// =============================================================================

/// <summary>
/// Produces a sequence of scans with realistic churn. Seeded, so the whole
/// program is reproducible — the same numbers appear in the README, in the
/// commit history, and on your screen.
/// </summary>
public sealed class Generator
{
    // Fixed seed. Reproducibility is worth more than variety here: it means the
    // documented output and the actual output can be compared.
    private readonly Random _rng = new(20260807);

    // Forty machines. `$"host-{i:D3}.mil"` is string interpolation with a format
    // specifier — D3 zero-pads to three digits, giving host-001 through host-040.
    private readonly string[] _hosts =
        Enumerable.Range(1, 40).Select(i => $"host-{i:D3}.mil").ToArray();

    // The plugin catalogue: real Nessus plugin ids, names, and severities. A
    // plugin is one specific check, and its id is stable forever, which is what
    // makes a finding trackable across scans.
    //
    // C# note: `[ ... ]` is a collection expression (C# 12) — shorthand for
    // `new (int, string, short)[] { ... }`. The elements are value tuples with
    // named members, so `_plugins[i].Severity` works without declaring a type.
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
        (20007, "SSL Version 2 and 3 Protocol Detection",    3),
        (15901, "SSL Certificate Expiry",                    3),
        (45411, "SSL Certificate with Wrong Hostname",       2),
    ];

    // Public vulnerability identifiers, for the few findings that have one. Most
    // do not: a weak cipher suite is a configuration weakness, not a named CVE.
    private readonly Dictionary<string, string?> _cves = new()
    {
        [ "73412" ] = "CVE-2014-0160",   // Heartbleed
        [ "97833" ] = "CVE-2017-0143",   // EternalBlue
        [ "78479" ] = "CVE-2014-3566",   // POODLE
        [ "26928" ] = "CVE-2013-2566",   // RC4 weakness
    };

    // THE STATE THAT MAKES THIS WORK. The set of problems currently open, carried
    // from one scan to the next. Without it every scan would be independent, no
    // finding would persist, and nothing could be said to have been "resolved".
    //
    // A HashSet of (host, pluginIndex) gives free deduplication — the same
    // problem cannot be open twice on the same machine, which is exactly the
    // real-world constraint.
    private HashSet<(string Host, int PluginIdx)> _open = [];

    /// <summary>
    /// Produces the next scan. The first call seeds an initial population; every
    /// call after that ages the existing one — some findings remediated, some new
    /// ones appearing — and returns whatever is still open.
    /// </summary>
    /// <param name="first">
    /// True only for the very first scan. Seeds rather than churns.
    /// </param>
    /// <returns>Every finding open as of this scan, sorted for stable output.</returns>
    public List<Finding> NextScan(bool first)
    {
        if (first)
        {
            // Seed: give each host between 4 and 11 distinct findings.
            //
            // Count what actually landed, not how many times we tried — a random
            // (host, plugin) pick that is already open is a collision, and
            // HashSet.Add returns false for it without adding anything. Counting
            // attempts would leave hosts short of their target.
            //
            // `added` is tracked rather than recounted. Asking the set "how many
            // entries does this host have" on every iteration walks the whole
            // collection each time, which turns a linear loop into a quadratic
            // one. Add already tells us whether it inserted; believe it.
            //
            // Terminates because the target (max 11) is always below the number of
            // plugins (20), so there is always another distinct pair available.
            // Raise that ceiling past _plugins.Length and this loop will hang.
            _open = [];
            foreach (var host in _hosts)
            {
                var target = _rng.Next(4, 12);
                var added  = 0;

                while (added < target)
                    if (_open.Add((host, _rng.Next(_plugins.Length))))
                        added++;
            }
        }
        else
        {
            // ---- Remediation, weighted by severity ----
            //
            // A flat rate here was the first version's mistake. Real remediation
            // is triaged: a critical gets someone paged this week, an
            // informational finding sits for a year because nobody is in a hurry
            // and nobody should be. Without that weighting the aging report
            // flat-lines at one number for every severity, which is both
            // uninformative and obviously wrong to anyone who has seen a real one.
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
            }).ToList();   // materialise before mutating — you cannot remove from
                           // a collection while a LINQ query over it is still lazy

            foreach (var r in resolved) _open.Remove(r);

            // ---- New findings appear ----
            //
            // New machines get onboarded, and the scanner vendor ships new checks
            // that suddenly report on machines nobody touched.
            //
            // The loop counts what was genuinely ADDED, not how many attempts were
            // made. A random (host, plugin) pair that is already open is not a new
            // finding — it is a collision, and HashSet.Add returns false for it.
            // The first version counted attempts, so the real intake was far lower
            // than intended and the whole estate shrank to nothing over six weeks.
            var target = _rng.Next(30, 49);
            int added = 0, guard = 0;
            while (added < target && guard++ < 2000)   // guard: the set can saturate
            {
                var candidate = (_hosts[_rng.Next(_hosts.Length)], _rng.Next(_plugins.Length));
                if (_open.Add(candidate)) added++;
            }
        }

        return Materialise();
    }

    /// <summary>
    /// Returns the current open set again, completely unchanged — the same
    /// findings the previous <see cref="NextScan"/> call produced.
    ///
    /// This exists solely to test idempotency: feed an identical scan back into
    /// the pipeline and assert that no new fact rows appear. It is deliberately
    /// separate from NextScan so that "replay the last scan" cannot accidentally
    /// advance the simulation.
    /// </summary>
    public List<Finding> NextScanReplay() => Materialise();

    /// <summary>
    /// Turns the internal (host, pluginIndex) set into full Finding records by
    /// looking up plugin details, then sorts them.
    ///
    /// The sort is not cosmetic: a HashSet has no defined iteration order, so
    /// without it the same logical scan would serialise differently on different
    /// runs and the output would be needlessly unstable to diff.
    /// </summary>
    private List<Finding> Materialise() =>
        _open
            .Select(o =>
            {
                var p = _plugins[o.PluginIdx];
                // TryGetValue is the no-exception lookup: returns false and leaves
                // `cve` null when the key is absent, which is the common case.
                // `out var cve` declares the variable inline at the call site.
                _cves.TryGetValue(p.Id.ToString(), out var cve);
                return new Finding(o.Host, p.Id, p.Name, p.Severity, cve);
            })
            .OrderBy(f => f.Host).ThenBy(f => f.PluginId)
            .ToList();
}
