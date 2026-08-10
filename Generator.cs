namespace ScanIngest;

// =============================================================================
// Generator.cs — stands in for the scanner.
//
// In a real deployment Tenable Nessus finds the problems. Here this class
// invents them, so the project runs on any machine with nothing to install and
// no scanner to license.
//
// WHAT IT PRODUCES
//
// One scan per call: a list of Finding records, each saying "machine X has
// problem Y, and it is this severe". Forty machines, drawn from the twenty
// checks in PluginCatalog. Program.cs calls it six times, for six weekly scans.
//
// WHAT MAKES IT MORE THAN RANDOM NUMBERS
//
// It remembers. The _open field holds the problems currently open and carries
// them from one scan into the next. Each new scan starts from the previous one,
// removes some findings (remediated) and adds some (newly discovered).
//
// That memory is what every report in this project runs on. A finding present in
// both weeks is "still open". One that disappears was "resolved". One that shows
// up is "new". Six independent random snapshots could not tell you which of those
// three things happened — and telling you which is the whole point of continuous
// monitoring.
//
// Remediation is weighted by severity — a critical is far likelier to be fixed
// between scans than an informational one — so serious problems clear quickly
// and the rest sit and age, which is what the aging report is measuring.
//
// The seed is fixed, so every run produces exactly the same numbers.
// =============================================================================

/// <summary>
/// Produces a sequence of scans that change realistically from week to week —
/// some problems fixed, some new ones appearing. Seeded, so the whole program
/// is reproducible — the same numbers appear in the README, in the commit
/// history, and on your screen.
/// </summary>
// C#: `sealed` = Java `final` on a class. Nobody can subclass this.
public sealed class Generator
{
    // Fixed seed. Reproducibility is worth more than variety here: it means the
    // documented output and the actual output can be compared.
    //
    // C#: `new(20260807)` with no type name — the type is already on the left,
    // C#: so C# infers it. Longhand is `new Random(20260807)`.
    private readonly Random _rng = new(20260807);

    // Forty machines: host-001.mil through host-040.mil.
    private readonly string[] _hosts = MakeHosts();

    /// <summary>
    /// Builds the forty host names, host-001.mil through host-040.mil.
    /// </summary>
    private static string[] MakeHosts()
    {
        var hosts = new string[40];

        for (var i = 0; i < 40; i++)
        {
            // i counts 0 to 39, but the names run 001 to 040, so add one.
            // ToString("D3") pads the number out to three digits: 7 becomes "007".
            hosts[i] = "host-" + (i + 1).ToString("D3") + ".mil";
        }

        return hosts;
    }

    // The catalogue of checks this scanner knows. PluginCatalog owns it, because
    // three things need it: this class, the plugin table in the database, and
    // plugin_control's foreign key into that table.
    //
    // Keeping it there rather than here also matches reality. A scanner's plugin
    // catalogue is a vendor feed that arrives on its own schedule, quite
    // separately from any scan results.
    //
    // C#: `(int Id, string Name, short Severity)` is a TUPLE type — an ad-hoc
    // C#: group of values with names, no class needed. Java has no equivalent;
    // C#: you would declare a record or a small class.
    // C#: Access the parts by name: `_plugins[3].Severity`.
    private readonly (int Id, string Name, short Severity)[] _plugins = PluginCatalog.All;

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
    //
    // C#: This works because C# tuples have VALUE equality built in — two tuples
    // C#: holding the same contents are equal, so the set can spot duplicates.
    // C#: In Java you would need a record, or equals()/hashCode() by hand.
    // C#: `= []` is just an empty set. Longhand: `new HashSet<...>()`.
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

            // C#: `foreach (var x in list)` is Java's `for (T x : list)`.
            // C#: `var` infers the type — here it is string.
            foreach (var host in _hosts)
            {
                // C#: Next(4, 12) gives 4..11. The upper bound is EXCLUSIVE.
                var target = _rng.Next(4, 12);
                var added  = 0;

                // C#: `(host, _rng.Next(...))` builds a two-part tuple.
                // C#: HashSet.Add returns true only if it actually inserted, so
                // C#: this counts real additions and ignores duplicate picks.
                while (added < target)
                    if (_open.Add((host, _rng.Next(_plugins.Length))))
                        added++;
            }
        }
        else
        {
            // ---- Remediation, weighted by severity ----
            //
            // Every open finding gets a chance of being fixed this week, and the
            // chance depends on how bad it is. Real remediation is triaged: a
            // critical gets someone paged, an informational finding sits for a
            // year because nobody is in a hurry and nobody should be.
            //
            // That weighting is what gives the aging report something to say.
            // Flatten these rates to one number and every severity comes back
            // averaging the same number of days open.
            //
            // The ones fixed this week are collected into a list first and
            // removed afterwards. Removing items from a collection while looping
            // over that same collection is not allowed.
            var resolved = new List<(string Host, int PluginIdx)>();

            foreach (var open in _open)
            {
                double chance;

                switch (_plugins[open.PluginIdx].Severity)
                {
                    case 4:  chance = 0.34; break;   // critical — someone is paged
                    case 3:  chance = 0.24; break;   // high
                    case 2:  chance = 0.13; break;   // medium
                    case 1:  chance = 0.07; break;   // low
                    default: chance = 0.04; break;   // informational — no hurry
                }

                // NextDouble() returns a number from 0.0 up to 1.0. Landing under
                // the threshold means this one got fixed.
                if (_rng.NextDouble() < chance)
                {
                    resolved.Add(open);
                }
            }

            foreach (var r in resolved)
            {
                _open.Remove(r);
            }

            // ---- New findings appear ----
            //
            // New machines get onboarded, and the scanner vendor ships new checks
            // that suddenly report on machines nobody touched.
            //
            // `added` counts what genuinely went IN, not how many attempts were
            // made. A random (host, plugin) pair that is already open is not a new
            // finding — it is a collision, and HashSet.Add returns false without
            // adding anything. Count attempts instead and collisions eat the
            // intake: fewer findings arrive than leave, and the estate drains away
            // week by week.
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
    public List<Finding> NextScanReplay()
    {
        return Materialise();
    }

    /// <summary>
    /// Turns the internal (host, pluginIndex) set into full Finding records by
    /// looking up plugin details, then sorts them.
    ///
    /// The sort is not cosmetic: a HashSet has no defined iteration order, so
    /// without it the same logical scan would serialise differently on different
    /// runs and the output would be needlessly unstable to diff.
    /// </summary>
    private List<Finding> Materialise()
    {
        var findings = new List<Finding>();

        foreach (var open in _open)
        {
            var plugin = _plugins[open.PluginIdx];

            // TryGetValue is the lookup that does not throw. When the key is not
            // there it returns false and leaves cve set to null, which is exactly
            // what is wanted — most findings have no CVE.
            string? cve;
            _cves.TryGetValue(plugin.Id.ToString(), out cve);

            findings.Add(
                new Finding(open.Host, plugin.Id, plugin.Name, plugin.Severity, cve));
        }

        findings.Sort(CompareFindings);
        return findings;
    }

    /// <summary>
    /// Orders findings by host, and within a host by plugin id.
    /// </summary>
    /// <returns>
    /// Negative if a comes first, positive if b does, zero if they tie — the
    /// ordinary comparison contract every sort routine expects.
    /// </returns>
    private static int CompareFindings(Finding a, Finding b)
    {
        int byHost = a.Host.CompareTo(b.Host);

        if (byHost != 0)
        {
            return byHost;
        }

        return a.PluginId.CompareTo(b.PluginId);
    }
}
