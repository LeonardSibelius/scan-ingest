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
    //
    // C#: Enumerable.Range(1,40) makes 1..40. `.Select(...)` is Java's `.map()`.
    // C#: `i => ...` is a lambda; Java writes `i -> ...`. One character apart.
    // C#: `$"...{i:D3}..."` is string interpolation — Java's String.format.
    // C#: The `:D3` part means "pad to 3 digits", so 7 becomes 007.
    private readonly string[] _hosts =
        Enumerable.Range(1, 40).Select(i => $"host-{i:D3}.mil").ToArray();

    // The catalogue of checks this scanner knows. It now lives in PluginCatalog
    // rather than here, because the generator is no longer its only consumer —
    // the database holds it as reference data, and plugin_control has a foreign
    // key pointing at it.
    //
    // That split matches reality: a scanner's plugin catalogue is a vendor feed
    // that arrives on its own schedule, quite separately from any scan results.
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
            // A flat rate here was the first version's mistake. Real remediation
            // is triaged: a critical gets someone paged this week, an
            // informational finding sits for a year because nobody is in a hurry
            // and nobody should be. Without that weighting the aging report
            // flat-lines at one number for every severity, which is both
            // uninformative and obviously wrong to anyone who has seen a real one.
            // C#: `.Where(...)` is Java's `.stream().filter(...)`.
            // C#: `o => { ...; return x; }` is a lambda with a body, for when one
            // C#: expression is not enough. `o` names each item as we visit it.
            var resolved = _open.Where(o =>
            {
                // C#: a switch EXPRESSION — produces a value. Arms use `=>`,
                // C#: are separated by commas, and `_` is the default case.
                // C#: No `case`, no `break`, no accidental fallthrough.
                var chance = _plugins[o.PluginIdx].Severity switch
                {
                    4 => 0.34,   // critical — someone is paged
                    3 => 0.24,   // high
                    2 => 0.13,   // medium
                    1 => 0.07,   // low
                    _ => 0.04    // informational — nobody is in a hurry
                };
                // C#: NextDouble() gives 0.0-1.0. Under the threshold = it happened.
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
    // C#: `=>` on a METHOD means "this method is one expression" — there is no
    // C#: body in braces and no `return` keyword. Java has no equivalent.
    private List<Finding> Materialise() =>
        _open
            // C#: `.Select(...)` is Java's `.map(...)` — transform each item.
            .Select(o =>
            {
                var p = _plugins[o.PluginIdx];
                // C#: TryGetValue is the lookup that does not throw: it returns
                // C#: false and leaves `cve` null when the key is missing.
                // C#: `out var cve` DECLARES the variable right there in the call.
                // C#: Java would need to declare it on a line above.
                _cves.TryGetValue(p.Id.ToString(), out var cve);
                return new Finding(o.Host, p.Id, p.Name, p.Severity, cve);
            })
            // C#: OrderBy/ThenBy = Java's Comparator.comparing().thenComparing().
            .OrderBy(f => f.Host).ThenBy(f => f.PluginId)
            // C#: `.ToList()` = Java's `.collect(toList())`. Runs the whole chain —
            // C#: nothing above this line actually executes until now.
            .ToList();
}
