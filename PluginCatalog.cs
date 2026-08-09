using Dapper;
using Npgsql;

namespace ScanIngest;

// =============================================================================
// PluginCatalog.cs — the list of checks the scanner knows how to run.
//
// A plugin is one specific question: "is SMBv1 enabled on this machine?" Its id
// is stable forever, which is the only reason a finding can be tracked from one
// scan to the next.
//
// In a real deployment this is a feed from Tenable, arriving on its own schedule
// and quite separately from any scan results. It lives here rather than inside
// the generator because two different things need it: the fake scanner needs it
// to invent findings, and the database needs it as reference data so the
// plugin→control mapping has something valid to point at.
// =============================================================================

public static class PluginCatalog
{
    /// <summary>
    /// The twenty checks this project knows about. Real Nessus plugin ids and
    /// names; the severity is the vendor's default rating.
    /// </summary>
    /// <remarks>
    /// C#: `static readonly` — one shared copy, assigned once, never reassigned.
    /// C#: Roughly Java's `static final`.
    /// C#: `(int Id, string Name, short Severity)[]` is an array of named tuples,
    /// C#: so elements are reached as `.Id` rather than `.Item1`.
    /// </remarks>
    public static readonly (int Id, string Name, short Severity)[] All =
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

    /// <summary>
    /// Loads the catalogue into the database. Must run before anything seeds
    /// <c>plugin_control</c>, which now has a foreign key pointing here.
    /// </summary>
    /// <remarks>
    /// Uses DO UPDATE rather than DO NOTHING. Vendors do revise a plugin's name
    /// and re-rate its severity, and when they do we want the newer wording — a
    /// catalogue that silently keeps the first version it ever saw would drift out
    /// of step with the findings arriving against it.
    /// </remarks>
    public static async Task<int> SeedAsync(NpgsqlConnection conn)
    {
        // C#: `foreach (var (id, name, severity) in All)` DECONSTRUCTS each tuple
        // C#: into three named locals in the loop header. Java has no equivalent.
        foreach (var (id, name, severity) in All)
            await conn.ExecuteAsync("""
                INSERT INTO plugin (plugin_id, name, severity)
                VALUES (@id, @name, @severity)
                ON CONFLICT (plugin_id) DO UPDATE
                    SET name     = EXCLUDED.name,
                        severity = EXCLUDED.severity
                """, new { id, name, severity });

        // Report what the catalogue holds, not what this call inserted — the
        // insert is idempotent, so a second run would otherwise report zero.
        return await conn.ExecuteScalarAsync<int>("SELECT count(*)::int FROM plugin");
    }
}
