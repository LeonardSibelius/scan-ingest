using Dapper;
using Npgsql;

namespace ScanIngest;

/// <summary>
/// The SECOND source of data, and the two reports that compare it against the
/// first. The first source is the scanner: Ingest.cs loads it into the finding
/// table, and reports 1 to 8 read that table and nothing else.
///
/// There are two ways to know whether a system is secure, and this project has
/// both of them.
///
///   THE MACHINE    A scanner looks at every host and reports what is broken on
///                  it today. That is Nessus, and Ingest.cs loads its output
///                  into the finding table.
///
///   THE PAPERWORK  A person assesses the system against a list of security
///                  REQUIREMENTS — accounts are managed, traffic is encrypted,
///                  flaws get patched — and records one verdict for each:
///                  Compliant or Non-Compliant. In the US federal world those
///                  requirements are called controls, they are numbered by NIST
///                  (AC-2, SC-8, SI-2), and the verdicts live in a system called
///                  eMASS. This class fakes that export.
///
/// The two are produced by different people at different times, so they drift
/// apart. That drift is not a mess to be tidied away. It is the product.
///
/// The row worth finding is a control a person marked COMPLIANT on a system the
/// scanner is right now reporting as broken. It means the paperwork describes a
/// system that no longer exists, and somebody senior is being told things are
/// fine when they are not.
///
/// Comparing the two requires one more thing: something has to say which scanner
/// check counts as evidence for which requirement. That is the Evidence table
/// immediately below, and it is the join that makes the whole comparison possible.
/// </summary>
public static class Controls
{
    // The control catalogue — the list of security requirements a system is
    // assessed against. This is REFERENCE data, not accumulating data: unlike
    // finding and poam, which grow with every scan, this is a short fixed list
    // that the other tables point at. It is meant to be small.
    //
    // Real NIST SP 800-53 has on the order of a thousand controls. This hand-
    // picks ten, and the choice is deliberate: five of them a scanner CAN see
    // (CM-6, CM-7, SC-8, SC-13, SC-17 — configuration and crypto, which a plugin
    // can test), and four it CANNOT (AC-2, AU-6, IA-5, SI-4 — procedural
    // controls, where the evidence is a person's judgement, not a scan). The mix
    // is what gives the correlation report both a "CONTRADICTED" case and a "not
    // assessable" case to find. Which plugin evidences which control is the
    // Evidence table just below.
    private static readonly (string Id, string Title, string Family)[] Catalog =
    [
        ("AC-2",  "Account Management",                          "AC"),
        ("AU-6",  "Audit Review, Analysis, and Reporting",        "AU"),
        ("CM-6",  "Configuration Settings",                       "CM"),
        ("CM-7",  "Least Functionality",                          "CM"),
        ("IA-5",  "Authenticator Management",                     "IA"),
        ("SC-8",  "Transmission Confidentiality and Integrity",   "SC"),
        ("SC-13", "Cryptographic Protection",                     "SC"),
        ("SC-17", "Public Key Infrastructure Certificates",       "SC"),
        ("SI-2",  "Flaw Remediation",                             "SI"),
        ("SI-4",  "Information System Monitoring",                "SI"),
    ];

    /// Plugin-to-control evidence mapping. Deliberately incomplete: plugins
    /// 11219 and 19506 are scanner artefacts that map to nothing, and AC-2 /
    /// AU-6 / IA-5 / SI-4 are procedural controls no scanner can speak to.
    /// Both gaps are real and both show up in the reports.
    private static readonly (int Plugin, string Control)[] Evidence =
    [
        (10107, "CM-6"),
        (25220, "CM-6"),
        (12085, "CM-7"),
        (11213, "CM-7"),
        (97833, "CM-7"),
        (10863, "SC-17"),
        (51192, "SC-17"),
        (57582, "SC-17"),
        (35291, "SC-17"),
        (15901, "SC-17"),
        (45411, "SC-17"),
        (42873, "SC-13"),
        (26928, "SC-13"),
        (35291, "SC-13"),
        (90317, "SC-13"),
        (20007, "SC-13"),
        (42873, "SC-8"),
        (26928, "SC-8"),
        (78479, "SC-8"),
        (73412, "SC-8"),
        (58751, "SC-8"),
        (20007, "SC-8"),
        (73412, "SI-2"),
        (97833, "SI-2"),
        (78479, "SI-2"),
    ];

    /// <summary>
    /// Loads the control catalogue and the plugin→control evidence map into the
    /// database. Idempotent, so it runs on every startup without checking.
    ///
    /// The evidence map is the join key for this whole file. Without it the two
    /// sources have nothing in common — the scanner talks about hosts and plugins,
    /// the compliance record talks about controls, and nothing connects them. In
    /// a real system this mapping is a maintained asset with an owner, because it
    /// determines what the correlation can and cannot see.
    /// </summary>
    public static async Task SeedCatalogAsync(NpgsqlConnection conn)
    {
        // C# note: `foreach (var (id, title, family) in Catalog)` deconstructs
        // each tuple into named locals in the loop header. Dapper then binds them
        // by name from the anonymous object `new { id, title, family }`.
        foreach (var (id, title, family) in Catalog)
            await conn.ExecuteAsync("""
                INSERT INTO control (control_id, title, family)
                VALUES (@id, @title, @family)
                ON CONFLICT (control_id) DO NOTHING
                """, new { id, title, family });

        foreach (var (plugin, control) in Evidence)
            await conn.ExecuteAsync("""
                INSERT INTO plugin_control (plugin_id, control_id)
                VALUES (@plugin, @control)
                ON CONFLICT DO NOTHING
                """, new { plugin, control });
    }

    /// <summary>
    /// Produces the eMASS export as it would have been written at assessment
    /// time — which is the date of the FIRST scan, five weeks before the latest.
    ///
    /// The assessor marks a control Non-Compliant only where they saw high or
    /// critical evidence. That is not laziness, it is how triage works: nobody
    /// fails a control over an informational finding. But it means medium and low
    /// evidence never reaches the compliance record at all, and continuous
    /// monitoring keeps seeing it. That asymmetry is where contradictions come from,
    /// and it is why this file does not hand-plant any.
    /// </summary>
    /// <param name="exportId">
    /// Fixed by the caller rather than generated, so re-running the program does
    /// not accumulate near-identical exports — the same replay-safety reasoning
    /// as the scan run ids.
    /// </param>
    /// <returns>
    /// How many control statuses the export CONTAINS — deliberately not how many
    /// rows this call inserted. Those differ: the insert is idempotent, so a
    /// second run against the same database inserts nothing and would report
    /// zero, which reads as a failure when the export is in fact complete. Report
    /// the state, not the delta.
    /// </returns>
    public static async Task<int> GenerateExportAsync(NpgsqlConnection conn, Guid exportId)
    {
        await conn.ExecuteAsync("""
            -- The assessment is dated to the FIRST scan, not the latest. That is
            -- the entire mechanism: the compliance record is a photograph, the
            -- scanner is a video, and by the time anyone reads them together the
            -- photograph is five weeks old.
            WITH earliest AS (
                SELECT scan_run_id, scanned_at
                FROM scan_run ORDER BY scanned_at ASC LIMIT 1
            ),
            -- Controls the assessor would have failed: those with high or
            -- critical evidence at assessment time. severity >= 3 is the triage
            -- line, and it is why medium and low findings never make it into the
            -- compliance record even though the scanner keeps reporting them.
            serious_evidence AS (
                SELECT DISTINCT pc.control_id
                FROM finding f
                JOIN earliest e     ON e.scan_run_id = f.scan_run_id
                JOIN plugin_control pc ON pc.plugin_id = f.plugin_id
                WHERE f.severity >= 3
            )
            INSERT INTO control_status
                (export_id, exported_at, control_id, compliance, assessed_by)
            SELECT @exportId,
                   (SELECT scanned_at FROM earliest),
                   c.control_id,
                   CASE WHEN se.control_id IS NOT NULL
                        THEN 'Non-Compliant' ELSE 'Compliant' END,
                   'SCA-Team-1'
            FROM control c
            LEFT JOIN serious_evidence se ON se.control_id = c.control_id
            -- Conflict target matches the primary key: an export is identified by
            -- its id, not its date. Re-running this is a no-op; a genuinely
            -- different export on the same date would still be accepted.
            ON CONFLICT (export_id, control_id) DO NOTHING
            """, new { exportId });

        // Report what the export holds, not what this call happened to add.
        return await conn.ExecuteScalarAsync<int>(
            "SELECT count(*)::int FROM control_status WHERE export_id = @exportId",
            new { exportId });
    }

    /// <summary>
    /// The correlation. Five outcomes, and only one of them is boring.
    ///
    ///   CONTRADICTED   — marked Compliant, scanner disagrees. Escalate.
    ///   not assessable — NO plugin maps to this control. The scanner cannot speak
    ///                    to it either way. Critically, this is NOT the same as
    ///                    clean: reporting an unscannable control as verified is
    ///                    how a dashboard lies to an Authorizing Official.
    ///   corroborated   — marked Non-Compliant, scanner agrees. Working as intended.
    ///   unevidenced    — marked Non-Compliant, evidence sources exist, nothing found.
    ///                    Either remediated and the paperwork is stale, or the
    ///                    finding was never technical.
    ///   verified clean — Compliant, evidence sources exist, they found nothing.
    ///                    The only row you can actually ignore.
    /// </summary>
    public static async Task<IEnumerable<CorrelationRow>> CorrelateAsync(NpgsqlConnection conn)
    {
        return await conn.QueryAsync<CorrelationRow>(SqlLibrary.Get("CorrelateAsync"));
    }

    /// <summary>
    /// Findings that map to no tracked control at all. This is an RMF coverage
    /// gap: the scanner is reporting something the authorisation package has no
    /// place to put. Either the mapping is incomplete or the package is.
    /// </summary>
    public static async Task<IEnumerable<UncoveredRow>> UncoveredAsync(NpgsqlConnection conn)
    {
        return await conn.QueryAsync<UncoveredRow>(SqlLibrary.Get("UncoveredAsync"));
    }
}
