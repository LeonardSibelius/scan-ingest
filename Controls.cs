using Dapper;
using Npgsql;

namespace ScanIngest;

/// <summary>
/// The second source, and the correlation between it and the first.
///
/// Nessus answers "what is broken on this host, right now."
/// eMASS answers "what did the assessor say about this system's controls."
///
/// Those two are produced by different people on different cadences, and they
/// drift apart. The gap between them is not noise to be cleaned up — it IS the
/// product. A control marked Compliant that has live scan evidence against it is
/// the single most valuable row this system can emit, because it means the
/// authorisation package is describing a system that no longer exists.
/// </summary>
public static class Controls
{
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
    public static async Task<IEnumerable<CorrelationRow>> CorrelateAsync(NpgsqlConnection conn) =>
        await conn.QueryAsync<CorrelationRow>(SqlLibrary.Get("CorrelateAsync"));

    /// <summary>
    /// Findings that map to no tracked control at all. This is an RMF coverage
    /// gap: the scanner is reporting something the authorisation package has no
    /// place to put. Either the mapping is incomplete or the package is.
    /// </summary>
    public static async Task<IEnumerable<UncoveredRow>> UncoveredAsync(NpgsqlConnection conn) =>
        await conn.QueryAsync<UncoveredRow>(SqlLibrary.Get("UncoveredAsync"));
}
