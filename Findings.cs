using Dapper;
using Npgsql;

namespace ScanIngest;

// =============================================================================
// Findings.cs holds five of the project's ten reports.
// The other five live in Poam.cs and Controls.cs.
//
// Files in this project are named by SUBJECT — Poam, Controls, Ingest,
// Schema, Generator, PluginCatalog — and each owns that subject end to end.
// Poam.cs both writes commitments and reads them back. This file is the odd one
// out only because findings are written elsewhere, by Ingest.cs.
//
// The SQL lives in queries.sql, and
// what remains is everything that is NOT SQL — which turns out to be the actual
// job of this file:
//
//   1. WHAT SHAPE does each row become?   `QueryAsync<SeverityRow>` says a row
//      of that result becomes a SeverityRow object, with typed properties the
//      rest of the program can use. psql prints a table to a screen and stops.
//      This hands back objects.
//
//   2. WHAT IS EACH REPORT CALLED, in C#?  `BySeverityAsync` is a method
//      Program.cs can call. The alternative is every caller knowing the name of
//      a SQL file and the shape of what comes back.
//
//   3. WHEN does it run, and against what?  Each takes a connection, and each is
//      awaitable, so the program can sequence them.
//
// That is the difference between `psql -f queries.sql` and this file. psql SHOWS
// you the data. This DELIVERS the data to a program — typed, named, awaitable.
// The SQL was never the point of this file; it was just the largest thing in it.
//
// Dapper is what makes point 1 work: you give it SQL and a type, it gives you
// instances of that type. It matches result columns to constructor parameters by
// name, ignoring case and underscores.
// =============================================================================

public static class Findings
{
    /// <summary>
    /// Open findings grouped by severity, for the most recent scan only.
    /// </summary>
    /// <returns>One <see cref="SeverityRow"/> per severity present, worst first.</returns>
    public static async Task<IEnumerable<SeverityRow>> BySeverityAsync(NpgsqlConnection conn) =>
        await conn.QueryAsync<SeverityRow>(SqlLibrary.Get("BySeverityAsync"));

    /// <summary>
    /// Classifies findings across the two most recent scans as new, resolved, or
    /// still open — the core continuous-monitoring question, since a snapshot
    /// gives you the size of the problem but only a delta shows progress.
    /// </summary>
    public static async Task<IEnumerable<DeltaRow>> DeltaAsync(NpgsqlConnection conn) =>
        await conn.QueryAsync<DeltaRow>(SqlLibrary.Get("DeltaAsync"));

    /// <summary>
    /// How long currently-open findings have been open, averaged per severity.
    /// Measured from first observation, so it reports on the estate rather than
    /// on when the pipeline happened to load a row.
    /// </summary>
    public static async Task<IEnumerable<AgingRow>> AgingAsync(NpgsqlConnection conn) =>
        await conn.QueryAsync<AgingRow>(SqlLibrary.Get("AgingAsync"));

    /// <summary>
    /// High-and-critical count per scan with the run-over-run change. The first
    /// row's delta is null and stays null — there is no earlier scan, and "no
    /// change recorded" is a different statement from "change of zero".
    /// </summary>
    public static async Task<IEnumerable<TrendRow>> TrendAsync(NpgsqlConnection conn) =>
        await conn.QueryAsync<TrendRow>(SqlLibrary.Get("TrendAsync"));

    /// <summary>
    /// Total rows in the fact table, across every scan. Used by the idempotency
    /// check: take it before a re-ingest, take it after, assert nothing moved.
    /// </summary>
    /// <remarks>
    /// ExecuteScalarAsync rather than QueryAsync — one value, not a row. There is
    /// no record type because there is nothing to shape.
    /// </remarks>
    public static async Task<long> TotalFactRowsAsync(NpgsqlConnection conn) =>
        await conn.ExecuteScalarAsync<long>(SqlLibrary.Get("TotalFactRowsAsync"));
}
