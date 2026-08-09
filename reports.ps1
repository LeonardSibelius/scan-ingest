<#
.SYNOPSIS
    A menu for running the reports in queries.sql one at a time.

.DESCRIPTION
    `dotnet run` prints all thirteen sections at once, which is no use when you
    are trying to understand one query. This reads queries.sql, lists what is in
    it, and runs whichever you pick — showing the SQL first, then its results.

    THE TEN REPORTS, AND WHERE THEY COME FROM

    The reports are not all in one place. They are split across three C# files by
    SUBJECT, and the menu falls into three blocks because queries.sql is ordered
    the same way:

         1.  TotalFactRowsAsync     Findings.cs   \
         2.  BySeverityAsync        Findings.cs    |  what the scanner SAW
         3.  TrendAsync             Findings.cs    |  how many, what changed,
         4.  DeltaAsync             Findings.cs    |  how long it has been broken
         5.  AgingAsync             Findings.cs   /

         6.  StatusAsync            Poam.cs       \  what people PROMISED
         7.  ByOwnerAsync           Poam.cs        |  who owns what,
         8.  WorstOverdueAsync      Poam.cs       /   who is late

         9.  CorrelateAsync         Controls.cs   \  where the scanner and the
        10.  UncoveredAsync         Controls.cs   /  paperwork DISAGREE

    Observations, commitments, contradictions. That is the whole program, and the
    menu numbers happen to be a map of it.

    Each report prints "from <file>" above its results, so you never have to
    remember which is which.

    WHERE THE SQL LIVES

    Not here, and not in the C# either. queries.sql is the single source: this
    script parses it at startup, and the program reads it through SqlLibrary.
    Editing that file changes both.

    The numbering follows the order of queries.sql. Reorder that file and these
    numbers move with it — the groupings above will still hold, the digits may not.

.EXAMPLE
    .\reports.ps1
    Opens the menu.

.EXAMPLE
    .\reports.ps1 -Report 9
    Runs the correlation — the one the whole project exists for — and exits.

.EXAMPLE
    .\reports.ps1 -List
    Prints the menu without entering it. Useful from a non-interactive shell.

.NOTES
    Assumes the scanprep database exists. If it does not, run `dotnet run` first.
#>

[CmdletBinding()]
param(
    # Run one report and exit, instead of showing the menu.
    [int] $Report = 0,

    # Print the list of reports and exit. Runs nothing.
    [switch] $List,

    # Database name.
    [string] $Database = 'scanprep',

    # Postgres user.
    [string] $User = 'postgres'
)

$ErrorActionPreference = 'Stop'

# --- Locate psql -------------------------------------------------------------
# The Windows installer does not put psql on PATH, so look for it. Highest
# version number wins, in case several are installed.
$psql = Get-Command psql -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
if (-not $psql) {
    $psql = Get-ChildItem 'C:\Program Files\PostgreSQL\*\bin\psql.exe' -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending |
            Select-Object -First 1 -ExpandProperty FullName
}
if (-not $psql) {
    Write-Host "Could not find psql.exe." -ForegroundColor Red
    Write-Host "Install PostgreSQL, or add its bin folder to your PATH." -ForegroundColor Red
    exit 1
}

# Password comes from the environment if set. This is a scratch database with a
# throwaway password; never do this for anything real.
if (-not $env:PGPASSWORD) { $env:PGPASSWORD = 'postgres' }

# --- Parse queries.sql -------------------------------------------------------
# Each report in that file looks like:
#
#     -- ===============================
#     -- Findings.cs -> BySeverityAsync
#     -- a description, one or more lines
#     -- ===============================
#     SELECT ... ;
#
# So: a rule line starts or ends a header block, a line matching `X.cs -> Method`
# identifies the report, and everything after the closing rule is its SQL until
# the next header begins.

$sqlPath = Join-Path $PSScriptRoot 'queries.sql'
if (-not (Test-Path $sqlPath)) {
    Write-Host "queries.sql not found next to this script." -ForegroundColor Red
    exit 1
}

$reports = @()
$current  = $null
$inHeader = $false

foreach ($line in Get-Content $sqlPath) {

    if ($line -match '^-- =+$') {
        if ($inHeader) {
            # Closing rule: the header is finished, SQL follows.
            $inHeader = $false
        }
        else {
            # Opening rule: bank whatever we were collecting, start a new block.
            if ($current -and $current.Method) { $reports += $current }
            $current  = [pscustomobject]@{
                Source      = ''
                Method      = ''
                Description = @()
                Sql         = @()
            }
            $inHeader = $true
        }
        continue
    }

    if (-not $current) { continue }

    if ($inHeader) {
        if ($line -match '^--\s+(\S+\.cs)\s+->\s+(\S+)\s*$') {
            $current.Source = $Matches[1]
            $current.Method = $Matches[2]
        }
        elseif ($line -match '^--\s?(.*)$' -and $Matches[1].Trim()) {
            $current.Description += $Matches[1].Trim()
        }
    }
    else {
        $current.Sql += $line
    }
}
if ($current -and $current.Method) { $reports += $current }

if ($reports.Count -eq 0) {
    Write-Host "No reports found in queries.sql." -ForegroundColor Red
    exit 1
}

# --- Run one report ----------------------------------------------------------
function Invoke-Report {
    param([Parameter(Mandatory)] $Item)

    $sql = ($Item.Sql -join "`n").Trim()

    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkGray
    Write-Host "  $($Item.Method)" -ForegroundColor Cyan
    Write-Host "  from $($Item.Source)" -ForegroundColor DarkGray
    Write-Host ('=' * 78) -ForegroundColor DarkGray
    foreach ($d in $Item.Description) { Write-Host "  $d" -ForegroundColor Gray }

    Write-Host ''
    Write-Host '--- the SQL ---' -ForegroundColor DarkYellow
    Write-Host $sql -ForegroundColor DarkYellow

    Write-Host ''
    Write-Host '--- the result ---' -ForegroundColor Green

    # Hand the SQL to psql on stdin rather than as an argument, so quoting and
    # newlines survive intact.
    $sql | & $psql -U $User -h localhost -d $Database
    Write-Host ''
}

# --- Print the menu ----------------------------------------------------------
# Everything here goes through Write-Host deliberately. Mixing Write-Host with
# bare pipeline output sends the two down different streams, and they then do not
# reliably interleave — the first version of this script printed its headings and
# silently dropped the list.
function Show-Menu {
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkGray
    Write-Host '  scan-ingest reports' -ForegroundColor White
    Write-Host "  database: $Database" -ForegroundColor DarkGray
    Write-Host ('=' * 78) -ForegroundColor DarkGray

    for ($i = 0; $i -lt $reports.Count; $i++) {
        $r    = $reports[$i]
        $desc = if ($r.Description.Count -gt 0) { $r.Description[0] } else { '' }
        Write-Host ('  {0,2}. {1,-22} {2}' -f ($i + 1), $r.Method, $desc)
    }

    Write-Host ''
    Write-Host '   A. run every report'
    Write-Host '   Q. quit'
    Write-Host ''
}

# --- Non-interactive modes ---------------------------------------------------
if ($List) {
    Show-Menu
    exit 0
}

if ($Report -gt 0) {
    if ($Report -gt $reports.Count) {
        Write-Host "There is no report $Report. There are $($reports.Count)." -ForegroundColor Red
        exit 1
    }
    Invoke-Report -Item $reports[$Report - 1]
    exit 0
}

# --- Menu loop ---------------------------------------------------------------
while ($true) {
    Show-Menu

    # Read-Host does not exist in a non-interactive host. Say so plainly rather
    # than throwing a stack trace at someone who piped input at this script.
    try   { $choice = Read-Host 'Choose' }
    catch {
        Write-Host ''
        Write-Host 'This menu needs an interactive terminal.' -ForegroundColor Yellow
        Write-Host 'Use  .\reports.ps1 -List        to see the reports' -ForegroundColor Yellow
        Write-Host 'or   .\reports.ps1 -Report 2    to run one directly.' -ForegroundColor Yellow
        exit 1
    }

    switch -Regex ($choice.Trim()) {
        '^[Qq]$'  { return }
        '^[Aa]$'  { foreach ($r in $reports) { Invoke-Report -Item $r } }
        '^\d+$'   {
            $n = [int]$choice
            if ($n -ge 1 -and $n -le $reports.Count) {
                Invoke-Report -Item $reports[$n - 1]
            }
            else {
                Write-Host "There is no report $n." -ForegroundColor Red
            }
        }
        default   { Write-Host 'Enter a number, A, or Q.' -ForegroundColor Red }
    }

    Write-Host 'Press Enter to return to the menu...' -ForegroundColor DarkGray
    [void](Read-Host)
}
