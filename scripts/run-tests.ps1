<#
.SYNOPSIS
    Run Clean-Slate QEMU xtask acceptance tests and report failures.

.DESCRIPTION
    Sets OVMF_CODE / OVMF_VARS when they are not already in the environment,
    then runs one or more `cargo xtask` acceptance tests. By default the
    milestone gates run (test-m1, test-m2, test-m3, test-m4); the individual
    test-m3-* and test-m4-* boots are constituents of those aggregates and are skipped unless
    named explicitly or -Exhaustive is given. Pass test names (or short
    aliases) to target a subset.

.PARAMETER Test
    One or more tests to run. Accepts full xtask names or short aliases:
      m1, m2, m3 / m3.7 (aggregate),
      entry / m3.1, address-space / m3.2, syscall / m3.3,
      lifecycle / m3.4, ipc / m3.5, resources / m3.6,
      m5-storage / m5.3

.PARAMETER Exhaustive
    Run every known test (milestone gates plus each individual M3/M4
    constituent) instead of the default suite. Ignored when explicit test
    names are given.

.PARAMETER List
    Print the available tests and exit.

.PARAMETER OvmfCode
    Override the OVMF code firmware path.

.PARAMETER OvmfVars
    Override the OVMF vars firmware path.

.PARAMETER ReportPath
    Optional path for a text report. Defaults to target/xtask-test-report.txt.

.EXAMPLE
    .\scripts\run-tests.ps1

.EXAMPLE
    .\scripts\run-tests.ps1 m1

.EXAMPLE
    .\scripts\run-tests.ps1 -Test lifecycle, ipc

.EXAMPLE
    .\scripts\run-tests.ps1 m3

.EXAMPLE
    .\scripts\run-tests.ps1 -Exhaustive
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [Alias("Tests")]
    [string[]]$Test,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RemainingTests,

    [switch]$List,

    [switch]$Exhaustive,

    [string]$OvmfCode,

    [string]$OvmfVars,

    [string]$ReportPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $ReportPath) {
    $ReportPath = Join-Path $RepoRoot "target\xtask-test-report.txt"
}

$DefaultOvmfCode = "C:\Program Files\qemu\share\edk2-x86_64-code.fd"
$DefaultOvmfVars = "C:\Program Files\qemu\share\edk2-i386-vars.fd"

# Role controls suite membership:
#   Milestone   - runs in the default suite.
#   Aggregate   - runs in the default suite; orchestrates the Constituent entries.
#   Constituent - debugging workflow for one boundary; only runs when named
#                 explicitly or with -Exhaustive.
$AllTests = [ordered]@{
    "test-m1"               = @{ Aliases = @("m1"); Description = "M1 memory acceptance"; Role = "Milestone" }
    "test-m2"               = @{ Aliases = @("m2"); Description = "M2 interrupt/timer/scheduler acceptance"; Role = "Milestone" }
    "test-m3"               = @{ Aliases = @("m3", "m3.7"); Description = "M3 milestone gate (aggregate of all M3 acceptance boots)"; Role = "Aggregate" }
    "test-m3-entry"         = @{ Aliases = @("m3-entry", "entry", "m3.1"); Description = "M3.1 userspace-entry acceptance"; Role = "Constituent" }
    "test-m3-address-space" = @{ Aliases = @("m3-address-space", "address-space", "m3.2"); Description = "M3.2 address-space isolation acceptance"; Role = "Constituent" }
    "test-m3-syscall"       = @{ Aliases = @("m3-syscall", "syscall", "m3.3"); Description = "M3.3 native-syscall acceptance"; Role = "Constituent" }
    "test-m3-lifecycle"     = @{ Aliases = @("m3-lifecycle", "lifecycle", "m3.4"); Description = "M3.4 process/thread lifecycle acceptance"; Role = "Constituent" }
    "test-m3-ipc"           = @{ Aliases = @("m3-ipc", "ipc", "m3.5"); Description = "M3.5 capability-authorized IPC acceptance"; Role = "Constituent" }
    "test-m3-resources"     = @{ Aliases = @("m3-resources", "resources", "m3.6"); Description = "M3.6 domain resource accounting/teardown acceptance"; Role = "Constituent" }
    "test-m4-crash-service" = @{ Aliases = @("m4-crash-service", "crash-service", "m4.7"); Description = "M4.7 supervised crash-service fixture acceptance"; Role = "Constituent" }
    "test-m4-service-lifecycle" = @{ Aliases = @("m4-service-lifecycle", "service-lifecycle", "m4.2"); Description = "M4.2 kernel service lifecycle control acceptance"; Role = "Constituent" }
    "test-m4-restart-policy"    = @{ Aliases = @("m4-restart-policy", "restart-policy", "m4.6"); Description = "M4.6 supervisor restart-policy convergence (host + userspace image build)"; Role = "Constituent" }
    "test-m4-supervisor"        = @{ Aliases = @("m4-supervisor", "supervisor", "m4.3"); Description = "M4.3 userspace supervisor runtime QEMU integration acceptance"; Role = "Constituent" }
    "test-m4"                   = @{ Aliases = @("m4", "m4.8"); Description = "M4 milestone gate (recovery QEMU boot + M4.6 host policy tests)"; Role = "Aggregate" }
    "test-m4-recovery"          = @{ Aliases = @("m4-recovery", "recovery", "m4.8-qemu"); Description = "M4.8 authoritative recovery QEMU acceptance"; Role = "Constituent" }
    "test-m5-storage"           = @{ Aliases = @("m5-storage", "m5.3"); Description = "M5.3 userspace storage-service seam acceptance"; Role = "Constituent" }
}

function Get-DefaultSuite {
    return @($AllTests.Keys | Where-Object { $AllTests[$_].Role -ne "Constituent" })
}

function Show-TestList {
    Write-Host "Available tests:"
    foreach ($name in $AllTests.Keys) {
        $entry = $AllTests[$name]
        $aliases = ($entry.Aliases -join ", ")
        $tag = switch ($entry.Role) {
            "Aggregate"   { "[aggregate]  " }
            "Constituent" { "[constituent]" }
            default       { "[milestone]  " }
        }
        Write-Host ("  {0,-24} {1} {2}" -f $name, $tag, $entry.Description)
        Write-Host ("  {0,-24} {1} aliases: {2}" -f "", "", $aliases)
    }
    Write-Host ""
    Write-Host "Default suite:  $((Get-DefaultSuite) -join ', ')"
    Write-Host "-Exhaustive:    $(@($AllTests.Keys) -join ', ')"
    Write-Host "Constituents are the per-boundary debugging workflows behind the test-m3 aggregate."
}

function Resolve-TestName {
    param([string]$Requested)

    $normalized = $Requested.Trim().ToLowerInvariant()
    if ($AllTests.Contains($normalized)) {
        return $normalized
    }

    foreach ($name in $AllTests.Keys) {
        if ($AllTests[$name].Aliases -contains $normalized) {
            return $name
        }
    }

    $known = @($AllTests.Keys) + @($AllTests.Values | ForEach-Object { $_.Aliases }) | ForEach-Object { $_ }
    Write-Host "Unknown test '$Requested'." -ForegroundColor Red
    Write-Host "Known names: $($known -join ', ')"
    exit 1
}

function Set-OvmfEnvironment {
     $env:Path += ";C:\Program Files\qemu"
    if ($OvmfCode) {
        $env:OVMF_CODE = $OvmfCode
    }
    elseif (-not $env:OVMF_CODE) {
        $env:OVMF_CODE = $DefaultOvmfCode
    }

    if ($OvmfVars) {
        $env:OVMF_VARS = $OvmfVars
    }
    elseif (-not $env:OVMF_VARS) {
        $env:OVMF_VARS = $DefaultOvmfVars
    }

    if (-not (Test-Path -LiteralPath $env:OVMF_CODE)) {
        Write-Host "OVMF_CODE not found: $($env:OVMF_CODE)" -ForegroundColor Red
        Write-Host "Pass -OvmfCode or set `$env:OVMF_CODE."
        exit 1
    }
    if (-not (Test-Path -LiteralPath $env:OVMF_VARS)) {
        Write-Host "OVMF_VARS not found: $($env:OVMF_VARS)" -ForegroundColor Red
        Write-Host "Pass -OvmfVars or set `$env:OVMF_VARS."
        exit 1
    }
}

function Get-FailureDetails {
    param([string[]]$Lines)

    $patterns = @(
        "error:",
        "ERROR",
        "failed with status",
        "timed out",
        "missing required marker",
        "OVMF firmware not found",
        "unknown command",
        "FAIL"
    )

    $hits = New-Object System.Collections.Generic.List[string]
    foreach ($line in $Lines) {
        foreach ($pattern in $patterns) {
            if ($line -like "*${pattern}*") {
                $trimmed = $line.Trim()
                if ($trimmed -and -not $hits.Contains($trimmed)) {
                    $hits.Add($trimmed)
                }
                break
            }
        }
    }

    if ($hits.Count -gt 0) {
        return @($hits | Select-Object -Last 12)
    }

    $tail = @($Lines | Where-Object { $_.Trim() } | Select-Object -Last 15)
    if ($tail.Count -gt 0) {
        return $tail
    }

    return @("No captured output.")
}

function Format-Duration {
    param([TimeSpan]$Elapsed)

    $seconds = $Elapsed.Seconds + ($Elapsed.Milliseconds / 1000.0)
    if ($Elapsed.TotalMinutes -ge 1) {
        return "{0}m {1:N1}s" -f [int][Math]::Floor($Elapsed.TotalMinutes), $seconds
    }
    return "{0:N1}s" -f $Elapsed.TotalSeconds
}

function ConvertTo-OutputLine {
    param($Value)

    if ($Value -is [System.Management.Automation.ErrorRecord]) {
        return $Value.ToString()
    }
    return [string]$Value
}

function Invoke-XtaskTest {
    param(
        [string]$Name,
        [System.Collections.Generic.List[string]]$OutputLines
    )

    # Cargo writes progress to stderr. Windows PowerShell wraps those lines as
    # ErrorRecords, which become terminating errors when EAP is Stop. Route
    # through cmd so both streams stay ordinary text.
    $previousEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & cmd.exe /c "cargo xtask $Name 2>&1" | ForEach-Object {
            $line = ConvertTo-OutputLine $_
            [void]$OutputLines.Add($line)
            Write-Host $line
        }
        if ($null -eq $LASTEXITCODE) {
            return 1
        }
        return $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousEap
    }
}

if ($List) {
    Show-TestList
    exit 0
}

$requested = @()
if ($Test) {
    $requested += $Test
}
if ($RemainingTests) {
    $requested += $RemainingTests
}

$selected = @()
if ($requested.Count -gt 0) {
    foreach ($item in $requested) {
        $selected += Resolve-TestName $item
    }
    $selected = @($selected | Select-Object -Unique)
}
elseif ($Exhaustive) {
    $selected = @($AllTests.Keys)
}
else {
    $selected = Get-DefaultSuite
}

Set-OvmfEnvironment
Push-Location $RepoRoot
try {
    $results = New-Object System.Collections.Generic.List[object]
    $startedAt = Get-Date

    Write-Host ""
    Write-Host "Clean-Slate xtask suite" -ForegroundColor Cyan
    Write-Host "  repo     $RepoRoot"
    Write-Host "  OVMF_CODE  $($env:OVMF_CODE)"
    Write-Host "  OVMF_VARS  $($env:OVMF_VARS)"
    Write-Host "  tests    $($selected -join ', ')"
    Write-Host ""

    foreach ($name in $selected) {
        Write-Host ("======== {0} ========" -f $name) -ForegroundColor Cyan
        $outputLines = New-Object System.Collections.Generic.List[string]
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $exitCode = Invoke-XtaskTest -Name $name -OutputLines $outputLines
        $sw.Stop()

        $passed = ($exitCode -eq 0)
        $result = [pscustomobject]@{
            Name     = $name
            Passed   = $passed
            ExitCode = $exitCode
            Duration = $sw.Elapsed
            Errors   = if ($passed) { @() } else { Get-FailureDetails -Lines $outputLines.ToArray() }
        }
        $results.Add($result)

        if ($passed) {
            Write-Host ("PASS  {0}  ({1})" -f $name, (Format-Duration $sw.Elapsed)) -ForegroundColor Green
        }
        else {
            Write-Host ("FAIL  {0}  ({1}, exit {2})" -f $name, (Format-Duration $sw.Elapsed), $exitCode) -ForegroundColor Red
        }
        Write-Host ""
    }

    $passedCount = @($results | Where-Object { $_.Passed }).Count
    $failedCount = $results.Count - $passedCount
    $totalElapsed = (Get-Date) - $startedAt

    $report = New-Object System.Collections.Generic.List[string]
    $report.Add("Clean-Slate xtask test report")
    $report.Add("Started:  $($startedAt.ToString('yyyy-MM-dd HH:mm:ss'))")
    $report.Add("Finished: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))")
    $report.Add("Duration: $(Format-Duration $totalElapsed)")
    $report.Add("OVMF_CODE: $($env:OVMF_CODE)")
    $report.Add("OVMF_VARS: $($env:OVMF_VARS)")
    $report.Add("")

    foreach ($result in $results) {
        $status = if ($result.Passed) { "PASS" } else { "FAIL" }
        $report.Add(("{0}  {1,-24} {2}" -f $status, $result.Name, (Format-Duration $result.Duration)))
        if (-not $result.Passed) {
            $report.Add("  exit code: $($result.ExitCode)")
            foreach ($errorLine in $result.Errors) {
                $report.Add("  $errorLine")
            }
        }
    }

    $report.Add("")
    $report.Add(("{0} passed, {1} failed, {2} run" -f $passedCount, $failedCount, $results.Count))

    $reportDir = Split-Path -Parent $ReportPath
    if ($reportDir -and -not (Test-Path -LiteralPath $reportDir)) {
        New-Item -ItemType Directory -Path $reportDir | Out-Null
    }
    Set-Content -LiteralPath $ReportPath -Value $report -Encoding UTF8

    Write-Host "======== summary ========" -ForegroundColor Cyan
    foreach ($result in $results) {
        if ($result.Passed) {
            Write-Host ("PASS  {0,-24} {1}" -f $result.Name, (Format-Duration $result.Duration)) -ForegroundColor Green
        }
        else {
            Write-Host ("FAIL  {0,-24} {1}" -f $result.Name, (Format-Duration $result.Duration)) -ForegroundColor Red
            Write-Host ("      exit code: {0}" -f $result.ExitCode) -ForegroundColor Red
            foreach ($errorLine in $result.Errors) {
                Write-Host ("      {0}" -f $errorLine) -ForegroundColor Yellow
            }
        }
    }
    Write-Host ""
    $summaryColor = if ($failedCount -eq 0) { "Green" } else { "Red" }
    Write-Host ("{0} passed, {1} failed  ({2})" -f $passedCount, $failedCount, (Format-Duration $totalElapsed)) -ForegroundColor $summaryColor
    Write-Host "Report: $ReportPath"

    if ($failedCount -gt 0) {
        exit 1
    }
    exit 0
}
finally {
    Pop-Location
}
