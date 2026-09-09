# Collect a real, local demo evidence bundle without changing the scanner.
# Read-only by default. Every deploy/prove/scan/validate/gate action requires -Yes
# and an explicit action switch. Cleanup is intentionally delegated to the
# existing targets/realworld/deploy.ps1 -Clean -Yes command.

[CmdletBinding()]
param(
    [switch]$Check,
    [switch]$Deploy,
    [switch]$Prove,
    [switch]$Scan,
    [switch]$Validate,
    [switch]$Gate,
    [switch]$RunAll,
    [switch]$Yes,
    [switch]$Resume,
    [ValidateSet('critical', 'high', 'medium', 'low', 'info')]
    [string]$FailOn = 'high',
    [string]$Out
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$ConfigPath = Join-Path $Root 'examples/demo_excel_017.yaml'
$DeployScript = Join-Path $Root 'targets/realworld/deploy.ps1'
Set-Location -LiteralPath $Root

$actions = @(
    [bool]$Deploy,
    [bool]$Prove,
    [bool]$Scan,
    [bool]$Validate,
    [bool]$Gate,
    [bool]$RunAll
) | Where-Object { $_ }
$actions = @($actions)

if (-not $Check -and $actions.Count -eq 0) {
    $Check = $true
}

if ($Check -and $actions.Count -gt 0) {
    throw 'Use -Check alone; it is read-only and cannot be combined with an action.'
}

if ($actions.Count -gt 0 -and -not $Yes) {
    throw 'State-changing/attack actions require explicit -Yes.'
}

if ($Resume -and -not $Out) {
    throw 'Use -Resume only with an explicit existing -Out directory.'
}

if ($Resume -and $actions.Count -eq 0) {
    throw 'Use -Resume with an explicit action switch.'
}

function Test-CommandPresent {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Get-PowerShellCommand {
    if (Test-CommandPresent 'pwsh') { return 'pwsh' }
    return 'powershell'
}

function Get-RunRoot {
    if ($Out) {
        if ([System.IO.Path]::IsPathRooted($Out)) {
            return [System.IO.Path]::GetFullPath($Out)
        }
        return [System.IO.Path]::GetFullPath((Join-Path $Root $Out))
    }
    $stamp = Get-Date -Format 'yyyyMMddTHHmmss'
    return Join-Path $Root "runs/demo_evidence/$stamp"
}

function Invoke-Logged {
    param(
        [string]$Name,
        [scriptblock]$Command,
        [string]$LogPath
    )
    $parent = Split-Path -Parent $LogPath
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    Write-Host "`n== $Name =="
    & $Command 2>&1 | Tee-Object -FilePath $LogPath
    $code = $LASTEXITCODE
    Write-Host "[$Name] exit_code=$code"
    $script:LastCommandExitCode = $code
}

function Get-McpwnInvocation {
    if (Test-CommandPresent 'python') {
        return 'python -m mcp_redteam.cli'
    }
    return $null
}

function Invoke-Mcpwn {
    param([string[]]$Arguments)
    & python -m mcp_redteam.cli @Arguments
}

function Test-ManagedContainersRunning {
    foreach ($name in @('excel-mcp-017', 'excel-mcp-018')) {
        $running = (& docker inspect --format '{{.State.Running}}' $name 2>$null).Trim()
        if ($LASTEXITCODE -ne 0 -or $running -ne 'true') {
            return $false
        }
    }
    return $true
}

function Get-ProofExitCode {
    param([string]$ReportPath, [int]$CommandExitCode)
    if ($CommandExitCode -ne 0 -or -not (Test-Path $ReportPath)) {
        return 1
    }
    if ((Get-Content -LiteralPath $ReportPath -Raw -Encoding UTF8) -notmatch '\*\*PASS\*\*') {
        return 1
    }
    return 0
}

function Test-ScanArtifactsWritten {
    param([string]$Version)
    $scanDir = Join-Path $RunRoot "scan/$Version"
    return (Test-Path (Join-Path $scanDir 'scan_result.json')) -and (Test-Path (Join-Path $scanDir 'findings.json'))
}

function Get-OverallExitCode {
    param([System.Collections.IDictionary]$ExitCodes)
    foreach ($name in @('deploy', 'prove_vulnerable', 'prove_fixed', 'validate_vulnerable', 'validate_fixed')) {
        if ($ExitCodes.Contains($name) -and [int]$ExitCodes[$name] -ne 0) {
            return 1
        }
    }
    foreach ($scan in @{ scan_vulnerable = 'excel-0.1.7'; scan_fixed = 'excel-0.1.8' }.GetEnumerator()) {
        if ($ExitCodes.Contains($scan.Key) -and [int]$ExitCodes[$scan.Key] -ne 0 -and -not (Test-ScanArtifactsWritten -Version $scan.Value)) {
            return 1
        }
    }
    foreach ($name in @('ci_vulnerable', 'ci_fixed')) {
        if ($ExitCodes.Contains($name) -and [int]$ExitCodes[$name] -in @(2, 3)) {
            return 1
        }
    }
    if ($ExitCodes.Contains('ci_fixed') -and [int]$ExitCodes['ci_fixed'] -eq 1) {
        return 1
    }
    return 0
}

function Get-GitSha {
    try {
        $sha = (& git -C $Root rev-parse HEAD 2>$null).Trim()
        if ($LASTEXITCODE -eq 0) { return $sha }
    } catch { }
    return ''
}

function Invoke-Preflight {
    $failures = @()
    Write-Host '== McPwn demo evidence preflight (read-only) =='

    if (Test-CommandPresent 'docker') {
        Write-Host '[PASS] docker CLI found'
    } else {
        Write-Host '[FAIL] docker CLI not found'
        $failures += 'docker'
    }

    if (Test-CommandPresent 'python') {
        Write-Host '[PASS] python found'
    } else {
        Write-Host '[FAIL] python not found'
        $failures += 'python'
    }

    $script:McpwnInvocation = Get-McpwnInvocation
    if ($script:McpwnInvocation) {
        & python -c 'import mcp_redteam' 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[PASS] McPwn CLI available via $script:McpwnInvocation (current checkout)"
        } else {
            Write-Host '[FAIL] python cannot import mcp_redteam from the current checkout'
            $failures += 'mcpwn'
        }
    } else {
        Write-Host '[FAIL] python is required for python -m mcp_redteam.cli'
        $failures += 'mcpwn'
    }

    if (Test-Path $ConfigPath) {
        Write-Host "[PASS] target config found: $ConfigPath"
    } else {
        Write-Host "[FAIL] target config missing: $ConfigPath"
        $failures += 'target-config'
    }

    foreach ($name in @('DEEPSEEK_API_KEY', 'ARK_API_KEY')) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if ($value) {
            Write-Host "[PASS] $name is set (value hidden)"
        } else {
            Write-Host "[WARN] $name is not set (value never printed)"
        }
    }

    if (Test-CommandPresent 'docker') {
        & (Get-PowerShellCommand) -NoProfile -ExecutionPolicy Bypass -File $DeployScript -Check
        if ($LASTEXITCODE -ne 0) {
            Write-Host '[WARN] deploy check returned a non-zero status'
        }
    }

    if ($failures.Count -gt 0) {
        Write-Host "Preflight incomplete: $($failures -join ', ')"
        $script:PreflightExitCode = 1
        return
    }
    $script:PreflightExitCode = 0
}

if ($Check) {
    Invoke-Preflight
    exit $script:PreflightExitCode
}

$script:McpwnInvocation = Get-McpwnInvocation
if (-not $script:McpwnInvocation) {
    throw 'McPwn CLI is unavailable; install the project or run from an environment with Python dependencies.'
}

$RunRoot = Get-RunRoot
$RunRootExists = Test-Path $RunRoot
if ($RunRootExists -and -not $Resume) {
    throw "Output directory already exists; choose a new -Out path or pass -Resume: $RunRoot"
}
if (-not $RunRootExists -and $Resume) {
    throw "Cannot resume a missing output directory: $RunRoot"
}
if (-not $RunRootExists) {
    New-Item -ItemType Directory -Force -Path $RunRoot | Out-Null
}
New-Item -ItemType Directory -Force -Path (Join-Path $RunRoot 'logs') | Out-Null

$manifestPath = Join-Path $RunRoot 'demo_manifest.json'
$priorManifest = $null
if ($Resume -and (Test-Path $manifestPath)) {
    $priorManifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
}

$results = [ordered]@{}
if ($priorManifest -and $priorManifest.exit_codes) {
    foreach ($property in $priorManifest.exit_codes.PSObject.Properties) {
        $results[$property.Name] = $property.Value
    }
}
$scanPaths = @{}

if ($Deploy -or $RunAll) {
    Invoke-Logged -Name 'deploy' -LogPath (Join-Path $RunRoot 'logs/deploy.log') -Command {
        & (Get-PowerShellCommand) -NoProfile -ExecutionPolicy Bypass -File $DeployScript -Yes
    }
    $results.deploy = $script:LastCommandExitCode
    if ($results.deploy -eq 0 -and -not (Test-ManagedContainersRunning)) {
        Write-Host '[deploy] containers are not both running after deploy'
        $results.deploy = 1
    }
}

if ($Prove -or $RunAll) {
    $proveDir = Join-Path $RunRoot 'prove'
    New-Item -ItemType Directory -Force -Path $proveDir | Out-Null
    Invoke-Logged -Name 'prove_vulnerable' -LogPath (Join-Path $RunRoot 'logs/prove_vulnerable.log') -Command {
        & python -m eval.realworld.prove excel-0.1.7 -o $proveDir
    }
    $results.prove_vulnerable = Get-ProofExitCode -ReportPath (Join-Path $proveDir 'excel-0.1.7/proof_report.md') -CommandExitCode $script:LastCommandExitCode
    Invoke-Logged -Name 'prove_fixed' -LogPath (Join-Path $RunRoot 'logs/prove_fixed.log') -Command {
        & python -m eval.realworld.prove excel-0.1.8 -o $proveDir
    }
    $results.prove_fixed = Get-ProofExitCode -ReportPath (Join-Path $proveDir 'excel-0.1.8/proof_report.md') -CommandExitCode $script:LastCommandExitCode
}

if ($Scan -or $RunAll) {
    $positive = Join-Path $RunRoot 'scan/excel-0.1.7'
    $fixed = Join-Path $RunRoot 'scan/excel-0.1.8'
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $positive) | Out-Null
    Invoke-Logged -Name 'scan_vulnerable' -LogPath (Join-Path $RunRoot 'logs/scan_vulnerable.log') -Command {
        Invoke-Mcpwn @('scan', '--target-config', $ConfigPath, '--out', $positive)
    }
    $results.scan_vulnerable = $script:LastCommandExitCode
    Invoke-Logged -Name 'scan_fixed' -LogPath (Join-Path $RunRoot 'logs/scan_fixed.log') -Command {
        Invoke-Mcpwn @('scan', 'http://127.0.0.1:9204/sse', '--sandbox-root', '/tmp/sandbox', '--out', $fixed)
    }
    $results.scan_fixed = $script:LastCommandExitCode
    $scanPaths.vulnerable = $positive
    $scanPaths.fixed = $fixed
}

if ($Validate -or $RunAll) {
    foreach ($key in @('vulnerable', 'fixed')) {
        if (-not $scanPaths.ContainsKey($key)) {
            $version = if ($key -eq 'vulnerable') { 'excel-0.1.7' } else { 'excel-0.1.8' }
            $scanPaths[$key] = Join-Path $RunRoot "scan/$version"
        }
        Invoke-Logged -Name "validate_$key" -LogPath (Join-Path $RunRoot "logs/validate_$key.log") -Command {
            Invoke-Mcpwn @('validate-artifact', $scanPaths[$key])
        }
        $results["validate_$key"] = $script:LastCommandExitCode
    }
}

if ($Gate -or $RunAll) {
    foreach ($key in @('vulnerable', 'fixed')) {
        if (-not $scanPaths.ContainsKey($key)) {
            $version = if ($key -eq 'vulnerable') { 'excel-0.1.7' } else { 'excel-0.1.8' }
            $scanPaths[$key] = Join-Path $RunRoot "scan/$version"
        }
        Invoke-Logged -Name "ci_$key" -LogPath (Join-Path $RunRoot "logs/ci_$key.log") -Command {
            Invoke-Mcpwn @('ci', $scanPaths[$key], '--fail-on', $FailOn)
        }
        $results["ci_$key"] = $script:LastCommandExitCode
    }
}

$artifactHashes = [ordered]@{}
foreach ($key in @('vulnerable', 'fixed')) {
    if ($scanPaths[$key]) {
        $artifact = Join-Path $scanPaths[$key] 'findings.json'
        if (Test-Path $artifact) {
            $relative = $artifact.Substring($RunRoot.Length).TrimStart('\', '/')
            $artifactHashes[$relative] = (Get-FileHash -Algorithm SHA256 -LiteralPath $artifact).Hash.ToLowerInvariant()
        }
    }
}

$scanMetadata = @{}
foreach ($key in @('vulnerable', 'fixed')) {
    if ($scanPaths[$key]) {
        $scanResultPath = Join-Path $scanPaths[$key] 'scan_result.json'
        if (Test-Path $scanResultPath) {
            $raw = Get-Content -LiteralPath $scanResultPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $scanMetadata[$key] = [ordered]@{
                target = $raw.sse_url
                transport = $raw.transport
                attacker_model = $raw.attacker_model
                attacker_temperature = $raw.attacker_temperature
                attacker_tokens = $raw.attacker_tokens
                judge_tokens = $raw.judge_tokens
                wall_seconds = $raw.wall_seconds
                stop_reason = $raw.stop_reason
            }
        }
    }
}

$manifest = [ordered]@{
    schema_version = 1
    git_sha = Get-GitSha
    created_at_utc = if ($priorManifest -and $priorManifest.created_at_utc) { $priorManifest.created_at_utc } else { (Get-Date).ToUniversalTime().ToString('o') }
    updated_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    target_pair = @(
        [ordered]@{ name = 'excel-0.1.7'; endpoint = 'http://127.0.0.1:9203/sse'; role = 'vulnerable' },
        [ordered]@{ name = 'excel-0.1.8'; endpoint = 'http://127.0.0.1:9204/sse'; role = 'fixed' }
    )
    commands = [ordered]@{
        deploy = 'targets/realworld/deploy.ps1 -Yes'
        prove_vulnerable = 'python -m eval.realworld.prove excel-0.1.7 -o <run>/prove'
        prove_fixed = 'python -m eval.realworld.prove excel-0.1.8 -o <run>/prove'
        scan_vulnerable = 'python -m mcp_redteam.cli scan --target-config examples/demo_excel_017.yaml --out <run>/scan/excel-0.1.7'
        scan_fixed = 'python -m mcp_redteam.cli scan http://127.0.0.1:9204/sse --sandbox-root /tmp/sandbox --out <run>/scan/excel-0.1.8'
        validate_vulnerable = 'python -m mcp_redteam.cli validate-artifact <run>/scan/excel-0.1.7'
        validate_fixed = 'python -m mcp_redteam.cli validate-artifact <run>/scan/excel-0.1.8'
        ci_vulnerable = "python -m mcp_redteam.cli ci <run>/scan/excel-0.1.7 --fail-on $FailOn"
        ci_fixed = "python -m mcp_redteam.cli ci <run>/scan/excel-0.1.8 --fail-on $FailOn"
    }
    exit_codes = $results
    artifact_sha256 = $artifactHashes
    scan_metadata = $scanMetadata
    secrets_included = $false
}

$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
Write-Host "`nWrote redacted manifest: $manifestPath"
Write-Host 'Review logs and artifacts manually before sharing.'
exit (Get-OverallExitCode -ExitCodes $results)
