[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$tempBase = if ($env:VALIDATION_TEMP_BASE) {
    [System.IO.Path]::GetFullPath($env:VALIDATION_TEMP_BASE)
}
else {
    [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
}
if (-not (Test-Path -LiteralPath $tempBase -PathType Container)) {
    throw 'validation temporary base directory does not exist'
}
$tempRoot = Join-Path $tempBase ('secrets-flexvolume-plugin-validation-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot | Out-Null

function Invoke-Checked {
    param(
        [Parameter(Mandatory)][string]$Command,
        [Parameter(Mandatory)][string[]]$Arguments
    )
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Command failed with exit code $LASTEXITCODE"
    }
}

function Build-Target {
    param(
        [Parameter(Mandatory)][string]$GoOS,
        [Parameter(Mandatory)][string]$GoArch,
        [Parameter(Mandatory)][string]$Output
    )
    $savedGoOS = $env:GOOS
    $savedGoArch = $env:GOARCH
    $savedCGO = $env:CGO_ENABLED
    try {
        $env:GOOS = $GoOS
        $env:GOARCH = $GoArch
        $env:CGO_ENABLED = '0'
        Invoke-Checked go @(
            'build', '-mod=mod', '-trimpath', '-buildvcs=false', '-ldflags=-s -w',
            '-o', $Output, './cmd/secrets-flexvolume-plugin'
        )
    }
    finally {
        $env:GOOS = $savedGoOS
        $env:GOARCH = $savedGoArch
        $env:CGO_ENABLED = $savedCGO
    }
}

Push-Location $repoRoot
try {
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) { throw 'go is required' }
    if (-not (Get-Command gofmt -ErrorAction SilentlyContinue)) { throw 'gofmt is required' }

    $env:GOTOOLCHAIN = 'local'
    $env:GOWORK = 'off'
    $env:GOPROXY = 'off'
    $env:GOSUMDB = 'off'
    $env:GOCACHE = Join-Path $tempRoot 'go-build'
    $env:GOMODCACHE = Join-Path $tempRoot 'go-mod'

    $unformatted = @(& gofmt -l cmd internal)
    if ($LASTEXITCODE -ne 0 -or $unformatted.Count -ne 0) {
        throw "gofmt check failed: $($unformatted -join ', ')"
    }

    Invoke-Checked go @('test', '-mod=mod', '-count=3', './...')
    Invoke-Checked go @('test', '-mod=mod', '-tags=publictree', '-count=1', './internal/safety')
    Invoke-Checked go @('vet', '-mod=mod', './...')
    Invoke-Checked go @('mod', 'verify')

    $modules = @(& go list -mod=mod -m all)
    if ($LASTEXITCODE -ne 0 -or $modules.Count -ne 1 -or $modules[0] -ne 'github.com/PastureStack/secrets-flexvolume-plugin') {
        throw 'module dependency gate failed'
    }

    $cgoEnabled = (& go env CGO_ENABLED).Trim()
    if ($LASTEXITCODE -eq 0 -and $cgoEnabled -eq '1' -and (Get-Command gcc -ErrorAction SilentlyContinue)) {
        Invoke-Checked go @('test', '-mod=mod', '-race', '-count=1', './...')
    }
    else {
        Write-Host 'SKIP race test: CGO or gcc is unavailable.'
    }

    $hostGoOS = (& go env GOOS).Trim()
    $hostGoArch = (& go env GOARCH).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'unable to determine host target' }
    $hostExtension = if ($hostGoOS -eq 'windows') { '.exe' } else { '' }
    $hostA = Join-Path $tempRoot ("host-a$hostExtension")
    $hostB = Join-Path $tempRoot ("host-b$hostExtension")
    $windowsBinary = Join-Path $tempRoot 'secrets-flexvolume-plugin-windows-amd64.exe'
    $linuxBinary = Join-Path $tempRoot 'secrets-flexvolume-plugin-linux-amd64'

    Build-Target $hostGoOS $hostGoArch $hostA
    Build-Target $hostGoOS $hostGoArch $hostB
    Build-Target 'windows' 'amd64' $windowsBinary
    Build-Target 'linux' 'amd64' $linuxBinary

    $hostHashA = (Get-FileHash -LiteralPath $hostA -Algorithm SHA256).Hash
    $hostHashB = (Get-FileHash -LiteralPath $hostB -Algorithm SHA256).Hash
    if ($hostHashA -ne $hostHashB) { throw 'same-platform reproducibility gate failed' }

    foreach ($binary in @($windowsBinary, $linuxBinary)) {
        $env:SECRETS_FLEXVOLUME_PLUGIN_BINARY = $binary
        Invoke-Checked go @('test', '-mod=mod', '-count=1', '-run', '^TestExternalBinaryGate$', './internal/safety')
    }
    Remove-Item Env:SECRETS_FLEXVOLUME_PLUGIN_BINARY -ErrorAction SilentlyContinue

    $digest = 'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'
    $request = [ordered]@{
        apiVersion = 'pasturestack.io/secrets-flexvolume-plugin/v1alpha1'
        operation = 'stage'
        volumeRef = $digest
        ownerRef = $digest
        requestRef = $digest
        idempotencyRef = $digest
        sourceRef = $digest
        manifest = [ordered]@{
            manifestRef = $digest
            version = 1
            generation = 1
            expectedGeneration = 0
            notBefore = '2026-01-01T00:00:00Z'
            rotateAt = '2026-01-02T00:00:00Z'
            expiresAt = '2026-01-03T00:00:00Z'
            entries = @([ordered]@{
                name = 'validation/marker'
                type = 'regular'
                claimedBytes = 12
                claimedDigest = $digest
                uid = 1000
                gid = 1000
                mode = '0400'
            })
        }
        lifecycle = [ordered]@{ currentState = 'absent'; leaseCount = 0 }
        assertions = [ordered]@{ redacted = $true; encrypted = $true; attested = $true }
    }
    $requestJSON = $request | ConvertTo-Json -Depth 8 -Compress

    $capabilities = (& $hostA capabilities | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'capabilities smoke test failed' }
    $validated = ($requestJSON | & $hostA validate | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'validate smoke test failed' }
    $planned = ($requestJSON | & $hostA --locale zh-TW plan | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'plan smoke test failed' }

    foreach ($output in @($capabilities, $validated, $planned)) {
        if ($output.Contains('validation/marker') -or $output.Contains($digest)) {
            throw 'CLI output echoed request metadata'
        }
        $decoded = $output | ConvertFrom-Json
        foreach ($control in $decoded.controls.PSObject.Properties) {
            if ([bool]$control.Value) { throw "control enabled: $($control.Name)" }
        }
    }
    if (-not $planned.Contains('asserted-unverified')) { throw 'assertion status gate failed' }

    Write-Host 'Validation passed.'
}
finally {
    Pop-Location
    $resolvedTemp = [System.IO.Path]::GetFullPath($tempRoot)
    if (-not $resolvedTemp.StartsWith($tempBase, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'temporary path escaped its base directory'
    }
    if (Test-Path -LiteralPath $resolvedTemp) {
        Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
    }
}
