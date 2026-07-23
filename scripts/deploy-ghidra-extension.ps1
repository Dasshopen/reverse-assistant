[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$GhidraInstallDir,

    [string]$GhidraUserDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$resolvedInstallDir = (
    Resolve-Path -LiteralPath $GhidraInstallDir
).Path

$gradleWrapper = Join-Path `
    $resolvedInstallDir `
    "support\gradle\gradlew.bat"

if (-not (Test-Path -LiteralPath $gradleWrapper -PathType Leaf)) {
    throw "The Ghidra Gradle wrapper was not found: $gradleWrapper"
}

$extensionProject = (
    Resolve-Path -LiteralPath (
        Join-Path `
            $PSScriptRoot `
            "..\ghidra-extension\ReverseAssistantExporter"
    )
).Path

if ([string]::IsNullOrWhiteSpace($GhidraUserDir)) {
    $ghidraInstallationName = Split-Path `
        $resolvedInstallDir `
        -Leaf

    $GhidraUserDir = Join-Path `
        $env:APPDATA `
        "ghidra\$ghidraInstallationName"
}

if (-not (Test-Path -LiteralPath $GhidraUserDir -PathType Container)) {
    throw "The Ghidra user directory does not exist: $GhidraUserDir"
}

$installedExtension = Join-Path `
    $GhidraUserDir `
    "Extensions\ReverseAssistantExporter"

$installedJars = @(
    Get-ChildItem `
        -LiteralPath (Join-Path $installedExtension "lib") `
        -Filter "*.jar" `
        -File `
        -ErrorAction SilentlyContinue
)

foreach ($jar in $installedJars) {
    try {
        $stream = [System.IO.File]::Open(
            $jar.FullName,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None
        )

        $stream.Dispose()
    }
    catch {
        throw "Close Ghidra before deploying the extension. Locked file: $($jar.FullName)"
    }
}

Write-Host "Building Reverse Assistant Exporter..."

& $gradleWrapper `
    -p $extensionProject `
    "-PGHIDRA_INSTALL_DIR=$resolvedInstallDir" `
    buildExtension

if ($LASTEXITCODE -ne 0) {
    throw "The Ghidra extension build failed."
}

$archive = Get-ChildItem `
    -LiteralPath (Join-Path $extensionProject "dist") `
    -Filter "*.zip" `
    -File |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if ($null -eq $archive) {
    throw "No extension archive was found in the dist directory."
}

$temporaryDirectory = Join-Path `
    ([System.IO.Path]::GetTempPath()) `
    (
        "reverse-assistant-ghidra-deploy-" +
        [System.Guid]::NewGuid().ToString("N")
    )

New-Item `
    -ItemType Directory `
    -Path $temporaryDirectory |
    Out-Null

try {
    Expand-Archive `
        -LiteralPath $archive.FullName `
        -DestinationPath $temporaryDirectory

    $extractedExtension = Join-Path `
        $temporaryDirectory `
        "ReverseAssistantExporter"

    if (-not (
        Test-Path `
            -LiteralPath $extractedExtension `
            -PathType Container
    )) {
        throw "The archive does not contain ReverseAssistantExporter."
    }

    New-Item `
        -ItemType Directory `
        -Force `
        -Path $installedExtension |
        Out-Null

    Copy-Item `
        -Path (Join-Path $extractedExtension "*") `
        -Destination $installedExtension `
        -Recurse `
        -Force

    # ZIP entries produced by Ghidra's extension build can carry timestamps
    # older than Ghidra's compiled-script cache. Refresh installed files so an
    # upgraded .java script is recompiled instead of calling an obsolete JAR
    # method signature from a stale cached .class file.
    $deploymentTime = Get-Date
    Get-ChildItem `
        -LiteralPath $installedExtension `
        -File `
        -Recurse |
        ForEach-Object {
            $_.LastWriteTime = $deploymentTime
        }

    Write-Host ""
    Write-Host "Deployment successful:"
    Write-Host $installedExtension
    Write-Host ""
    Write-Host "Restart Ghidra to load the updated extension."
}
finally {
    if (Test-Path -LiteralPath $temporaryDirectory) {
        Remove-Item `
            -LiteralPath $temporaryDirectory `
            -Recurse `
            -Force `
            -ErrorAction SilentlyContinue
    }
}
