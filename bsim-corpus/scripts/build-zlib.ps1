[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptDir = $PSScriptRoot
$corpusRoot = Split-Path $scriptDir -Parent
$manifestPath = Join-Path $corpusRoot "manifest.json"
$sourcesDir = Join-Path $corpusRoot "sources"
$buildDir = Join-Path $corpusRoot "build\zlib-1.3.2-x64-release-syms"

. (Join-Path $scriptDir "lib\FetchAndVerify.ps1")
. (Join-Path $scriptDir "lib\VsEnv.ps1")

$archivePath = Get-VerifiedSource `
    -ManifestPath $manifestPath `
    -LibraryName "zlib" `
    -SourcesDir $sourcesDir

$extractedDir = Join-Path $sourcesDir "zlib-1.3.2"

if (-not (Test-Path -LiteralPath $extractedDir -PathType Container)) {
    Write-Host "Extracting zlib source..."
    & tar.exe -xzf $archivePath -C $sourcesDir

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to extract $archivePath"
    }
}

# zlib 1.3.2 removed its old Visual Studio project files in favor of CMake,
# but still ships the NMAKE makefile used here, which is the simpler,
# CMake-free path and keeps the toolchain identical to the sqlite3 build.
$makefile = Join-Path $extractedDir "win32\Makefile.msc"

if (-not (Test-Path -LiteralPath $makefile -PathType Leaf)) {
    throw "win32\Makefile.msc was not found after extraction: $makefile"
}

Import-VisualStudioX64Environment

if (-not (Get-Command nmake.exe -ErrorAction SilentlyContinue)) {
    throw "nmake.exe is not on PATH after importing the VS environment."
}

Push-Location $extractedDir
try {
    & nmake.exe -f win32\Makefile.msc clean
    & nmake.exe -f win32\Makefile.msc

    if ($LASTEXITCODE -ne 0) {
        throw "nmake failed to build zlib"
    }
}
finally {
    Pop-Location
}

if (Test-Path -LiteralPath $buildDir) {
    Remove-Item -LiteralPath $buildDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

Copy-Item -LiteralPath (Join-Path $extractedDir "zlib1.dll") -Destination $buildDir
Copy-Item -LiteralPath (Join-Path $extractedDir "zlib1.pdb") -Destination $buildDir

Write-Host ""
Write-Host "Built: $(Join-Path $buildDir 'zlib1.dll')"
Write-Host "Symbols: $(Join-Path $buildDir 'zlib1.pdb')"
