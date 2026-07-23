[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptDir = $PSScriptRoot
$corpusRoot = Split-Path $scriptDir -Parent
$manifestPath = Join-Path $corpusRoot "manifest.json"
$sourcesDir = Join-Path $corpusRoot "sources"
$buildDir = Join-Path $corpusRoot "build\sqlite3-3.53.3-x64-release-syms"

. (Join-Path $scriptDir "lib\FetchAndVerify.ps1")
. (Join-Path $scriptDir "lib\VsEnv.ps1")

$archivePath = Get-VerifiedSource `
    -ManifestPath $manifestPath `
    -LibraryName "sqlite3" `
    -SourcesDir $sourcesDir

$extractedDir = Join-Path $sourcesDir "sqlite-amalgamation-3530300"

if (-not (Test-Path -LiteralPath $extractedDir -PathType Container)) {
    Write-Host "Extracting SQLite amalgamation..."
    Expand-Archive -LiteralPath $archivePath -DestinationPath $sourcesDir
}

$sqliteSource = Join-Path $extractedDir "sqlite3.c"

if (-not (Test-Path -LiteralPath $sqliteSource -PathType Leaf)) {
    throw "sqlite3.c was not found after extraction: $sqliteSource"
}

Import-VisualStudioX64Environment

if (Test-Path -LiteralPath $buildDir) {
    Remove-Item -LiteralPath $buildDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

Write-Host "Compiling sqlite3.dll (x64, Release, symbols kept)..."

Push-Location $buildDir
try {
    # cl.exe/link.exe write normal progress to stderr; PowerShell's strict
    # mode otherwise treats that as a terminating error even on success, so
    # relax it here and rely on $LASTEXITCODE (checked below) instead.
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"

    # /MD links the dynamic MSVC CRT (msvcrt/ucrt) instead of statically
    # linking it into sqlite3.dll. Without it, CRT helper functions (e.g.
    # __acrt_locale_changed) get baked into sqlite3.dll and BSim/FID would
    # attribute them to "sqlite3" -- a real false-positive risk, confirmed
    # by inspecting the previous build's symbol table.
    & cl.exe /nologo /MD /O2 /Zi "/DSQLITE_API=__declspec(dllexport)" /c $sqliteSource 2>$null

    if ($LASTEXITCODE -ne 0) {
        $ErrorActionPreference = $previousErrorActionPreference
        throw "cl.exe failed to compile sqlite3.c"
    }

    & link.exe /nologo /DLL /DEBUG /OUT:sqlite3.dll sqlite3.obj 2>$null

    if ($LASTEXITCODE -ne 0) {
        $ErrorActionPreference = $previousErrorActionPreference
        throw "link.exe failed to link sqlite3.dll"
    }

    $ErrorActionPreference = $previousErrorActionPreference
}
finally {
    Pop-Location
}

Write-Host ""
Write-Host "Built: $(Join-Path $buildDir 'sqlite3.dll')"
Write-Host "Symbols: $(Join-Path $buildDir 'sqlite3.pdb')"
