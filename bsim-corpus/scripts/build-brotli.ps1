[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptDir = $PSScriptRoot
$corpusRoot = Split-Path $scriptDir -Parent
$manifestPath = Join-Path $corpusRoot "manifest.json"
$sourcesDir = Join-Path $corpusRoot "sources"
$extractedDir = Join-Path $sourcesDir "brotli-1.2.0"
$buildDir = Join-Path $corpusRoot "build\brotli-1.2.0-x64-release-syms"

. (Join-Path $scriptDir "lib\FetchAndVerify.ps1")
. (Join-Path $scriptDir "lib\VsEnv.ps1")

$archivePath = Get-VerifiedSource -ManifestPath $manifestPath -LibraryName "brotli" -SourcesDir $sourcesDir
if (-not (Test-Path -LiteralPath $extractedDir -PathType Container)) {
    Expand-Archive -LiteralPath $archivePath -DestinationPath $sourcesDir -Force
}

$includeDir = Join-Path $extractedDir "c\include"
if (-not (Test-Path -LiteralPath (Join-Path $includeDir "brotli\decode.h") -PathType Leaf)) {
    throw "brotli sources were not found after extraction: $includeDir"
}

Import-VisualStudioX64Environment
if (Test-Path -LiteralPath $buildDir) {
    Remove-Item -LiteralPath $buildDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

$dll = Join-Path $buildDir "brotli.dll"
$pdb = Join-Path $buildDir "brotli.pdb"
$compilerPdb = Join-Path $buildDir "brotli-compile.pdb"

# common + dec (decoder) + enc (encoder) -- c/tools/brotli.c is the CLI
# front-end, not part of the library, and is excluded. dec/ and enc/ each
# have their own "static_init.c" -- compiling all groups into one shared
# /Fo directory silently collapses same-named objects onto each other
# (confirmed: linking then failed on a real missing decoder symbol with no
# compile error at all), so each group compiles into its own object
# subdirectory instead of one shared one.
$cDir = Join-Path $extractedDir "c"
$groups = @("common", "dec", "enc")
$objects = @()

$previousErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
foreach ($group in $groups) {
    $groupDir = Join-Path $cDir $group
    $groupObjDir = Join-Path $buildDir $group
    New-Item -ItemType Directory -Force -Path $groupObjDir | Out-Null
    $groupSources = Get-ChildItem $groupDir -Filter *.c | ForEach-Object { $_.FullName }

    & cl.exe /nologo /c /O2 /Zi /MD /GL- /DBROTLI_SHARED_COMPILATION "/I$includeDir" "/Fo$groupObjDir\" "/Fd$compilerPdb" $groupSources
    if ($LASTEXITCODE -ne 0) {
        $ErrorActionPreference = $previousErrorActionPreference
        throw "cl.exe failed to compile brotli's $group sources"
    }

    $objects += Get-ChildItem $groupObjDir -Filter *.obj | ForEach-Object { $_.FullName }
}

& link.exe /nologo /DLL /DEBUG:FULL /INCREMENTAL:NO "/PDB:$pdb" "/OUT:$dll" $objects
$exitCode = $LASTEXITCODE
$ErrorActionPreference = $previousErrorActionPreference
if ($exitCode -ne 0) {
    throw "link.exe failed to link brotli.dll"
}

if (-not (Test-Path -LiteralPath $dll -PathType Leaf) -or -not (Test-Path -LiteralPath $pdb -PathType Leaf)) {
    throw "brotli build completed without producing the expected DLL/PDB"
}

Write-Host "Built: $dll"
Write-Host "Symbols: $pdb"
