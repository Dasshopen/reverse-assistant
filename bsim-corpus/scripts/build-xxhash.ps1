[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptDir = $PSScriptRoot
$corpusRoot = Split-Path $scriptDir -Parent
$manifestPath = Join-Path $corpusRoot "manifest.json"
$sourcesDir = Join-Path $corpusRoot "sources"
$extractedDir = Join-Path $sourcesDir "xxHash-0.8.3"
$buildDir = Join-Path $corpusRoot "build\xxhash-0.8.3-x64-release-syms"

. (Join-Path $scriptDir "lib\FetchAndVerify.ps1")
. (Join-Path $scriptDir "lib\VsEnv.ps1")

$archivePath = Get-VerifiedSource -ManifestPath $manifestPath -LibraryName "xxhash" -SourcesDir $sourcesDir
if (-not (Test-Path -LiteralPath $extractedDir -PathType Container)) {
    Expand-Archive -LiteralPath $archivePath -DestinationPath $sourcesDir -Force
}

$source = Join-Path $extractedDir "xxhash.c"
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
    throw "xxHash source was not found after extraction: $source"
}

Import-VisualStudioX64Environment
if (Test-Path -LiteralPath $buildDir) {
    Remove-Item -LiteralPath $buildDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

$dll = Join-Path $buildDir "xxhash.dll"
$pdb = Join-Path $buildDir "xxhash.pdb"
$compilerPdb = Join-Path $buildDir "xxhash-compile.pdb"
$previousErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& cl.exe /nologo /LD /O2 /Zi /MD /GL- /DXXH_EXPORT "/I$extractedDir" "/Fo$buildDir\" "/Fd$compilerPdb" "/Fe$dll" $source /link /DEBUG:FULL /INCREMENTAL:NO "/PDB:$pdb"
$exitCode = $LASTEXITCODE
$ErrorActionPreference = $previousErrorActionPreference
if ($exitCode -ne 0) {
    throw "cl.exe failed to build xxHash"
}

if (-not (Test-Path -LiteralPath $dll -PathType Leaf) -or -not (Test-Path -LiteralPath $pdb -PathType Leaf)) {
    throw "xxHash build completed without producing the expected DLL/PDB"
}

Write-Host "Built: $dll"
Write-Host "Symbols: $pdb"
