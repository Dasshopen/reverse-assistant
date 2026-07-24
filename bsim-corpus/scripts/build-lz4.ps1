[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptDir = $PSScriptRoot
$corpusRoot = Split-Path $scriptDir -Parent
$manifestPath = Join-Path $corpusRoot "manifest.json"
$sourcesDir = Join-Path $corpusRoot "sources"
$extractedDir = Join-Path $sourcesDir "lz4-1.10.0"
$buildDir = Join-Path $corpusRoot "build\lz4-1.10.0-x64-release-syms"

. (Join-Path $scriptDir "lib\FetchAndVerify.ps1")
. (Join-Path $scriptDir "lib\VsEnv.ps1")

$archivePath = Get-VerifiedSource -ManifestPath $manifestPath -LibraryName "lz4" -SourcesDir $sourcesDir
if (-not (Test-Path -LiteralPath $extractedDir -PathType Container)) {
    Expand-Archive -LiteralPath $archivePath -DestinationPath $sourcesDir -Force
}

$libraryDir = Join-Path $extractedDir "lib"
if (-not (Test-Path -LiteralPath (Join-Path $libraryDir "lz4.c") -PathType Leaf)) {
    throw "LZ4 sources were not found after extraction: $libraryDir"
}

Import-VisualStudioX64Environment
if (Test-Path -LiteralPath $buildDir) {
    Remove-Item -LiteralPath $buildDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

$dll = Join-Path $buildDir "lz4.dll"
$pdb = Join-Path $buildDir "lz4.pdb"
$compilerPdb = Join-Path $buildDir "lz4-compile.pdb"
$sources = @(
    (Join-Path $libraryDir "lz4.c"),
    (Join-Path $libraryDir "lz4frame.c"),
    (Join-Path $libraryDir "lz4hc.c"),
    (Join-Path $libraryDir "xxhash.c")
)

$previousErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& cl.exe /nologo /LD /O2 /Zi /MD /GL- /DLZ4_DLL_EXPORT=1 "/I$libraryDir" "/Fo$buildDir\" "/Fd$compilerPdb" "/Fe$dll" $sources /link /DEBUG:FULL /INCREMENTAL:NO "/PDB:$pdb"
$exitCode = $LASTEXITCODE
$ErrorActionPreference = $previousErrorActionPreference
if ($exitCode -ne 0) {
    throw "cl.exe failed to build LZ4"
}

if (-not (Test-Path -LiteralPath $dll -PathType Leaf) -or -not (Test-Path -LiteralPath $pdb -PathType Leaf)) {
    throw "LZ4 build completed without producing the expected DLL/PDB"
}

Write-Host "Built: $dll"
Write-Host "Symbols: $pdb"
