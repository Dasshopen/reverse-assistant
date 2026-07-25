[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptDir = $PSScriptRoot
$corpusRoot = Split-Path $scriptDir -Parent
$manifestPath = Join-Path $corpusRoot "manifest.json"
$sourcesDir = Join-Path $corpusRoot "sources"
$extractedDir = Join-Path $sourcesDir "zstd-1.5.7"
$buildDir = Join-Path $corpusRoot "build\zstd-1.5.7-x64-release-syms"

. (Join-Path $scriptDir "lib\FetchAndVerify.ps1")
. (Join-Path $scriptDir "lib\VsEnv.ps1")

$archivePath = Get-VerifiedSource -ManifestPath $manifestPath -LibraryName "zstd" -SourcesDir $sourcesDir
if (-not (Test-Path -LiteralPath $extractedDir -PathType Container)) {
    Expand-Archive -LiteralPath $archivePath -DestinationPath $sourcesDir -Force
}

$libraryDir = Join-Path $extractedDir "lib"
if (-not (Test-Path -LiteralPath (Join-Path $libraryDir "zstd.h") -PathType Leaf)) {
    throw "zstd sources were not found after extraction: $libraryDir"
}

Import-VisualStudioX64Environment
if (Test-Path -LiteralPath $buildDir) {
    Remove-Item -LiteralPath $buildDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

$dll = Join-Path $buildDir "zstd.dll"
$pdb = Join-Path $buildDir "zstd.pdb"
$compilerPdb = Join-Path $buildDir "zstd-compile.pdb"

# common + compress + decompress + dictBuilder -- legacy/ (old format
# decoders) and deprecated/ (old buffer API) are omitted deliberately:
# neither adds real, distinctly-named functions relevant to BSim
# corroboration. zstd_compress.c references ZSTDMT_* symbols
# unconditionally (an #ifdef ZSTD_MULTITHREAD guard, not an #if, so even
# defining the macro to 0 still pulls them in) -- zstdmt_compress.c stays
# in rather than fighting that; threading.c's Windows-native thread shim
# means it needs no external pthread dependency here.
$sources = @(
    Get-ChildItem (Join-Path $libraryDir "common") -Filter *.c |
        ForEach-Object { $_.FullName }
    Get-ChildItem (Join-Path $libraryDir "compress") -Filter *.c |
        ForEach-Object { $_.FullName }
    Get-ChildItem (Join-Path $libraryDir "decompress") -Filter *.c |
        ForEach-Object { $_.FullName }
    Get-ChildItem (Join-Path $libraryDir "dictBuilder") -Filter *.c |
        ForEach-Object { $_.FullName }
)

$previousErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& cl.exe /nologo /LD /O2 /Zi /MD /GL- /DZSTD_DLL_EXPORT=1 /DZSTD_MULTITHREAD "/I$libraryDir" "/Fo$buildDir\" "/Fd$compilerPdb" "/Fe$dll" $sources /link /DEBUG:FULL /INCREMENTAL:NO "/PDB:$pdb"
$exitCode = $LASTEXITCODE
$ErrorActionPreference = $previousErrorActionPreference
if ($exitCode -ne 0) {
    throw "cl.exe failed to build zstd"
}

if (-not (Test-Path -LiteralPath $dll -PathType Leaf) -or -not (Test-Path -LiteralPath $pdb -PathType Leaf)) {
    throw "zstd build completed without producing the expected DLL/PDB"
}

Write-Host "Built: $dll"
Write-Host "Symbols: $pdb"
