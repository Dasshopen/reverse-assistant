# Runs the end-to-end BSim round-trip validation against every reference
# project. Ghidra analyzeHeadless may return exit code 0 even when a postScript
# throws, so this wrapper also requires the Java validator's success marker.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$GhidraInstallDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$resolvedInstallDir = (Resolve-Path -LiteralPath $GhidraInstallDir).Path
$analyzeHeadless = Join-Path $resolvedInstallDir "support\analyzeHeadless.bat"

if (-not (Test-Path -LiteralPath $analyzeHeadless -PathType Leaf)) {
    throw "analyzeHeadless.bat was not found: $analyzeHeadless"
}

$corpusRoot = Split-Path $PSScriptRoot -Parent
$dbFile = Join-Path $corpusRoot "build\reverse-assistant-seed.mv.db"
$dbUrl = "file:/" + (($dbFile -replace '\\', '/') -replace '\.mv\.db$', '')

if (-not (Test-Path -LiteralPath $dbFile -PathType Leaf)) {
    throw "BSim database not found: $dbFile; run build-corpus-database.ps1 first."
}

$libraries = @(
    @{
        Name = "sqlite3"
        ProjectDir = Join-Path $corpusRoot "build\ghidra-projects\sqlite3"
        Program = "sqlite3.dll"
    },
    @{
        Name = "zlib"
        ProjectDir = Join-Path $corpusRoot "build\ghidra-projects\zlib"
        Program = "zlib1.dll"
    },
    @{
        Name = "lz4"
        ProjectDir = Join-Path $corpusRoot "build\ghidra-projects\lz4"
        Program = "lz4.dll"
    },
    @{
        Name = "xxhash"
        ProjectDir = Join-Path $corpusRoot "build\ghidra-projects\xxhash"
        Program = "xxhash.dll"
    },
    @{
        Name = "zstd"
        ProjectDir = Join-Path $corpusRoot "build\ghidra-projects\zstd"
        Program = "zstd.dll"
    },
    @{
        Name = "brotli"
        ProjectDir = Join-Path $corpusRoot "build\ghidra-projects\brotli"
        Program = "brotli.dll"
    }
)

foreach ($library in $libraries) {
    $projectFile = Join-Path $library.ProjectDir "$($library.Name).gpr"

    if (-not (Test-Path -LiteralPath $projectFile -PathType Leaf)) {
        throw "Ghidra project not found: $projectFile; run build-corpus-database.ps1 first."
    }

    $successMarker = Join-Path $corpusRoot "build\verify-$($library.Name).ok"

    if (Test-Path -LiteralPath $successMarker) {
        Remove-Item -LiteralPath $successMarker -Force
    }

    Write-Host "Validating BSim round trip for $($library.Name)..."

    & $analyzeHeadless `
        $library.ProjectDir `
        $library.Name `
        -process $library.Program `
        -readOnly `
        -noanalysis `
        -scriptPath $PSScriptRoot `
        -postScript "VerifyBsimQuery.java" $dbUrl $successMarker

    if ($LASTEXITCODE -ne 0) {
        throw "analyzeHeadless failed while validating $($library.Name)"
    }

    if (-not (Test-Path -LiteralPath $successMarker -PathType Leaf)) {
        throw "BSim validation failed for $($library.Name); inspect Ghidra's application.log for the script error."
    }
}

Write-Host "BSim corpus validation succeeded for every reference library."
