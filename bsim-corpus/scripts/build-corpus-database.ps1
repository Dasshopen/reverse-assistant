# Builds the BSim seed database from the DLLs already compiled by
# build-sqlite.ps1 / build-zlib.ps1: analyzes each one with a full (non
# speed-optimized) Ghidra headless pass so the PDB analyzer assigns real
# function names, then generates and commits BSim signatures for it.
#
# H2-backed BSim databases can only be accessed by one process at a time,
# and Ghidra must not have the project open while bsim runs against it --
# this is naturally satisfied here since each analyzeHeadless invocation
# below exits before the corresponding bsim command runs.
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
$bsim = Join-Path $resolvedInstallDir "support\bsim.bat"

if (-not (Test-Path -LiteralPath $analyzeHeadless -PathType Leaf)) {
    throw "analyzeHeadless.bat was not found: $analyzeHeadless"
}

if (-not (Test-Path -LiteralPath $bsim -PathType Leaf)) {
    throw "bsim.bat was not found: $bsim"
}

$corpusRoot = Split-Path $PSScriptRoot -Parent
$projectsDir = Join-Path $corpusRoot "build\ghidra-projects"
$dbBaseName = "reverse-assistant-seed"
$dbFile = Join-Path $corpusRoot "build\$dbBaseName.mv.db"
$dbUrl = "file:/" + ($corpusRoot -replace '\\', '/') + "/build/$dbBaseName"

$libraries = @(
    @{ Name = "sqlite3"; Dll = Join-Path $corpusRoot "build\sqlite3-3.53.3-x64-release-syms\sqlite3.dll" },
    @{ Name = "zlib"; Dll = Join-Path $corpusRoot "build\zlib-1.3.2-x64-release-syms\zlib1.dll" },
    @{ Name = "lz4"; Dll = Join-Path $corpusRoot "build\lz4-1.10.0-x64-release-syms\lz4.dll" },
    @{ Name = "xxhash"; Dll = Join-Path $corpusRoot "build\xxhash-0.8.3-x64-release-syms\xxhash.dll" }
)

foreach ($library in $libraries) {
    if (-not (Test-Path -LiteralPath $library.Dll -PathType Leaf)) {
        throw "$($library.Name) DLL not found at $($library.Dll); run its build script first."
    }
}

if (Test-Path -LiteralPath $dbFile) {
    Write-Host "Removing existing BSim database: $dbFile"
    Remove-Item -LiteralPath $dbFile -Force
}

if (Test-Path -LiteralPath $projectsDir) {
    Remove-Item -LiteralPath $projectsDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $projectsDir | Out-Null

Write-Host "Creating BSim database: $dbUrl"
& $bsim createdatabase $dbUrl medium_64

if ($LASTEXITCODE -ne 0) {
    throw "bsim createdatabase failed"
}

foreach ($library in $libraries) {
    $projectDir = Join-Path $projectsDir $library.Name
    $sigsDir = Join-Path $projectsDir "$($library.Name)-sigs"

    # analyzeHeadless expects the project directory to already exist when
    # creating a new project (confirmed by testing: it throws
    # "Directory not found" otherwise, unlike -process on an existing project).
    New-Item -ItemType Directory -Force -Path $projectDir | Out-Null

    Write-Host ""
    Write-Host "Analyzing $($library.Name) ($($library.Dll))..."

    & $analyzeHeadless $projectDir $library.Name -import $library.Dll

    if ($LASTEXITCODE -ne 0) {
        throw "analyzeHeadless failed while analyzing $($library.Name)"
    }

    $ghidraProjectUrl = "ghidra:/" + ($projectDir -replace '\\', '/') + "/$($library.Name)"

    New-Item -ItemType Directory -Force -Path $sigsDir | Out-Null

    Write-Host "Generating and committing BSim signatures for $($library.Name)..."

    & $bsim generatesigs $ghidraProjectUrl $sigsDir --bsim $dbUrl --commit

    if ($LASTEXITCODE -ne 0) {
        throw "bsim generatesigs failed for $($library.Name)"
    }
}

Write-Host ""
Write-Host "BSim seed database built: $dbFile"
