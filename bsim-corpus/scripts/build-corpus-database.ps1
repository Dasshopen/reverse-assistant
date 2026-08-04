# Builds the BSim seed database from the reference binaries already compiled
# by the library/runtime build scripts: analyzes each one with a full (non
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
$dbBaseName = "reverse-assistant-seed"
$dbFile = Join-Path $corpusRoot "build\$dbBaseName.mv.db"
$stagingBaseName = "$dbBaseName-next"
$stagingDbFile = Join-Path $corpusRoot "build\$stagingBaseName.mv.db"
$dbUrl = "file:/" + ($corpusRoot -replace '\\', '/') + "/build/$stagingBaseName"
$projectsDir = Join-Path $corpusRoot "build\ghidra-projects-next"
$finalProjectsDir = Join-Path $corpusRoot "build\ghidra-projects"

$libraries = @(
    @{ Name = "sqlite3"; Dll = Join-Path $corpusRoot "build\sqlite3-3.53.3-x64-release-syms\sqlite3.dll" },
    @{ Name = "zlib"; Dll = Join-Path $corpusRoot "build\zlib-1.3.2-x64-release-syms\zlib1.dll" },
    @{ Name = "lz4"; Dll = Join-Path $corpusRoot "build\lz4-1.10.0-x64-release-syms\lz4.dll" },
    @{ Name = "xxhash"; Dll = Join-Path $corpusRoot "build\xxhash-0.8.3-x64-release-syms\xxhash.dll" },
    @{ Name = "zstd"; Dll = Join-Path $corpusRoot "build\zstd-1.5.7-x64-release-syms\zstd.dll" },
    @{ Name = "brotli"; Dll = Join-Path $corpusRoot "build\brotli-1.2.0-x64-release-syms\brotli.dll" },
    @{ Name = "msvc-runtime"; Dll = Join-Path $corpusRoot "build\msvc-runtime-x64-release-syms\msvc-runtime-reference.exe" },
    @{
        Name = "edk2-uefi"
        Dll = Join-Path $corpusRoot "build\edk2-stable202605-shell-x64-debug-syms\Shell.efi"
        Pdb = Join-Path $corpusRoot "build\edk2-stable202605-shell-x64-debug-syms\Shell.pdb"
    }
)

$edk2ModulesRoot = Join-Path $corpusRoot "build\edk2-stable202605-shell-x64-debug-syms\modules"
$edk2Modules = @(
    @{ Id = "acpi-view"; Efi = "AcpiViewApp.efi"; Pdb = "AcpiViewApp.pdb" },
    @{ Id = "dp"; Efi = "dp.efi"; Pdb = "dp.pdb" },
    @{ Id = "dp-command"; Efi = "dpDynamicCommand.efi"; Pdb = "dpDynamicCommand.pdb" },
    @{ Id = "http"; Efi = "http.efi"; Pdb = "http.pdb" },
    @{ Id = "http-command"; Efi = "httpDynamicCommand.efi"; Pdb = "httpDynamicCommand.pdb" },
    @{ Id = "tftp"; Efi = "tftp.efi"; Pdb = "tftp.pdb" },
    @{ Id = "tftp-command"; Efi = "TftpDynamicCommand.efi"; Pdb = "TftpDynamicCommand.pdb" },
    @{ Id = "var-policy"; Efi = "varpolicy.efi"; Pdb = "varpolicy.pdb" },
    @{ Id = "var-policy-command"; Efi = "VariablePolicyDynamicCommand.efi"; Pdb = "VariablePolicyDynamicCommand.pdb" }
)
foreach ($module in $edk2Modules) {
    $moduleDir = Join-Path $edk2ModulesRoot $module.Id
    $libraries += @{
        Name = "edk2-$($module.Id)"
        Dll = Join-Path $moduleDir $module.Efi
        Pdb = Join-Path $moduleDir $module.Pdb
    }
}

$manifestPath = Join-Path $corpusRoot "manifest.json"
$pyinstallerVersions = @(
    (Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json).libraries |
        Where-Object { $_.name -like "pyinstaller-*" } |
        ForEach-Object { $_.version }
)
$pyinstallerArchitectures = @("x86", "x64")
# Debug variants are built for reproducibility but intentionally not ingested:
# their extra logging produces near-duplicate candidates and increases name
# ambiguity without representing normal packaged applications.
$pyinstallerBootloaders = @("run", "runw")
foreach ($version in $pyinstallerVersions) {
    foreach ($architecture in $pyinstallerArchitectures) {
        $referenceDir = Join-Path $corpusRoot "build\pyinstaller\$version-$architecture"
        foreach ($bootloader in $pyinstallerBootloaders) {
            $projectId = "pyinstaller-$($version.Replace('.', '_'))-$architecture-$bootloader"
            $libraries += @{
                Name = $projectId
                Dll = Join-Path $referenceDir "$bootloader.exe"
                Pdb = Join-Path $referenceDir "$bootloader.pdb"
            }
        }
    }
}

foreach ($library in $libraries) {
    if (-not (Test-Path -LiteralPath $library.Dll -PathType Leaf)) {
        throw "$($library.Name) reference binary not found at $($library.Dll); run its build script first."
    }

    if ($library.ContainsKey("Pdb") -and -not (Test-Path -LiteralPath $library.Pdb -PathType Leaf)) {
        throw "$($library.Name) reference PDB not found at $($library.Pdb); run its build script first."
    }
}

if (Test-Path -LiteralPath $stagingDbFile) {
    Write-Host "Removing incomplete staging BSim database: $stagingDbFile"
    Remove-Item -LiteralPath $stagingDbFile -Force
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

    if ($library.ContainsKey("Pdb")) {
        & $analyzeHeadless `
            $projectDir `
            $library.Name `
            -import $library.Dll `
            -scriptPath $PSScriptRoot `
            -preScript "ConfigurePdb.java" $library.Pdb `
            -postScript "RemoveUnusableBsimFunctions.java"
    }
    else {
        & $analyzeHeadless `
            $projectDir `
            $library.Name `
            -import $library.Dll `
            -scriptPath $PSScriptRoot `
            -postScript "RemoveUnusableBsimFunctions.java"
    }

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
Write-Host "Promoting completed BSim database into place..."
$promotionStamp = Get-Date -Format "yyyyMMdd-HHmmss"
if (Test-Path -LiteralPath $dbFile) {
    $dbBackup = Join-Path $corpusRoot "build\$dbBaseName.previous-$promotionStamp.mv.db"
    Move-Item -LiteralPath $dbFile -Destination $dbBackup
    Write-Host "Previous database retained at: $dbBackup"
}
Move-Item -LiteralPath $stagingDbFile -Destination $dbFile

if (Test-Path -LiteralPath $finalProjectsDir) {
    $projectsBackup = Join-Path $corpusRoot "build\ghidra-projects.previous-$promotionStamp"
    Move-Item -LiteralPath $finalProjectsDir -Destination $projectsBackup
    Write-Host "Previous reference projects retained at: $projectsBackup"
}
Move-Item -LiteralPath $projectsDir -Destination $finalProjectsDir

Write-Host "BSim seed database built: $dbFile"
