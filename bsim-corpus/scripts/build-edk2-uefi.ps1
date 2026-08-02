[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptDir = $PSScriptRoot
$corpusRoot = Split-Path $scriptDir -Parent
$manifestPath = Join-Path $corpusRoot "manifest.json"
$sourcesDir = Join-Path $corpusRoot "sources"
$toolsDir = Join-Path $corpusRoot "build\portable-tools"
$buildDir = Join-Path $corpusRoot "build\edk2-stable202605-shell-x64-debug-syms"

. (Join-Path $scriptDir "lib\FetchAndVerify.ps1")
. (Join-Path $scriptDir "lib\VsEnv.ps1")

$edk2Archive = Get-VerifiedSource -ManifestPath $manifestPath -LibraryName "edk2-uefi" -SourcesDir $sourcesDir
$pythonArchive = Get-VerifiedSource -ManifestPath $manifestPath -LibraryName "python-embed" -SourcesDir $sourcesDir
$nasmArchive = Get-VerifiedSource -ManifestPath $manifestPath -LibraryName "nasm-portable" -SourcesDir $sourcesDir
$mipiSysTArchive = Get-VerifiedSource -ManifestPath $manifestPath -LibraryName "edk2-mipisyst" -SourcesDir $sourcesDir
$edk2BrotliArchive = Get-VerifiedSource -ManifestPath $manifestPath -LibraryName "edk2-brotli" -SourcesDir $sourcesDir

$edk2Root = Join-Path $sourcesDir "edk2-edk2-stable202605"
$pythonRoot = Join-Path $toolsDir "python-3.12.10"
$nasmRoot = Join-Path $toolsDir "nasm-2.16.03"
$mipiSysTRoot = Join-Path $edk2Root "MdePkg\Library\MipiSysTLib\mipisyst"

if (-not (Test-Path -LiteralPath $edk2Root -PathType Container)) {
    Write-Host "Extracting EDK2 source..."
    Expand-Archive -LiteralPath $edk2Archive -DestinationPath $sourcesDir
}

if (-not (Test-Path -LiteralPath (Join-Path $mipiSysTRoot "library\include") -PathType Container)) {
    Write-Host "Extracting the EDK2-pinned MipiSysT submodule..."
    $mipiExtractRoot = Join-Path $toolsDir "mipisyst-extract"
    if (Test-Path -LiteralPath $mipiExtractRoot) {
        Remove-Item -LiteralPath $mipiExtractRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $mipiExtractRoot | Out-Null
    Expand-Archive -LiteralPath $mipiSysTArchive -DestinationPath $mipiExtractRoot
    $mipiArchiveRoot = Get-ChildItem -LiteralPath $mipiExtractRoot -Directory | Select-Object -First 1
    if ($null -eq $mipiArchiveRoot) {
        throw "The MipiSysT archive had no source directory."
    }
    if (Test-Path -LiteralPath $mipiSysTRoot) {
        Remove-Item -LiteralPath $mipiSysTRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $mipiSysTRoot | Out-Null
    Copy-Item -Path (Join-Path $mipiArchiveRoot.FullName '*') -Destination $mipiSysTRoot -Recurse -Force
    Remove-Item -LiteralPath $mipiExtractRoot -Recurse -Force
}

$brotliTargets = @(
    (Join-Path $edk2Root "BaseTools\Source\C\BrotliCompress\brotli"),
    (Join-Path $edk2Root "MdeModulePkg\Library\BrotliCustomDecompressLib\brotli")
)
if ($brotliTargets | Where-Object { -not (Test-Path -LiteralPath (Join-Path $_ "c\include") -PathType Container) }) {
    Write-Host "Extracting the EDK2-pinned Brotli submodule..."
    $brotliExtractRoot = Join-Path $toolsDir "edk2-brotli-extract"
    if (Test-Path -LiteralPath $brotliExtractRoot) {
        Remove-Item -LiteralPath $brotliExtractRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $brotliExtractRoot | Out-Null
    Expand-Archive -LiteralPath $edk2BrotliArchive -DestinationPath $brotliExtractRoot
    $brotliArchiveRoot = Get-ChildItem -LiteralPath $brotliExtractRoot -Directory | Select-Object -First 1
    if ($null -eq $brotliArchiveRoot) {
        throw "The EDK2 Brotli archive had no source directory."
    }
    foreach ($target in $brotliTargets) {
        if (Test-Path -LiteralPath $target) {
            Remove-Item -LiteralPath $target -Recurse -Force
        }
        New-Item -ItemType Directory -Force -Path $target | Out-Null
        Copy-Item -Path (Join-Path $brotliArchiveRoot.FullName '*') -Destination $target -Recurse -Force
    }
    Remove-Item -LiteralPath $brotliExtractRoot -Recurse -Force
}

if (-not (Test-Path -LiteralPath (Join-Path $pythonRoot "python.exe") -PathType Leaf)) {
    Write-Host "Extracting portable Python..."
    New-Item -ItemType Directory -Force -Path $pythonRoot | Out-Null
    Expand-Archive -LiteralPath $pythonArchive -DestinationPath $pythonRoot
}

if (-not (Test-Path -LiteralPath (Join-Path $nasmRoot "nasm.exe") -PathType Leaf)) {
    Write-Host "Extracting portable NASM..."
    $nasmExtractRoot = Join-Path $toolsDir "nasm-extract"
    if (Test-Path -LiteralPath $nasmExtractRoot) {
        Remove-Item -LiteralPath $nasmExtractRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $nasmExtractRoot | Out-Null
    Expand-Archive -LiteralPath $nasmArchive -DestinationPath $nasmExtractRoot
    $nasmBinary = Get-ChildItem -LiteralPath $nasmExtractRoot -Filter nasm.exe -File -Recurse | Select-Object -First 1
    if ($null -eq $nasmBinary) {
        throw "nasm.exe was not found in $nasmArchive"
    }
    New-Item -ItemType Directory -Force -Path $nasmRoot | Out-Null
    Copy-Item -LiteralPath $nasmBinary.FullName -Destination (Join-Path $nasmRoot "nasm.exe")
    Remove-Item -LiteralPath $nasmExtractRoot -Recurse -Force
}

$pythonExe = Join-Path $pythonRoot "python.exe"
# Python's embeddable distribution enables isolated-path mode through this
# file, which intentionally ignores PYTHONPATH. EDK2's BaseTools are Python
# modules loaded from PYTHONPATH, so disable isolation in this private copy.
$isolatedPathFile = Join-Path $pythonRoot "python312._pth"
if (Test-Path -LiteralPath $isolatedPathFile -PathType Leaf) {
    Move-Item -LiteralPath $isolatedPathFile -Destination "$isolatedPathFile.disabled" -Force
}
& $pythonExe --version
if ($LASTEXITCODE -ne 0) {
    throw "The portable Python runtime could not be started."
}

Import-VisualStudioX64Environment

$env:WORKSPACE = $edk2Root
$env:PACKAGES_PATH = $edk2Root
$env:EDK_TOOLS_PATH = Join-Path $edk2Root "BaseTools"
$env:EDK_TOOLS_BIN = Join-Path $edk2Root "BaseTools\Bin\Win64"
$env:PYTHON_COMMAND = $pythonExe
$env:PYTHON_HOME = $pythonRoot
$env:NASM_PREFIX = $nasmRoot.TrimEnd('\') + '\'
# The native tools are compiled by the x64 Visual Studio environment. EDK2
# otherwise defaults their ABI to IA32, which turns valid host pointers into
# truncation warnings (and /WX then rejects the build with modern MSVC).
$env:HOST_ARCH = "X64"

# GitHub source archives intentionally do not contain Git submodules. The
# native BrotliCompress helper depends on one of those submodules, but is not
# used by ShellPkg. Keep this archive-only build reproducible by excluding that
# unrelated host utility instead of silently fetching unpinned Git content.
$baseToolsMakefile = Join-Path $edk2Root "BaseTools\Source\C\Makefile"
$brotliSubmodule = Join-Path $edk2Root "BaseTools\Source\C\BrotliCompress\brotli\c"
if (-not (Test-Path -LiteralPath $brotliSubmodule -PathType Container)) {
    $makefileContents = Get-Content -LiteralPath $baseToolsMakefile -Raw
    $patchedContents = $makefileContents -replace '(?m)^  BrotliCompress \\\r?\n', ''
    if ($patchedContents -eq $makefileContents -and $makefileContents -match '(?m)^  BrotliCompress') {
        throw "Could not exclude the unavailable BrotliCompress host utility from $baseToolsMakefile"
    }
    Set-Content -LiteralPath $baseToolsMakefile -Value $patchedContents -Encoding Ascii
}

Push-Location $edk2Root
try {
    Write-Host "Preparing EDK2 BaseTools and building the official X64 UEFI Shell..."
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    # Keep setup and build in the same cmd.exe process: edksetup exports PATH,
    # PYTHONPATH and the Visual Studio prefixes only to its calling shell.
    & cmd.exe /d /c "call edksetup.bat Rebuild VS2022 && build -p ShellPkg\ShellPkg.dsc -a X64 -t VS2022 -b DEBUG"
    $buildExitCode = $LASTEXITCODE
    $ErrorActionPreference = $previousErrorActionPreference
    if ($buildExitCode -ne 0) {
        throw "EDK2 BaseTools/ShellPkg build failed with exit code $buildExitCode."
    }
}
finally {
    Pop-Location
}

$shellOutput = Join-Path $edk2Root "Build\Shell\DEBUG_VS2022\X64"
$shellEfi = Get-ChildItem -LiteralPath $shellOutput -Filter Shell.efi -File -Recurse | Select-Object -First 1
if ($null -eq $shellEfi) {
    throw "The EDK2 build succeeded but Shell.efi was not found."
}

if (Test-Path -LiteralPath $buildDir) {
    Remove-Item -LiteralPath $buildDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
Copy-Item -LiteralPath $shellEfi.FullName -Destination (Join-Path $buildDir "Shell.efi")

$symbolCandidates = @(Get-ChildItem -LiteralPath $shellOutput -File -Recurse |
    Where-Object { $_.Extension -in @('.pdb', '.map') -and $_.BaseName -in @('Shell', 'Shell.dll') })
foreach ($symbol in $symbolCandidates) {
    Copy-Item -LiteralPath $symbol.FullName -Destination $buildDir -Force
}

# ShellPkg also builds several production UEFI applications and dynamic
# commands. Keep one copy of each with its exact PDB: shared EDK2 library code
# can lose its symbol in one linked image while remaining named in another,
# so this broader set is materially more useful than Shell.efi alone.
$moduleDefinitions = @(
    @{ Id = 'acpi-view'; Efi = 'AcpiViewApp.efi'; Pdb = 'AcpiViewApp.pdb' },
    @{ Id = 'dp'; Efi = 'dp.efi'; Pdb = 'dp.pdb' },
    @{ Id = 'dp-command'; Efi = 'dpDynamicCommand.efi'; Pdb = 'dpDynamicCommand.pdb' },
    @{ Id = 'http'; Efi = 'http.efi'; Pdb = 'http.pdb' },
    @{ Id = 'http-command'; Efi = 'httpDynamicCommand.efi'; Pdb = 'httpDynamicCommand.pdb' },
    @{ Id = 'tftp'; Efi = 'tftp.efi'; Pdb = 'tftp.pdb' },
    @{ Id = 'tftp-command'; Efi = 'TftpDynamicCommand.efi'; Pdb = 'TftpDynamicCommand.pdb' },
    @{ Id = 'var-policy'; Efi = 'varpolicy.efi'; Pdb = 'varpolicy.pdb' },
    @{ Id = 'var-policy-command'; Efi = 'VariablePolicyDynamicCommand.efi'; Pdb = 'VariablePolicyDynamicCommand.pdb' }
)
$modulesDir = Join-Path $buildDir 'modules'
New-Item -ItemType Directory -Force -Path $modulesDir | Out-Null
foreach ($module in $moduleDefinitions) {
    $moduleEfi = Join-Path $shellOutput $module.Efi
    $modulePdb = Get-ChildItem -LiteralPath $shellOutput -Filter $module.Pdb -File -Recurse |
        Select-Object -First 1
    if (-not (Test-Path -LiteralPath $moduleEfi -PathType Leaf) -or $null -eq $modulePdb) {
        throw "EDK2 module or PDB missing for $($module.Id)."
    }
    $moduleDir = Join-Path $modulesDir $module.Id
    New-Item -ItemType Directory -Force -Path $moduleDir | Out-Null
    Copy-Item -LiteralPath $moduleEfi -Destination (Join-Path $moduleDir $module.Efi)
    Copy-Item -LiteralPath $modulePdb.FullName -Destination (Join-Path $moduleDir $module.Pdb)
}

Write-Host ""
Write-Host "Built EDK2 reference: $(Join-Path $buildDir 'Shell.efi')"
Write-Host "Symbol files copied: $($symbolCandidates.Count)"
Write-Host "Additional production EDK2 modules copied: $($moduleDefinitions.Count)"
