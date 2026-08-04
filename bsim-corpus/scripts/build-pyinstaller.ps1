[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptDir = $PSScriptRoot
$corpusRoot = Split-Path $scriptDir -Parent
$manifestPath = Join-Path $corpusRoot "manifest.json"
$sourcesDir = Join-Path $corpusRoot "sources"
$buildRoot = Join-Path $corpusRoot "build\pyinstaller"
$portableToolsDir = Join-Path $corpusRoot "build\portable-tools"
$pythonRoot = Join-Path $portableToolsDir "python-3.12.10"
$pythonExe = Join-Path $pythonRoot "python.exe"

. (Join-Path $scriptDir "lib\FetchAndVerify.ps1")

# Waf performs its own target-aware MSVC discovery through vcvarsall. It only
# needs vswhere.exe to be discoverable by the nested batch file. Importing a
# complete vcvars environment here would both force one architecture's LIB
# path onto the other and make PATH grow on every version until cmd.exe hits
# its command-line limit.
$vsInstallerDir = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer"
$vswhere = Join-Path $vsInstallerDir "vswhere.exe"
if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
    throw "vswhere.exe was not found; install Visual Studio Build Tools with the C++ workload."
}
if (($env:Path -split ';') -notcontains $vsInstallerDir) {
    $env:Path = "$vsInstallerDir;$env:Path"
}
$vsInstallPath = & $vswhere `
    -products '*' `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath `
    -latest
if ([string]::IsNullOrWhiteSpace($vsInstallPath)) {
    throw "No Visual Studio installation with the C++ x86/x64 workload was found."
}
$msvcVersion = Get-ChildItem -LiteralPath (Join-Path $vsInstallPath "VC\Tools\MSVC") -Directory |
    Sort-Object { [version]$_.Name } -Descending |
    Select-Object -First 1 -ExpandProperty Name

if (-not (Test-Path -LiteralPath $pythonExe -PathType Leaf)) {
    $pythonArchive = Get-VerifiedSource `
        -ManifestPath $manifestPath `
        -LibraryName "python-embed" `
        -SourcesDir $sourcesDir
    New-Item -ItemType Directory -Force -Path $pythonRoot | Out-Null
    Expand-Archive -LiteralPath $pythonArchive -DestinationPath $pythonRoot -Force
}

if (-not (Test-Path -LiteralPath $pythonExe -PathType Leaf)) {
    throw "Portable Python was not found after extraction: $pythonExe"
}

$versions = @(
    (Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json).libraries |
        Where-Object { $_.name -like "pyinstaller-*" } |
        ForEach-Object { $_.version }
)
if ($versions.Count -eq 0) {
    throw "No PyInstaller reference is pinned in manifest.json."
}
$architectures = @(
    @{ Waf = "32bit"; Output = "Windows-32bit-intel"; Id = "x86" },
    @{ Waf = "64bit"; Output = "Windows-64bit-intel"; Id = "x64" }
)
$bootloaders = @("run.exe", "run_d.exe", "runw.exe", "runw_d.exe")

New-Item -ItemType Directory -Force -Path $buildRoot | Out-Null

foreach ($version in $versions) {
    $manifestName = "pyinstaller-$version"
    $archivePath = Get-VerifiedSource `
        -ManifestPath $manifestPath `
        -LibraryName $manifestName `
        -SourcesDir $sourcesDir
    $sourceRoot = Join-Path $sourcesDir $manifestName

    $wafPath = Join-Path $sourceRoot "bootloader\waf"
    if (-not (Test-Path -LiteralPath $wafPath -PathType Leaf)) {
        if (Test-Path -LiteralPath $sourceRoot -PathType Container) {
            Remove-Item -LiteralPath $sourceRoot -Recurse -Force
        }

        # The sdist contains unrelated test fixtures whose extended Windows
        # paths are rejected by bsdtar in recent releases. Only these two
        # trees participate in the bootloader build/output, so extracting
        # them explicitly is both safer and substantially smaller.
        & tar.exe -xf $archivePath -C $sourcesDir `
            "$manifestName/bootloader" `
            "$manifestName/PyInstaller/bootloader" `
            "$manifestName/PyInstaller/_shared_with_waf.py"
        if ($LASTEXITCODE -ne 0) {
            throw "tar.exe failed to extract $manifestName"
        }
    }

    # PyInstaller 6.21's wscript imports this sibling helper. Accommodate a
    # source tree left by an older interrupted run of this script as well.
    $sharedWafHelper = Join-Path $sourceRoot "PyInstaller\_shared_with_waf.py"
    if (-not (Test-Path -LiteralPath $sharedWafHelper -PathType Leaf)) {
        & tar.exe -xf $archivePath -C $sourcesDir "$manifestName/PyInstaller/_shared_with_waf.py"
        if ($LASTEXITCODE -ne 0) {
            throw "tar.exe failed to extract PyInstaller's shared Waf helper for $manifestName"
        }
    }

    $bootloaderRoot = Join-Path $sourceRoot "bootloader"
    $waf = Join-Path $bootloaderRoot "waf"
    if (-not (Test-Path -LiteralPath $waf -PathType Leaf)) {
        throw "PyInstaller bootloader build script was not found: $waf"
    }

    foreach ($architecture in $architectures) {
        $outputDir = Join-Path $sourceRoot "PyInstaller\bootloader\$($architecture.Output)"
        $destinationDir = Join-Path $buildRoot "$version-$($architecture.Id)"
        $buildInfo = @(
            "PyInstaller=$version",
            "Architecture=$($architecture.Id)",
            "TargetArch=$($architecture.Waf)",
            "VisualStudio=$vsInstallPath",
            "MSVCToolset=$msvcVersion",
            "SourceSha256=$((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant())"
        )

        $expectedArtifacts = @(
            $bootloaders | ForEach-Object {
                Join-Path $destinationDir $_
                Join-Path $destinationDir ([System.IO.Path]::ChangeExtension($_, ".pdb"))
            }
        )
        if (@($expectedArtifacts | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Leaf) }).Count -eq 0) {
            Set-Content -LiteralPath (Join-Path $destinationDir "build-info.txt") -Value $buildInfo -Encoding UTF8
            Write-Host "PyInstaller $version $($architecture.Id) reference bootloaders already exist; skipping build."
            continue
        }

        if (Test-Path -LiteralPath $destinationDir) {
            Remove-Item -LiteralPath $destinationDir -Recurse -Force
        }
        New-Item -ItemType Directory -Force -Path $destinationDir | Out-Null

        # CL/LINK inject symbol generation without changing PyInstaller's
        # production optimization profile. A single build job avoids several
        # linker instances racing on MSVC's default compiler PDB.
        $previousCompilerOptions = ${env:_CL_}
        $previousLinkerOptions = ${env:_LINK_}
        try {
            # CL and LINK themselves are compiler executable overrides in
            # Waf. Their underscored MSVC counterparts append options without
            # hiding cl.exe/link.exe from compiler discovery.
            ${env:_CL_} = "/Z7 /GL-"
            ${env:_LINK_} = "/DEBUG:FULL /INCREMENTAL:NO"
            Push-Location $bootloaderRoot
            try {
                & $pythonExe $waf distclean
                if ($LASTEXITCODE -ne 0) {
                    throw "PyInstaller $version distclean failed"
                }
                & $pythonExe $waf all "--target-arch=$($architecture.Waf)" --jobs=1
                if ($LASTEXITCODE -ne 0) {
                    throw "PyInstaller $version $($architecture.Id) bootloader build failed"
                }
            }
            finally {
                Pop-Location
            }
        }
        finally {
            ${env:_CL_} = $previousCompilerOptions
            ${env:_LINK_} = $previousLinkerOptions
        }

        foreach ($bootloader in $bootloaders) {
            $binary = Join-Path $outputDir $bootloader
            if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
                throw "Expected PyInstaller bootloader was not produced: $binary"
            }

            Copy-Item -LiteralPath $binary -Destination (Join-Path $destinationDir $bootloader)
            # Waf keeps linker PDBs in bootloader/build/<variant>, while it
            # copies only the executable to PyInstaller/bootloader/<platform>.
            # Resolve by basename immediately: the following architecture's
            # distclean removes the current build tree.
            $pdbName = [System.IO.Path]::ChangeExtension($bootloader, ".pdb")
            $pdbCandidates = @(
                Get-ChildItem -LiteralPath (Join-Path $bootloaderRoot "build") `
                    -Filter $pdbName -File -Recurse -ErrorAction SilentlyContinue
            )
            if ($pdbCandidates.Count -ne 1) {
                throw "Expected exactly one PDB named $pdbName for $version $($architecture.Id); found $($pdbCandidates.Count)."
            }
            Copy-Item -LiteralPath $pdbCandidates[0].FullName -Destination (Join-Path $destinationDir $pdbName)
        }

        Set-Content -LiteralPath (Join-Path $destinationDir "build-info.txt") -Value $buildInfo -Encoding UTF8
        Write-Host "Built PyInstaller $version $($architecture.Id) reference bootloaders: $destinationDir"
    }
}
