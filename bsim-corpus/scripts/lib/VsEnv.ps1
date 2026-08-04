# Locates the installed Visual Studio Build Tools via vswhere and imports the
# x64 native tools environment (cl.exe, link.exe, INCLUDE, LIB) into the
# current PowerShell session by shelling out to vcvarsall.bat and capturing
# the resulting environment block. PowerShell has no built-in equivalent of
# sourcing a .bat file, so this is the standard workaround.
function Import-VisualStudioEnvironment {
    [CmdletBinding()]
    param(
        [ValidateSet("x86", "x64")]
        [string] $TargetArchitecture = "x64"
    )

    $vswhere = Join-Path `
        ${env:ProgramFiles(x86)} `
        "Microsoft Visual Studio\Installer\vswhere.exe"

    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
        throw "vswhere.exe was not found; install Visual Studio Build Tools with the C++ workload."
    }

    $installPath = & $vswhere `
        -products '*' `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath `
        -latest

    if ([string]::IsNullOrWhiteSpace($installPath)) {
        throw "No Visual Studio installation with the C++ x64 build tools was found."
    }

    $vcvarsall = Join-Path $installPath "VC\Auxiliary\Build\vcvarsall.bat"

    if (-not (Test-Path -LiteralPath $vcvarsall -PathType Leaf)) {
        throw "vcvarsall.bat was not found: $vcvarsall"
    }

    # vcvarsall.bat internally shells out to a bare "vswhere.exe" that isn't
    # necessarily on PATH; that failure is harmless to vcvarsall itself (it
    # still finds the toolchain via its own relative paths) but PowerShell's
    # strict mode treats any stderr from a native command as a terminating
    # error, so relax that just for this call.
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    # Keep a 64-bit host toolchain, but select libraries and headers for the
    # binary architecture. In particular, an x86 compiler with an x64 LIB
    # path links successfully only until it reaches the first Windows import.
    $vcvarsArchitecture = if ($TargetArchitecture -eq "x86") { "x64_x86" } else { "x64" }
    $envOutput = & cmd.exe /c "`"$vcvarsall`" $vcvarsArchitecture && set" 2>$null
    $ErrorActionPreference = $previousErrorActionPreference

    foreach ($line in $envOutput) {
        if ($line -match '^([^=]+)=(.*)$') {
            Set-Item -Path "env:$($Matches[1])" -Value $Matches[2]
        }
    }

    if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
        throw "cl.exe is still not on PATH after importing the VS environment."
    }
}

function Import-VisualStudioX64Environment {
    [CmdletBinding()]
    param()

    Import-VisualStudioEnvironment -TargetArchitecture "x64"
}
