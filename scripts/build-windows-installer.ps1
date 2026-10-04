[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$GhidraInstallDir
)

# Maintainer-only packaging. Customers do not run this script.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repository = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$ghidraDirectory = (Resolve-Path -LiteralPath $GhidraInstallDir).Path
$extensionDirectory = Join-Path $repository 'ghidra-extension\ReverseAssistantExporter'
$corpus = Join-Path $repository 'bsim-corpus\build\reverse-assistant-seed.mv.db'
$assets = Join-Path $repository '.release-assets'
$gradle = Join-Path $ghidraDirectory 'support\gradle\gradlew.bat'
if (-not (Test-Path -LiteralPath $corpus -PathType Leaf)) {
    throw 'Generate and verify the BSim corpus before packaging.'
}
if (-not (Test-Path -LiteralPath $gradle -PathType Leaf)) {
    throw 'Select a Ghidra installation containing the Gradle wrapper.'
}
[void](New-Item -ItemType Directory -Path $assets -Force)
Push-Location $repository
$originalPackagingRustFlags = $env:RUSTFLAGS
try {
    $extensionBuildStarted = (Get-Date).AddSeconds(-2)
    & $gradle -p $extensionDirectory "-PGHIDRA_INSTALL_DIR=$ghidraDirectory" clean buildExtension --rerun-tasks
    if ($LASTEXITCODE -ne 0) { throw 'Extension build failed.' }
    $archives = @(Get-ChildItem -LiteralPath (Join-Path $extensionDirectory 'dist') -Filter '*.zip' -File |
        Where-Object { $_.LastWriteTime -ge $extensionBuildStarted })
    if ($archives.Count -ne 1) { throw 'Expected exactly one freshly built extension archive.' }
    $packagedExtension = Join-Path $assets 'ReverseAssistantExporter.zip'
    Copy-Item -LiteralPath $archives[0].FullName -Destination $packagedExtension -Force
    $checksum = (Get-FileHash -LiteralPath $packagedExtension -Algorithm SHA256).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllText((Join-Path $assets 'ReverseAssistantExporter.sha256'), $checksum)

    $packagedCorpus = Join-Path $assets 'reverse-assistant-seed.mv.db'
    Copy-Item -LiteralPath $corpus -Destination $packagedCorpus -Force
    $h2Jar = @(Get-ChildItem -LiteralPath (Join-Path $ghidraDirectory 'Ghidra\Features\BSim\lib') -Filter 'h2-*.jar' -File)
    if ($h2Jar.Count -ne 1) { throw 'Expected one Ghidra H2 library.' }
    $corpusBase = Join-Path $assets 'reverse-assistant-seed'
    & java -cp $h2Jar[0].FullName (Join-Path $PSScriptRoot 'SanitizeReleaseCorpus.java') $corpusBase
    if ($LASTEXITCODE -ne 0) { throw 'Corpus metadata sanitization failed.' }
    # Exercise Ghidra's result deserializer, not just the H2 schema: repository
    # values have semantic URL constraints that SQL alone cannot validate.
    $queryMarker = Join-Path $assets ('query-' + [guid]::NewGuid().ToString('N') + '.ok')
    $referenceProject = Join-Path $repository 'bsim-corpus\build\ghidra-projects\zlib'
    if (-not (Test-Path -LiteralPath (Join-Path $referenceProject 'zlib.gpr'))) {
        throw 'The analyzed zlib reference project is required for the packaging smoke test.'
    }
    $queryUrl = 'file:/' + $corpusBase.Replace('\', '/')
    $queryOutput = & (Join-Path $ghidraDirectory 'support\analyzeHeadless.bat') $referenceProject zlib `
        -process zlib1.dll -readOnly -noanalysis -scriptPath (Join-Path $repository 'bsim-corpus\scripts') `
        -postScript VerifyBsimQuery.java $queryUrl $queryMarker 2>&1
    $queryExitCode = $LASTEXITCODE
    [System.IO.File]::WriteAllLines((Join-Path $assets 'corpus-query.log'), [string[]]$queryOutput)
    if ($queryExitCode -ne 0 -or -not (Test-Path -LiteralPath $queryMarker -PathType Leaf)) {
        throw 'Packaged corpus query failed. Inspect .release-assets/corpus-query.log.'
    }

    $manifest = Get-Content -LiteralPath 'bsim-corpus\manifest.json' -Raw | ConvertFrom-Json
    $notices = [System.Text.StringBuilder]::new()
    [void]$notices.AppendLine('Reverse Assistant - Third-party notices')
    [void]$notices.AppendLine('Application source: MIT. Tools and reference data retain their own licenses.')
    [void]$notices.AppendLine([System.IO.File]::ReadAllText((Join-Path $repository 'LICENSE')))
    [void]$notices.AppendLine('Java and Ghidra are downloaded from upstream during setup; their distributions include notices.')
    [void]$notices.AppendLine('The corpus contains function signatures, not the reference executables or PDB files.')
    [void]$notices.AppendLine('MSVC runtime references were built with the local Microsoft toolchain. Review redistribution rights before release.')
    foreach ($library in $manifest.libraries) {
        [void]$notices.AppendLine("$($library.name) $($library.version): $($library.license)")
        [void]$notices.AppendLine($library.license_url)
    }
    $sourceRoot = Join-Path $repository 'bsim-corpus\sources'
    if (-not (Test-Path -LiteralPath $sourceRoot -PathType Container)) {
        throw 'Corpus source directory is required to collect upstream license notices.'
    }
    $licenseFiles = @(Get-ChildItem -LiteralPath $sourceRoot -Recurse -File |
        Where-Object { $_.Name -match '^(LICENSE|LICENCE|COPYING|NOTICE|COPYRIGHT)([._-].*)?$' })
    if ($licenseFiles.Count -eq 0) { throw 'No upstream license notices found.' }
    foreach ($licenseFile in ($licenseFiles | Sort-Object FullName)) {
        [void]$notices.AppendLine("`n--- " + $licenseFile.FullName.Substring($sourceRoot.Length + 1) + ' ---')
        [void]$notices.AppendLine([System.IO.File]::ReadAllText($licenseFile.FullName))
    }
    [System.IO.File]::WriteAllText((Join-Path $assets 'THIRD_PARTY_NOTICES.txt'), $notices.ToString())
    & npm.cmd run check
    if ($LASTEXITCODE -ne 0) { throw 'Frontend checks failed.' }
    & cargo test --manifest-path src-tauri/Cargo.toml --lib
    if ($LASTEXITCODE -ne 0) { throw 'Rust tests failed.' }
    # Hide maintainer paths in compiler-generated locations and dependency code.
    $normalizedUserProfile = $env:USERPROFILE.Replace('\', '/')
    $env:RUSTFLAGS = "$originalPackagingRustFlags --remap-path-prefix=$normalizedUserProfile=C:/build-user"
    & npm.cmd run tauri build -- --config src-tauri/tauri.release.conf.json
    if ($LASTEXITCODE -ne 0) { throw 'Installer build failed.' }
    foreach ($packagedFile in @($packagedCorpus, (Join-Path $repository 'src-tauri\target\release\reverse-assistant.exe'))) {
        $packagedBytes = [System.IO.File]::ReadAllBytes($packagedFile)
        foreach ($encoding in @([System.Text.Encoding]::UTF8, [System.Text.Encoding]::Unicode)) {
            $packagedText = $encoding.GetString($packagedBytes)
            if ($packagedText.Contains($env:USERPROFILE) -or $packagedText.Contains($normalizedUserProfile)) {
                throw 'A packaged artifact still contains a personal build-path marker. Do not publish it.'
            }
        }
    }
    $installerDirectory = Join-Path $repository 'src-tauri\target\release\bundle\nsis'
    $applicationVersion = (Get-Content -LiteralPath (Join-Path $repository 'src-tauri\tauri.conf.json') -Raw | ConvertFrom-Json).version
    $installers = @(Get-ChildItem -LiteralPath $installerDirectory -Filter "*_${applicationVersion}_x64-setup.exe" -File)
    if ($installers.Count -ne 1) { throw 'Expected exactly one Windows setup executable.' }
    $installer = $installers[0]
    $installerHash = (Get-FileHash -LiteralPath $installer.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllText((Join-Path $installerDirectory 'SHA256SUMS.txt'), "$installerHash  $($installer.Name)`n")
    Copy-Item -LiteralPath (Join-Path $assets 'THIRD_PARTY_NOTICES.txt') -Destination $installerDirectory -Force
    Write-Output "Installer prepared: $($installer.FullName)"
    Write-Output 'Release gate: validate on clean Windows and review corpus redistribution rights before publishing.'
}
finally {
    $env:RUSTFLAGS = $originalPackagingRustFlags
    Pop-Location
}
