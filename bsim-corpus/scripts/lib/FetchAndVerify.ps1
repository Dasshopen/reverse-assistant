# Downloads a manifest-tracked source archive if not already present, and
# verifies its SHA-256 against the hash already pinned in the manifest.
# A missing hash is refused rather than trusted-on-first-download: silently
# recording whatever the first download produced would mean a single
# compromised/MITM'd download poisons the pin nobody ever independently
# checked. Pin the hash in manifest.json yourself (after verifying it
# through an independent channel) before running this.
function Get-VerifiedSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,

        [Parameter(Mandatory = $true)]
        [string]$LibraryName,

        [Parameter(Mandatory = $true)]
        [string]$SourcesDir
    )

    $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    $entries = @($manifest.libraries)
    if ($null -ne $manifest.build_tools) {
        $entries += @($manifest.build_tools)
    }
    $entry = $entries | Where-Object { $_.name -eq $LibraryName }

    if ($null -eq $entry) {
        throw "No manifest entry found for library '$LibraryName' in $ManifestPath"
    }

    if ([string]::IsNullOrWhiteSpace($entry.sha256)) {
        throw "No SHA-256 is pinned for '$($entry.name)' in $ManifestPath. Pin a hash you have verified through an independent channel before downloading -- this script will not trust an unpinned first download."
    }

    if (-not (Test-Path -LiteralPath $SourcesDir -PathType Container)) {
        New-Item -ItemType Directory -Force -Path $SourcesDir | Out-Null
    }

    $archivePath = Join-Path $SourcesDir $entry.archive_name

    if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
        Write-Host "Downloading $($entry.name) $($entry.version) from $($entry.source_url)..."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $entry.source_url -OutFile $archivePath -UseBasicParsing
    }

    $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()

    if ($entry.sha256.ToLowerInvariant() -ne $actualHash) {
        throw "SHA-256 mismatch for $($entry.name): expected $($entry.sha256), got $actualHash. The downloaded archive may be corrupted or tampered with."
    }

    Write-Host "$($entry.name) archive hash verified: $actualHash"

    return $archivePath
}
