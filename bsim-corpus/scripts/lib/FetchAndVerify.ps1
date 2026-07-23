# Downloads a manifest-tracked source archive if not already present, and
# verifies its SHA-256. If the manifest has no pinned hash yet for this
# library, the hash of the first successful download is recorded so future
# runs can detect corruption or tampering.
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
    $entry = $manifest.libraries | Where-Object { $_.name -eq $LibraryName }

    if ($null -eq $entry) {
        throw "No manifest entry found for library '$LibraryName' in $ManifestPath"
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

    if ([string]::IsNullOrWhiteSpace($entry.sha256)) {
        Write-Warning "No SHA-256 pinned yet for $($entry.name); recording the hash of this download: $actualHash"
        $entry.sha256 = $actualHash
        $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ManifestPath -Encoding utf8
    }
    elseif ($entry.sha256.ToLowerInvariant() -ne $actualHash) {
        throw "SHA-256 mismatch for $($entry.name): expected $($entry.sha256), got $actualHash. The downloaded archive may be corrupted or tampered with."
    }
    else {
        Write-Host "$($entry.name) archive hash verified: $actualHash"
    }

    return $archivePath
}
