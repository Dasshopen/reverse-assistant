[CmdletBinding()]
param([switch]$IncludeHistory)

# Read-only, heuristic publication check. Never print matching secret values.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repository = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
Push-Location $repository
try {
    $candidateFiles = @(& git ls-files --cached --others --exclude-standard) | Sort-Object -Unique
    if ($LASTEXITCODE -ne 0) { throw 'Unable to list publication candidates.' }
    $patterns = [ordered]@{
        'provider token' = '(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{35,}|sk-(?:proj-|ant-)?[A-Za-z0-9_-]{24,}|xox[baprs]-[A-Za-z0-9-]{20,})'
        'private key' = '-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'
        'credentials in URL' = 'https?://[^\s/:@]+:[^\s/@]+@'
        'literal credential assignment' = '(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|authorization)\s*["'']?\s*[:=]\s*["''][^"''\r\n]{8,}["'']'
    }
    $findings = 0
    $scanned = 0
    foreach ($relativePath in $candidateFiles) {
        $normalized = $relativePath.Replace('\', '/')
        $blocked = $normalized -match '(^|/)(\.claude|\.codex|\.aws|\.ssh|test-binaries|ghidra-analysis|analysis-results)/' -or
            $normalized -match '(^|/)(ai_providers|ghidra-installation|credentials)\.json$' -or
            ($normalized -match '(^|/)\.env($|\.)' -and $normalized -notmatch '(^|/)\.env\.example$') -or
            $normalized -match '(?i)\.(exe|dll|elf|efi|bin|zip|mv\.db|pem|key|p12|pfx|log|dmp|stackdump|bak)$'
        if ($blocked) {
            Write-Output "REVIEW local/private/binary artifact: $relativePath"
            $findings++
            continue
        }
        if (-not (Test-Path -LiteralPath $relativePath -PathType Leaf)) { continue }
        # Icons are intentional binary assets, not text files.
        if ($normalized -match '(?i)\.(png|jpg|jpeg|gif|ico|icns|woff2?|pdf)$') { continue }
        $lineNumber = 0
        foreach ($line in [System.IO.File]::ReadLines((Join-Path $repository $relativePath))) {
            $lineNumber++
            foreach ($kind in $patterns.Keys) {
                if ($line -match $patterns[$kind]) {
                    Write-Output ('REVIEW {0}:{1} [{2}]' -f $relativePath, $lineNumber, $kind)
                    $findings++
                }
            }
        }
        $scanned++
    }
    if ($IncludeHistory) {
        # Git -G uses extended POSIX expressions, not .NET regex syntax.
        $historyPattern = 'AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{35,}|sk-(proj-|ant-)?[A-Za-z0-9_-]{24,}|xox[baprs]-[A-Za-z0-9-]{20,}|-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'
        $historyHits = @(& git log --all '--format=%h' --name-only -G $historyPattern)
        if ($LASTEXITCODE -ne 0) { throw 'Unable to inspect Git history.' }
        if ($historyHits.Count -gt 0) {
            Write-Output 'REVIEW historical signature matches (commits/paths only):'
            $historyHits | Where-Object { $_ } | Write-Output
            $findings++
        }
    }
    Write-Output "Checked $scanned text candidates; $findings finding(s). No secret values printed."
    Write-Output 'Heuristic only: review staged changes, author identity and redistribution rights separately.'
    if ($findings -gt 0) { exit 1 }
}
finally {
    Pop-Location
}
