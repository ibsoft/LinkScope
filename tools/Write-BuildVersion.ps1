# Produce a release-branch version from local metadata, or an explicitly enabled GitHub lookup.
# Regular GitHub merge commits retain the source branch name in the subject.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$OutputPath)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$pattern = '^v_[0-9]+\.[0-9]+\.[0-9]+(?:[-.][A-Za-z0-9]+)*$'
$version = 'unversioned'
$source = 'no release merge metadata available'
$git = Get-Command git.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
$gitPath = if ($git) { $git.Source } else { $null }
if (-not $gitPath) {
    $candidate = Join-Path $env:ProgramFiles 'Git\cmd\git.exe'
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { $gitPath = $candidate }
}
function Invoke-Git([string[]]$Arguments) {
    if (-not $gitPath) { return }
    # Git probes can fail in a source-only ZIP or shallow checkout; that is not a build failure.
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $gitPath -C $root @Arguments 2>$null
        if ($LASTEXITCODE -eq 0) { $output }
    } finally { $ErrorActionPreference = $savedPreference }
}
if ($env:LINKSCOPE_RELEASE_VERSION) {
    if ($env:LINKSCOPE_RELEASE_VERSION -cnotmatch $pattern) {
        throw 'LINKSCOPE_RELEASE_VERSION must be a release branch name, for example v_1.0.1.'
    }
    $version = $env:LINKSCOPE_RELEASE_VERSION
    $source = 'explicit release metadata'
} else {
    $top = Invoke-Git @('rev-parse','--show-toplevel') | Select-Object -First 1
    $head = $null
    # Do not derive a ZIP's version from an unrelated enclosing checkout.
    if ($top -and ([IO.Path]::GetFullPath($top).TrimEnd([char[]]@('\','/')) -ieq [IO.Path]::GetFullPath($root).TrimEnd([char[]]@('\','/')))) {
        $head = Invoke-Git @('rev-parse','--verify','HEAD') | Select-Object -First 1
    }
    # Supports squash/rebase merges when a GitHub Actions closed-PR workflow builds the merged commit.
    if ($env:GITHUB_EVENT_NAME -eq 'pull_request' -and $env:GITHUB_EVENT_PATH -and (Test-Path -LiteralPath $env:GITHUB_EVENT_PATH -PathType Leaf)) {
        try {
            $event = Get-Content -Raw -LiteralPath $env:GITHUB_EVENT_PATH | ConvertFrom-Json
            $pr = $event.pull_request
            if ($event.action -eq 'closed' -and $pr.merged -eq $true -and $pr.base.ref -eq 'main' -and $pr.head.ref -cmatch $pattern -and $head -and $pr.merge_commit_sha -eq $head) {
                $version = $pr.head.ref
                $source = 'GitHub merged pull-request metadata'
            }
        } catch { Write-Warning 'GitHub event metadata could not be read; checking local merge history.' }
    }
    # Opt-in authenticated GitHub lookup includes squash and rebase merges. No credentials are embedded in the app.
    if ($version -eq 'unversioned' -and $head -and $env:LINKSCOPE_GITHUB_VERSION_LOOKUP -eq '1') {
        try {
            $gh = Get-Command gh.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($gh) {
                Push-Location -LiteralPath $root
                try {
                    $oldPreference=$ErrorActionPreference; $ErrorActionPreference='Continue'
                    $raw = & $gh.Source pr list --state merged --base main --limit 500 --json headRefName,mergeCommit,mergedAt 2>$null
                    $ghExit = $LASTEXITCODE
                } finally { $ErrorActionPreference=$oldPreference; Pop-Location }
                if ($ghExit -eq 0 -and $raw) {
                    $prs = ($raw -join "`n") | ConvertFrom-Json
                    foreach ($pr in ($prs | Where-Object { $_.headRefName -cmatch $pattern -and $_.mergeCommit.oid -cmatch '^[0-9a-f]{40}$' -and $_.mergedAt } | Sort-Object mergedAt -Descending)) {
                        # PR must actually be included in the commit being built. Never stamp an older checkout with a newer branch.
                        & $gitPath -C $root merge-base --is-ancestor $pr.mergeCommit.oid $head 2>$null
                        if ($LASTEXITCODE -eq 0) { $version=$pr.headRefName; $source='GitHub merged PR metadata verified against build ancestry'; break }
                    }
                }
            }
        } catch { Write-Warning 'GitHub version lookup unavailable; using local metadata.' }
    }
    if ($version -eq 'unversioned' -and $head) {
        # Do not stamp a build with a newer release that is not in its own ancestry.
        # Prefer local main, then the locally fetched origin/main ref. Neither requires network access.
        $base = $null
        foreach ($ref in @('refs/heads/main','refs/remotes/origin/main')) {
            $base = Invoke-Git @('merge-base','HEAD',$ref) | Select-Object -First 1
            if ($base) { break }
        }
        if (-not $base -and $env:GITHUB_REF -eq 'refs/heads/main') { $base = $head }
        if ($base) {
            foreach ($subject in (Invoke-Git @('log','--first-parent','--merges','--format=%s',$base))) {
                $branch = $null
                if ($subject -cmatch '^Merge pull request #[0-9]+ from [^/\s]+/(v_[^\s]+)$') { $branch = $Matches[1] }
                elseif ($subject -cmatch "^Merge branch '(v_[^']+)'(?: into main)?$") { $branch = $Matches[1] }
                if ($branch -and $branch -cmatch $pattern) { $version = $branch; $source = 'latest release merge in local main ancestry'; break }
            }
        }
    }
    if ($version -eq 'unversioned') {
        $metadata = Join-Path $root 'release-version.txt'
        if (Test-Path -LiteralPath $metadata -PathType Leaf) {
            $candidate = (Get-Content -Raw -LiteralPath $metadata).Trim()
            if ($candidate -cnotmatch $pattern) { throw 'release-version.txt must contain one known merged release branch name (for example v_1.0.1).' }
            $version = $candidate; $source = 'explicit release archive metadata'
        }
    }
}
$full = [System.IO.Path]::GetFullPath($OutputPath)
[System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($full)) | Out-Null
# Preserve the file timestamp on unchanged versions to avoid needless recompilation.
if (-not [System.IO.File]::Exists($full) -or [System.IO.File]::ReadAllText($full) -cne $version) {
    [System.IO.File]::WriteAllText($full, $version, ([System.Text.UTF8Encoding]::new($false)))
}
Write-Host "LinkScope build version: $version ($source)"
