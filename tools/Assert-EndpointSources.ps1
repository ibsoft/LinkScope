# Build input preflight (also used by Build.cmd). Checks do not execute application code.
param([string]$CompileList)
$ErrorActionPreference = 'Stop'
try {
    $root = Split-Path -Parent $PSScriptRoot
    $src = Join-Path $root 'src'
    $manifest = Join-Path $PSScriptRoot 'RequiredSources.txt'
    if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { throw 'Missing tools\RequiredSources.txt. Restore the complete current project.' }
    $required = @([IO.File]::ReadAllLines($manifest) | Where-Object { $_.Trim().Length -gt 0 })
    if ($required.Count -eq 0) { throw 'The required source manifest is empty.' }
    $missing = @($required | Where-Object { -not (Test-Path -LiteralPath (Join-Path $src $_) -PathType Leaf) })
    if ($missing.Count -gt 0) { throw ('Missing required C# source file(s): ' + ($missing -join ', ')) }
    $sourceFiles = @(Get-ChildItem -LiteralPath $src -Filter '*.cs' -File)
    if ($CompileList) {
        if (-not [IO.Path]::IsPathRooted($CompileList)) { $CompileList = Join-Path $root $CompileList }
        if (-not (Test-Path -LiteralPath $CompileList -PathType Leaf)) { throw 'MSBuild did not write its evaluated compiler input list.' }
        # Item identities may be relative or absolute; resolve relative paths against the
        # actual project, not the PowerShell caller's current directory. No metadata transform.
        $actual = @([IO.File]::ReadAllLines($CompileList) | ForEach-Object {
            $entry = $_.Trim().Trim('"')
            if ($entry.Length -gt 0) {
                if (-not [IO.Path]::IsPathRooted($entry)) { $entry = Join-Path $root $entry }
                [IO.Path]::GetFullPath($entry)
            }
        })
        $problems = @()
        foreach ($file in $sourceFiles) {
            $expectedPath = [IO.Path]::GetFullPath($file.FullName)
            $count = @($actual | Where-Object { [string]::Equals($_, $expectedPath, [StringComparison]::OrdinalIgnoreCase) }).Count
            if ($count -ne 1) { $problems += ($file.Name + ' (actual inclusion count: ' + $count + ')') }
        }
        if ($problems.Count -gt 0) {
            Write-Host ('Compiler input list: ' + $CompileList)
            Write-Host ('Total compiler items: ' + $actual.Count)
            throw ('MSBuild source mismatch: ' + ($problems -join ', ') + '. Inspect the refreshed compiler input list and project path.')
        }
    }
    $engine = [IO.File]::ReadAllText((Join-Path $src 'EndpointProtection.cs'))
    $response = [IO.File]::ReadAllText((Join-Path $src 'EndpointResponse.cs'))
    $accounts = [IO.File]::ReadAllText((Join-Path $src 'UserAccounts.cs'))
    $access = [IO.File]::ReadAllText((Join-Path $src 'Access.cs'))
    $web = [IO.File]::ReadAllText((Join-Path $src 'Web.cs'))
    $marker = '// Endpoint source layout: split-response-v2'
    if (-not $engine.Contains($marker) -or -not $response.Contains($marker)) {
        throw 'EndpointProtection.cs and EndpointResponse.cs are from different or older releases.'
    }
    if ($engine -notmatch '(?m)^\s*internal\s+sealed\s+class\s+EndpointProtection\b' -or
        $engine -match '(?m)^\s*(?:internal\s+)?(?:static\s+|sealed\s+)?class\s+Endpoint(?:Response|Writer)\b' -or
        $response -notmatch '(?m)^\s*namespace\s+LinkScope\s*\{' -or
        $response -notmatch '(?m)^\s*internal\s+static\s+class\s+EndpointResponse\b' -or
        $response -notmatch '(?m)^\s*internal\s+sealed\s+class\s+EndpointWriter\b') {
        throw 'Endpoint response declarations are missing, duplicated or misplaced.'
    }
    if ($accounts -notmatch '(?m)^\s*namespace\s+LinkScope\s*\{' -or
        $accounts -notmatch '(?m)^\s*internal\s+sealed\s+class\s+UserAccounts\b' -or
        $accounts -notmatch '(?m)^\s*public\s+sealed\s+class\s+UserInput\b' -or
        $access -notmatch '\breadonly\s+UserAccounts\s+Users\b' -or
        $web -notmatch '\bDecode<UserInput>\(') {
        throw 'UserAccounts.cs, Access.cs and Web.cs do not contain the current user-management implementation. Restore them together.'
    }
    # Ensure no duplicate copies of these security-critical classes were placed in src.
    $all = ($sourceFiles | ForEach-Object { [IO.File]::ReadAllText($_.FullName) }) -join "`n"
    foreach ($type in @('EndpointResponse','EndpointWriter','UserAccounts','UserInput')) {
        $pattern = '(?m)^\s*(?:(?:public|internal|private|protected|static|sealed|abstract|partial)\s+)*class\s+' + $type + '\b'
        if ([regex]::Matches($all,$pattern).Count -ne 1) { throw ('Missing or duplicate class: ' + $type) }
    }
    Write-Host ('LinkScope source preflight passed: ' + $sourceFiles.Count + ' C# files; endpoint response and user-management types present.')
    if ($CompileList) { Write-Host ('MSBuild evaluated inputs verified: ' + $CompileList) }
    Write-Host ('Project root: ' + $root)
    exit 0
} catch {
    Write-Host ('ERROR: ' + $_.Exception.Message)
    Write-Host 'Use a complete, current source tree. Close Visual Studio, reload the correct solution, and rebuild.'
    exit 1
}
