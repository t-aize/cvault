# Execute the actual download function with synthetic network responses.
# No external network access or Pester dependency is required.
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$source = Join-Path $projectRoot 'scripts/bootstrap-windows.ps1'
$parseErrors = $null
$tree = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$null, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'Invalid bootstrap syntax.' }
$definition = $tree.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Get-VerifiedArchive'
}, $true)
if (-not $definition) { throw 'Missing download function.' }
. ([scriptblock]::Create($definition.Extent.Text))

$testDirectory = Join-Path ([IO.Path]::GetTempPath()) ('cvault-bootstrap-' + [guid]::NewGuid().ToString('N'))
$downloadDirectory = $testDirectory
New-Item -ItemType Directory -Path $testDirectory | Out-Null
$script:calls = 0
$script:failures = 0
$script:delays = @()
$script:payload = [byte[]](1, 2, 3, 4, 255)
function Invoke-WebRequest {
    param($Uri, $OutFile, [switch]$UseBasicParsing)
    $script:calls++
    [IO.File]::WriteAllBytes($OutFile, $script:payload)
    if ($script:calls -le $script:failures) { throw [Net.WebException]::new('Synthetic DNS failure') }
}
function Start-Sleep { param($Seconds) $script:delays += $Seconds }
function Assert-True($condition, $message) { if (-not $condition) { throw $message } }
try {
    $sample = Join-Path $testDirectory 'sample'
    [IO.File]::WriteAllBytes($sample, $script:payload)
    $digest = (Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash
    $spec = @{ file = 'archive.bin'; url = 'https://example.invalid/archive'; sha256 = $digest }
    $script:failures = 2
    $archive = Get-VerifiedArchive $spec
    Assert-True ($script:calls -eq 3) 'DNS retries did not recover.'
    Assert-True (($script:delays -join ',') -eq '2,4') 'Incorrect exponential delays.'
    Assert-True ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -eq $digest) 'Unverified archive published.'
    Assert-True (-not (Test-Path -LiteralPath "$archive.part")) 'Partial file retained.'
    $before = $script:calls
    Get-VerifiedArchive $spec | Out-Null
    Assert-True ($script:calls -eq $before) 'Valid cache accessed the network.'

    [IO.File]::WriteAllBytes($archive, [byte[]](0))
    $rejected = $false
    try { Get-VerifiedArchive $spec | Out-Null } catch { $rejected = $_.Exception.Message -match 'checksum mismatch' }
    Assert-True $rejected 'Modified cache was accepted.'
    Assert-True ($script:calls -eq $before) 'Modified cache was silently replaced.'
    Remove-Item -LiteralPath $archive

    $script:calls = 0; $script:failures = 0; $script:delays = @()
    $script:payload = [byte[]](0)
    $rejected = $false
    try { Get-VerifiedArchive $spec | Out-Null } catch { $rejected = $_.Exception.Message -match 'checksum mismatch' }
    Assert-True $rejected 'Downloaded checksum mismatch was accepted.'
    Assert-True (-not (Test-Path -LiteralPath $archive)) 'Invalid checksum was published.'
    Assert-True (-not (Test-Path -LiteralPath "$archive.part")) 'Invalid partial file retained.'

    $script:calls = 0; $script:failures = 5; $script:delays = @()
    $rejected = $false
    try { Get-VerifiedArchive $spec | Out-Null } catch { $rejected = $true }
    Assert-True $rejected 'Retry exhaustion did not fail.'
    Assert-True ($script:calls -eq 5) 'Retries were not bounded.'
    Assert-True (($script:delays -join ',') -eq '2,4,8,16') 'Incorrect retry exhaustion delays.'
    Assert-True (-not (Test-Path -LiteralPath $archive)) 'Interrupted download was published.'
    Assert-True (-not (Test-Path -LiteralPath "$archive.part")) 'Interrupted partial file retained.'
    Write-Host 'Windows bootstrap: retry recovery, bounded failures, checksums and cache publication verified.'
} finally {
    # The only recursive removal is our resolved, randomly named test directory.
    $resolvedTest = (Resolve-Path -LiteralPath $testDirectory).Path
    $resolvedParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not $resolvedTest.StartsWith($resolvedParent, [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $resolvedTest) -notlike 'cvault-bootstrap-*') { throw 'Unsafe cleanup target.' }
    Remove-Item -LiteralPath $resolvedTest -Recurse -Force
}
