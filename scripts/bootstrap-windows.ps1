<#
Install the latest verified stable toolchain locally and configure CLion presets.
Versions and archive hashes are pinned in toolchain.json. No global installation.
#>
[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [switch]$IncludeMsvc
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$versions = Get-Content -LiteralPath (Join-Path $projectRoot 'toolchain.json') -Raw | ConvertFrom-Json
$dependencyDirectory = Join-Path $projectRoot '.deps'
$downloadDirectory = Join-Path $dependencyDirectory 'downloads'
$presetsPath = Join-Path $projectRoot 'CMakeUserPresets.json'
if (Test-Path -LiteralPath $presetsPath) {
    $existing = Get-Content -LiteralPath $presetsPath -Raw | ConvertFrom-Json
    if (-not $existing.vendor.'cvault/bootstrap'.generated) {
        throw 'CMakeUserPresets.json contains personal settings. See docs/development.md for manual configuration.'
    }
}
New-Item -ItemType Directory -Force -Path $downloadDirectory | Out-Null

function Get-VerifiedArchive($specification) {
    $archivePath = Join-Path $downloadDirectory $specification.file
    if (-not (Test-Path -LiteralPath $archivePath)) {
        Write-Host "Downloading $($specification.file)..."
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            try {
                Invoke-WebRequest -Uri $specification.url -OutFile $archivePath -UseBasicParsing
                break
            } catch {
                if ($attempt -eq 3) { throw }
            }
        }
    }
    if ((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash -ne $specification.sha256) {
        throw "Archive checksum mismatch: $archivePath. Nothing was extracted."
    }
    return $archivePath
}

$toolkitDirectory = Join-Path $dependencyDirectory "w64devkit-$($versions.windowsToolkit.version)"
$toolBin = Join-Path $toolkitDirectory 'w64devkit\bin'
$toolkitArchive = Get-VerifiedArchive $versions.windowsToolkit
if (-not (Test-Path -LiteralPath (Join-Path $toolBin 'gcc.exe'))) {
    New-Item -ItemType Directory -Force -Path $toolkitDirectory | Out-Null
    $sevenZip = Get-Command 7z -ErrorAction SilentlyContinue
    $sevenZipPath = Join-Path $env:ProgramFiles '7-Zip\7z.exe'
    if ($sevenZip) { $sevenZipPath = $sevenZip.Source }
    if (Test-Path -LiteralPath $sevenZipPath) {
        & $sevenZipPath x -y "-o$toolkitDirectory" $toolkitArchive
    } else {
        # The verified upstream archive is also a noninteractive self-extractor.
        & $toolkitArchive -y "-o$toolkitDirectory"
    }
    if ($LASTEXITCODE -ne 0) { throw 'Toolchain extraction failed.' }
}
$cmakeArchive = Get-VerifiedArchive $versions.cmakeWindows
$cmakeDirectory = Join-Path $dependencyDirectory "tools\cmake-$($versions.cmakeVersion)-windows-x86_64"
$cmakeBin = Join-Path $cmakeDirectory 'bin'
if (-not (Test-Path -LiteralPath (Join-Path $cmakeBin 'cmake.exe'))) {
    Expand-Archive -LiteralPath $cmakeArchive -DestinationPath (Join-Path $dependencyDirectory 'tools') -Force
}
$cmake = Join-Path $cmakeBin 'cmake.exe'
$ctest = Join-Path $cmakeBin 'ctest.exe'
$ninja = Join-Path $toolBin 'ninja.exe'
$gcc = Join-Path $toolBin 'gcc.exe'
foreach ($tool in @($cmake, $ctest, $ninja, $gcc)) {
    if (-not (Test-Path -LiteralPath $tool)) { throw "Missing tool: $tool" }
}
$gccVersion = (& $gcc -dumpfullversion | Out-String).Trim()
$ninjaVersion = (& $ninja --version | Out-String).Trim()
$cmakeInfo = (& $cmake --version | Out-String)
if ($gccVersion -ne $versions.gccVersion -or $ninjaVersion -ne $versions.ninjaVersion -or
    $cmakeInfo -notmatch ('cmake version ' + [regex]::Escape($versions.cmakeVersion) + '\s')) {
    throw 'Extracted tool versions do not match toolchain.json.'
}

# Keep each mutable upstream stable snapshot isolated by its verified hash.
$sodiumDirectory = Join-Path $dependencyDirectory ('sodium-mingw-' + $versions.sodiumWindows.sha256.Substring(0, 12))
$sodiumRoot = Join-Path $sodiumDirectory 'libsodium-win64'
$sodiumArchive = Get-VerifiedArchive $versions.sodiumWindows
if (-not (Test-Path -LiteralPath (Join-Path $sodiumRoot 'lib\libsodium.dll.a'))) {
    New-Item -ItemType Directory -Force -Path $sodiumDirectory | Out-Null
    & tar -xzf $sodiumArchive -C $sodiumDirectory
    if ($LASTEXITCODE -ne 0) { throw 'libsodium extraction failed.' }
}
$msvcSodiumRoot = $null
if ($IncludeMsvc) {
    $msvcDirectory = Join-Path $dependencyDirectory ('sodium-msvc-' + $versions.sodiumMsvc.sha256.Substring(0, 12))
    $msvcSodiumRoot = Join-Path $msvcDirectory 'libsodium'
    $msvcArchive = Get-VerifiedArchive $versions.sodiumMsvc
    if (-not (Test-Path -LiteralPath (Join-Path $msvcSodiumRoot 'x64\Release\v143\static\libsodium.lib'))) {
        Expand-Archive -LiteralPath $msvcArchive -DestinationPath $msvcDirectory -Force
    }
}

$cache = @{
    CMAKE_C_COMPILER = $gcc.Replace('\', '/')
    CMAKE_MAKE_PROGRAM = $ninja.Replace('\', '/')
    SODIUM_ROOT = $sodiumRoot.Replace('\', '/')
}
$configurePresets = @()
$buildPresets = @()
$testPresets = @()
foreach ($configuration in @('debug', 'release')) {
    $name = "windows-clion-$configuration"
    $configurePresets += @{
        name = $name
        displayName = "Windows GCC $gccVersion - $configuration"
        inherits = $configuration
        binaryDir = '${sourceDir}/build/windows-gcc-' + $gccVersion + '-' + $configuration
        cacheVariables = $cache
        environment = @{ PATH = $cmakeBin + ';' + $toolBin + ';$penv{PATH}' }
    }
    $buildPresets += @{ name = $name; configurePreset = $name }
    $testPresets += @{
        name = $name; configurePreset = $name
        output = @{ outputOnFailure = $true }
    }
}
$presets = [ordered]@{
    version = 12
    vendor = @{ 'cvault/bootstrap' = @{ generated = $true } }
    configurePresets = $configurePresets
    buildPresets = $buildPresets
    testPresets = $testPresets
}
$utf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($presetsPath, ($presets | ConvertTo-Json -Depth 10) + "`n", $utf8)
$paths = @{ binDirectory = $toolBin; cmakeBinDirectory = $cmakeBin; sodiumRoot = $sodiumRoot; msvcSodiumRoot = $msvcSodiumRoot }
[System.IO.File]::WriteAllText((Join-Path $dependencyDirectory 'paths.json'), ($paths | ConvertTo-Json) + "`n", $utf8)
Write-Host "Ready: GCC $gccVersion, CMake $($versions.cmakeVersion), Ninja $ninjaVersion."
Write-Host "CLion toolchain directory: $(Split-Path $toolBin)"
Write-Host "CLion CMake executable: $cmake"
if (-not $SkipBuild) {
    Push-Location -LiteralPath $projectRoot
    try {
        & $cmake --preset windows-clion-debug
        if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed.' }
        & $cmake --build --preset windows-clion-debug
        if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
        & $ctest --preset windows-clion-debug
        if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
    } finally {
        Pop-Location
    }
}
