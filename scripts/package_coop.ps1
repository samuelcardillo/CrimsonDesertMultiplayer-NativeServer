# Builds the co-op test kit: dist\cdmp-coop-<date>[-<suffix>].zip with the launcher, the ASI loader, the mod, the
# host's and the guest's configs, and the instructions.
#
#   .\scripts\package_coop.ps1                      # uses the RelWithDebInfo build
#   .\scripts\package_coop.ps1 -Suffix 3663-v23     # dist\cdmp-coop-<date>-3663-v23
#
# package.txt in the kit is what cdmp_launcher.exe reads (docs/LAUNCHER.md): the kit's id, the game build it is for
# and the SHA-256 of the four files the launcher installs. The game build is the one installed on this PC (the one
# the kit was tested with); -Game '1.0.0.3663=0x6AF5D198' says another, and can be given more than once.

param(
    [ValidateSet('Debug', 'Release', 'RelWithDebInfo')]
    [string]$Config = 'RelWithDebInfo',
    [string]$Suffix = '',
    [string]$OutDir = '',
    [string]$GameDir = $(if ($env:CDMP_GAME_DIR) { $env:CDMP_GAME_DIR } else { 'D:\SteamLibrary\steamapps\common\Crimson Desert\bin64' }),
    [string[]]$Game = @()
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$bin = Join-Path $root "build\bin\$Config"
foreach ($f in 'cdmp.asi', 'cdmp_launcher.exe') {
    if (-not (Test-Path (Join-Path $bin $f))) { throw "Build first: $f not found in $bin" }
}

# The game build(s) this kit is for: "<version> 0x<PE timestamp>".
$games = @()
foreach ($g in $Game) {
    if ($g -notmatch '^([0-9.]+)=(0x[0-9A-Fa-f]{1,8})$') { throw "-Game must look like 1.0.0.3663=0x6AF5D198 (got '$g')" }
    $games += "$($Matches[1]) $($Matches[2])"
}
if (-not $games) {
    $exe = Join-Path $GameDir 'CrimsonDesert.exe'
    if (-not (Test-Path -LiteralPath $exe)) { throw "CrimsonDesert.exe not found in $GameDir; say the game build with -Game" }
    $stream = [IO.File]::Open($exe, 'Open', 'Read', 'ReadWrite')
    try {
        $head = New-Object byte[] 4096
        [void]$stream.Read($head, 0, 4096)
    } finally { $stream.Dispose() }
    $pe = [BitConverter]::ToUInt32($head, [BitConverter]::ToInt32($head, 0x3C) + 8)
    $v = (Get-Item -LiteralPath $exe).VersionInfo
    $games += ('{0}.{1}.{2}.{3} 0x{4:X8}' -f $v.FileMajorPart, $v.FileMinorPart, $v.FileBuildPart, $v.FilePrivatePart, $pe)
}

$stamp = Get-Date -Format 'yyyyMMdd'
$name = "cdmp-coop-$stamp" + $(if ($Suffix) { "-$Suffix" } else { '' })
if ($name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') { throw "the kit's name '$name' must be letters, digits, '.', '_' or '-'" }
if (-not $OutDir) { $OutDir = Join-Path $root 'dist' }
$staging = Join-Path $OutDir $name
if (Test-Path $staging) { Remove-Item -Recurse -Force $staging }
New-Item -ItemType Directory -Force $staging | Out-Null

$loader = Join-Path $root 'third_party\ultimate-asi-loader\v9.7.4\dinput8.dll'
if (-not (Test-Path $loader)) { throw 'Ultimate ASI Loader not found: see third_party\ultimate-asi-loader\README.md' }
Copy-Item $loader (Join-Path $staging 'winmm.dll')
Copy-Item (Join-Path $bin 'cdmp.asi') $staging
# Two profiles; cdmp.ini starts as the guest's (the host renames theirs, or the launcher writes it).
Copy-Item (Join-Path $root 'kit\coop\cdmp.ini.host') $staging
Copy-Item (Join-Path $root 'kit\coop\cdmp.ini.guest') $staging
Copy-Item (Join-Path $root 'kit\coop\cdmp.ini.guest') (Join-Path $staging 'cdmp.ini')
Copy-Item (Join-Path $root 'kit\coop\README.txt') $staging
# The launcher, and where it looks for newer kits (empty unless kit\coop\cdmp_launcher.ini says one).
Copy-Item (Join-Path $bin 'cdmp_launcher.exe') $staging
Copy-Item (Join-Path $root 'kit\coop\cdmp_launcher.ini') $staging
# Keeping the progress (README, section 6): both run with the game closed.
Copy-Item (Join-Path $root 'tools\scripts\apply-guest-progress.ps1') $staging
Copy-Item (Join-Path $root 'scripts\host_save_restore.ps1') $staging

# What the launcher installs, with each file's SHA-256 (the launcher refuses a file that does not match).
$package = @('; Crimson Desert Multiplayer: this kit, as cdmp_launcher.exe reads it. Do not edit.', '[package]', "id=$name")
foreach ($g in $games) { $package += "game=$g" }
foreach ($f in 'winmm.dll', 'cdmp.asi', 'cdmp.ini.host', 'cdmp.ini.guest') {
    $package += 'file={0} {1}' -f $f, (Get-FileHash (Join-Path $staging $f) -Algorithm SHA256).Hash.ToLower()
}
$package | Set-Content -Encoding ascii (Join-Path $staging 'package.txt')

Get-ChildItem $staging -File | Where-Object Name -ne 'SHA256.txt' | ForEach-Object {
    '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name
} | Set-Content -Encoding ascii (Join-Path $staging 'SHA256.txt')

$zip = "$staging.zip"
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $zip
Write-Host "Co-op kit: $zip ($([math]::Round((Get-Item $zip).Length / 1KB)) KB) for game $($games -join ', ')"
