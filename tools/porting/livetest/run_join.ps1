# One full live join: close both copies, deploy, launch, host into the world, guest into the world.
param([switch]$NoDeploy, [switch]$Attach, [int]$AttachHost, [int]$AttachGuest, [string]$HostIni = '', [string]$GuestIni = '')
$ErrorActionPreference = 'Stop'
$sp = $PSScriptRoot
$ui = Join-Path $sp 'ui.ps1'
$root = 'D:\SteamLibrary\steamapps\common\Crimson Desert\multi'
$bin = 'D:\SteamLibrary\steamapps\common\Crimson Desert\bin64'
Set-Location $root

if ($Attach) {
    $hostPid = $AttachHost; $guestPid = $AttachGuest
} else {
    $launchLock = New-Object System.Threading.Mutex($false, 'Local\cdmp_two_copy_launcher')
    if (-not $launchLock.WaitOne(0)) { throw 'launch failed: another launcher (launch_house/run_join) is running' }
    Get-Process CrimsonDesert -ErrorAction SilentlyContinue | Stop-Process -Force
    while (Get-Process CrimsonDesert -ErrorAction SilentlyContinue) { Start-Sleep -Milliseconds 500 }
    Start-Sleep -Seconds 2
    if (-not $NoDeploy) { & .\scripts\deploy.ps1 *>&1 | Select-Object -Last 1 }
    $cfg = Join-Path $root 'tools\porting\configs'
    # Everything the launcher and the game's console print, in all streams, so it can be searched and kept out of the way.
    $out = & .\scripts\launch-2inst.ps1 -GuestSlot slot2 -HostIni $(if ($HostIni) { $HostIni } else { "$cfg\cdmp.3527-2inst-host.ini" }) -GuestIni $(if ($GuestIni) { $GuestIni } else { "$cfg\cdmp.3527-2inst-guest.ini" }) -BackupDir "$root\backups" *>&1 | Out-String
    if ($out -notmatch 'Host:\s+PID (\d+)') { throw "launch failed: $($out.Substring([Math]::Max(0,$out.Length-400)))" }
    $hostPid = [int]$Matches[1]
    if ($out -notmatch 'Guest: PID (\d+)') { throw 'no guest pid' }
    $guestPid = [int]$Matches[1]
}
"pids host $hostPid guest $guestPid" | Tee-Object -FilePath (Join-Path $sp 'pids.txt')

function Press-Until([int]$gamePid, [string]$log, [string]$pattern, [int]$limitSec) {
    # E is Play on the title. The window may lose the foreground: keep trying until the log moves on.
    $start = Get-Date; $lastPress = [datetime]::MinValue
    while (((Get-Date) - $start).TotalSeconds -lt $limitSec) {
        if (Select-String -Path $log -Pattern $pattern -Quiet) { return $true }
        if (-not (Get-Process -Id $gamePid -ErrorAction SilentlyContinue)) { throw "PID $gamePid is gone" }
        if (((Get-Date) - $lastPress).TotalSeconds -ge 25) {
            try { & $ui -Do key -GamePid $gamePid -Keys E -HoldMs 200 | Out-Null; $lastPress = Get-Date } catch { $lastPress = (Get-Date).AddSeconds(-20) }
        }
        Start-Sleep -Seconds 2
    }
    return $false
}

Start-Sleep -Seconds 35
if (-not (Press-Until $hostPid "$bin\cdmp.host.log" 'Local: pos' 240)) { throw 'host did not reach the world' }
"host in world"
# Idle before the guest joins.
Set-Location "$root\tools\porting"
for ($i = 0; $i -lt 60; $i++) {
    $r = python read_loading_state_3527.py --pid $hostPid --out "$sp\host_state.json" 2>&1 | Out-String
    if ($r -match '"state": "0x18"') { break }
    Start-Sleep -Seconds 2
}
Set-Location $root
"host idle"
# 'connection REMOTE' already appears at the title: only the load lines prove Play was pressed.
if (-not (Press-Until $guestPid "$bin\cdmp.guest.log" 'Session2 guest load:' 240)) { throw 'guest did not start loading' }
"guest loading"
$deadline = (Get-Date).AddSeconds(240); $done = $false
while ((Get-Date) -lt $deadline) {
    if (-not (Get-Process -Id $guestPid -ErrorAction SilentlyContinue)) { "GUEST GONE"; break }
    if (-not (Get-Process -Id $hostPid -ErrorAction SilentlyContinue)) { "HOST GONE"; break }
    $s = @(Select-String -Path "$bin\cdmp.guest.log" -Pattern 'Session2 guest load: state 0x18')
    $rep = @(Select-String -Path "$bin\cdmp.guest.log" -Pattern 'Session2 guest load: state 0x11')
    if ($s.Count -and $rep.Count) { $done = $true; break }
    Start-Sleep -Seconds 3
}
"guest idle: $done"
Select-String -Path "$bin\cdmp.guest.log" -Pattern 'RemoteVisible|Session2 guest load:' | Select-Object -Last 12 | ForEach-Object { $_.Line.Substring(0,[Math]::Min(150,$_.Line.Length)) }
Select-String -Path "$bin\cdmp.host.log" -Pattern 'RemoteVisible' | Select-Object -Last 2 | ForEach-Object { $_.Line.Substring(0,[Math]::Min(180,$_.Line.Length)) }
