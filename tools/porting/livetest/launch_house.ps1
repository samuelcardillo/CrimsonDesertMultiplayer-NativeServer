# Close both copies, deploy, launch host + guest (guest waits at its title), host into the world. Prints the pids.
# Then: move the host (bash), and run_join.ps1 -Attach -AttachHost <h> -AttachGuest <g> for the guest's join.
param([string]$HostIni = '', [string]$GuestIni = '')
$ErrorActionPreference = 'Stop'
# One launcher at a time: on 2026-11-07 08:32 two ran together (a stale bash resumed an edited script) and started
# two host copies; the game closed one of them. The mutex is released when this process ends.
$launchLock = New-Object System.Threading.Mutex($false, 'Local\cdmp_two_copy_launcher')
if (-not $launchLock.WaitOne(0)) { throw 'launch failed: another launcher (launch_house/run_join) is running' }
$sp = $PSScriptRoot
$ui = Join-Path $sp 'ui.ps1'
$root = 'D:\SteamLibrary\steamapps\common\Crimson Desert\multi'
$bin = 'D:\SteamLibrary\steamapps\common\Crimson Desert\bin64'
Set-Location $root
Get-Process CrimsonDesert -ErrorAction SilentlyContinue | Stop-Process -Force
while (Get-Process CrimsonDesert -ErrorAction SilentlyContinue) { Start-Sleep -Milliseconds 500 }
Start-Sleep -Seconds 2
& .\scripts\deploy.ps1 *>&1 | Select-Object -Last 1
$cfg = Join-Path $root 'tools\porting\configs'
$out = & .\scripts\launch-2inst.ps1 -GuestSlot slot2 -HostIni $(if ($HostIni) { $HostIni } else { "$cfg\cdmp.3527-2inst-host.ini" }) -GuestIni $(if ($GuestIni) { $GuestIni } else { "$cfg\cdmp.3527-2inst-guest.ini" }) -BackupDir "$root\backups" *>&1 | Out-String
if ($out -notmatch 'Host:\s+PID (\d+)') { throw "launch failed: $($out.Substring([Math]::Max(0,$out.Length-400)))" }
$hostPid = [int]$Matches[1]
if ($out -notmatch 'Guest: PID (\d+)') { throw 'no guest pid' }
$guestPid = [int]$Matches[1]
"pids host $hostPid guest $guestPid" | Tee-Object -FilePath (Join-Path $sp 'pids.txt')
Start-Sleep -Seconds 35
$start = Get-Date; $lastPress = [datetime]::MinValue; $in = $false
while (((Get-Date) - $start).TotalSeconds -lt 240) {
    if (Select-String -Path "$bin\cdmp.host.log" -Pattern 'Local: pos' -Quiet) { $in = $true; break }
    if (-not (Get-Process -Id $hostPid -ErrorAction SilentlyContinue)) { throw "host $hostPid is gone" }
    if (((Get-Date) - $lastPress).TotalSeconds -ge 25) {
        try { & $ui -Do key -GamePid $hostPid -Keys E -HoldMs 200 | Out-Null; $lastPress = Get-Date } catch { $lastPress = (Get-Date).AddSeconds(-20) }
    }
    Start-Sleep -Seconds 2
}
"host in world: $in"
