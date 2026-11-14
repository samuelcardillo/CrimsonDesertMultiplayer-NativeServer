# Drive a Crimson Desert window for live tests. Input only goes to the window of the given PID: every send first
# checks that the foreground window belongs to it, so keys can never land in another application.
param(
    [Parameter(Mandatory)][ValidateSet('list','shot','key','click','hold','look','lmb','mmb','dclick','wheel','drag')][string]$Do,
    [int]$Dx = 0, [int]$Dy = 0, [int]$Steps = 20,
    [int]$GamePid,
    [string]$Out,
    [string]$Keys,      # space-separated virtual-key names
    [int]$HoldMs = 80,
    [int]$X, [int]$Y    # window client coordinates
)
Add-Type -AssemblyName System.Drawing
if (-not ('Native.U' -as [type])) {
Add-Type -ReferencedAssemblies System.Drawing.Common,System.Drawing.Primitives,System.Windows.Forms,System.Runtime.InteropServices,System.Collections,System.Linq,System.Console,System.Threading.Thread -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
namespace Native {
public static class U {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc f, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
  [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X, Y; }
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool ClientToScreen(IntPtr h, ref POINT p);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, int x, int y, uint d, UIntPtr e);
  [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte sc, uint f, UIntPtr e);
  [DllImport("user32.dll")] public static extern uint MapVirtualKeyW(uint c, uint t);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a, uint b, bool f);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr dc, uint flags);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetProcessDpiAwarenessContext(IntPtr c);
  public static List<IntPtr> Windows(uint want) {
    var found = new List<IntPtr>();
    EnumWindows((h, l) => { uint p; GetWindowThreadProcessId(h, out p);
      if (p == want && IsWindowVisible(h)) found.Add(h); return true; }, IntPtr.Zero);
    return found;
  }
  public static string Title(IntPtr h) { var s = new StringBuilder(256); GetWindowTextW(h, s, 256); return s.ToString(); }
  public static bool Focus(IntPtr h) {
    IntPtr fg = GetForegroundWindow(); uint dummy;
    // Already in front: send nothing. (Until 2026-11-14 an ALT tap went out on EVERY call, into the game: the character
    // kept running after a short W hold, and the other copy got the ALT when the focus changed hands.)
    if (fg == h) return true;
    uint a = GetWindowThreadProcessId(fg, out dummy), b = GetWindowThreadProcessId(h, out dummy), me = GetCurrentThreadId();
    AttachThreadInput(me, a, true); AttachThreadInput(me, b, true);
    BringWindowToTop(h); bool ok = SetForegroundWindow(h);
    if (GetForegroundWindow() != h) {
      keybd_event(0x12, 0, 0, UIntPtr.Zero); keybd_event(0x12, 0, 2, UIntPtr.Zero);  // ALT lets a background process take the foreground
      BringWindowToTop(h); ok = SetForegroundWindow(h);
    }
    AttachThreadInput(me, a, false); AttachThreadInput(me, b, false);
    return ok;
  }
}}
'@
}
[void][Native.U]::SetProcessDpiAwarenessContext([IntPtr](-4))  # per-monitor v2: real pixels for capture and clicks
$vk = @{ ENTER=0x0D; ESC=0x1B; SPACE=0x20; UP=0x26; DOWN=0x28; LEFT=0x25; RIGHT=0x27; W=0x57; A=0x41; S=0x53; D=0x44; E=0x45; F=0x46; G=0x47; H=0x48; R=0x52; Q=0x51; T=0x54; V=0x56; X=0x58; Z=0x5A; U=0x55; M=0x4D; I=0x49; J=0x4A; K=0x4B; N=0x4E; P=0x50; Y=0x59; SHIFT=0x10; LSHIFT=0xA0; ALT=0x12; CTRL=0x11; C=0x43; F8=0x77; F12=0x7B }

function Get-MainWindow([int]$procId) {
    $w = [Native.U]::Windows([uint32]$procId) | Where-Object { [Native.U]::Title($_) -match 'Crimson' } | Select-Object -First 1
    if (-not $w) { $w = [Native.U]::Windows([uint32]$procId) | Select-Object -First 1 }
    return $w
}

function Assert-Foreground([int]$procId, [IntPtr]$h) {
    [void][Native.U]::Focus($h); Start-Sleep -Milliseconds 300
    $fg = [Native.U]::GetForegroundWindow(); $p = [uint32]0
    [void][Native.U]::GetWindowThreadProcessId($fg, [ref]$p)
    if ($p -ne $procId) { throw "Foreground window belongs to PID $p, not the game ${procId}: no input sent" }
}

switch ($Do) {
    'list' {
        Get-CimInstance Win32_Process -Filter "Name='CrimsonDesert.exe'" | ForEach-Object {
            $h = Get-MainWindow $_.ProcessId
            $r = New-Object Native.U+RECT
            if ($h) { [void][Native.U]::GetClientRect($h, [ref]$r) }
            $p = New-Object Native.U+POINT
            if ($h) { [void][Native.U]::ClientToScreen($h, [ref]$p) }
            '{0} title="{1}" client={2}x{3} at ({4},{5})' -f $_.ProcessId, $(if ($h) { [Native.U]::Title($h) }), $r.R, $r.B, $p.X, $p.Y
        }
    }
    'shot' {
        $h = Get-MainWindow $GamePid
        if (-not $h) { throw "no window for $GamePid" }
        # Only ever capture the game itself: refuse if it cannot be brought to the front.
        Assert-Foreground $GamePid $h
        Start-Sleep -Milliseconds 400
        $r = New-Object Native.U+RECT; [void][Native.U]::GetClientRect($h, [ref]$r)
        $p = New-Object Native.U+POINT; [void][Native.U]::ClientToScreen($h, [ref]$p)
        $bmp = New-Object System.Drawing.Bitmap $r.R, $r.B
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen($p.X, $p.Y, 0, 0, $bmp.Size)
        if ($env:UI_CROP) { $c = $env:UI_CROP -split ','; $rc = New-Object System.Drawing.Rectangle ([int]$c[0]),([int]$c[1]),([int]$c[2]),([int]$c[3]); $part = $bmp.Clone($rc, $bmp.PixelFormat); $part.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png); $part.Dispose(); $g.Dispose(); $bmp.Dispose(); "cropped $Out"; break }
        $scale = [Math]::Min(1.0, 1100.0 / $r.R)
        $small = New-Object System.Drawing.Bitmap $bmp, ([int]($r.R * $scale)), ([int]($r.B * $scale))
        $small.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
        $g.Dispose(); $bmp.Dispose(); $small.Dispose()
        "saved $Out ($($r.R)x$($r.B))"
    }
    'key' {
        $h = Get-MainWindow $GamePid
        Assert-Foreground $GamePid $h
        foreach ($k in ($Keys -split '\s+')) {
            $c = [byte]$vk[$k]; $sc = [byte][Native.U]::MapVirtualKeyW($c, 0)
            [Native.U]::keybd_event($c, $sc, 0, [UIntPtr]::Zero); Start-Sleep -Milliseconds $HoldMs
            [Native.U]::keybd_event($c, $sc, 2, [UIntPtr]::Zero); Start-Sleep -Milliseconds 150
        }
        "sent $Keys to $GamePid"
    }
    'hold' {
        # Several keys held together for -HoldMs (walking).
        $h = Get-MainWindow $GamePid
        Assert-Foreground $GamePid $h
        $codes = ($Keys -split '\s+') | ForEach-Object { [byte]$vk[$_] }
        foreach ($c in $codes) { [Native.U]::keybd_event($c, [byte][Native.U]::MapVirtualKeyW($c, 0), 0, [UIntPtr]::Zero) }
        Start-Sleep -Milliseconds $HoldMs
        foreach ($c in $codes) { [Native.U]::keybd_event($c, [byte][Native.U]::MapVirtualKeyW($c, 0), 2, [UIntPtr]::Zero) }
        "held $Keys for $HoldMs ms on $GamePid"
    }
    'look' {
        # Relative mouse movement, spread over a few frames so the camera takes all of it.
        $h = Get-MainWindow $GamePid
        Assert-Foreground $GamePid $h
        for ($i = 0; $i -lt $Steps; $i++) {
            [Native.U]::mouse_event(1, [int]($Dx / $Steps), [int]($Dy / $Steps), 0, [UIntPtr]::Zero)
            Start-Sleep -Milliseconds 25
        }
        "looked $Dx,$Dy on $GamePid"
    }
    'wheel' {
        $h = Get-MainWindow $GamePid
        Assert-Foreground $GamePid $h
        if ($X -or $Y) {
            $p = New-Object Native.U+POINT; $p.X = $X; $p.Y = $Y
            [void][Native.U]::ClientToScreen($h, [ref]$p)
            [void][Native.U]::SetCursorPos($p.X, $p.Y); Start-Sleep -Milliseconds 150
        }
        1..$Steps | ForEach-Object { [Native.U]::mouse_event(0x0800, 0, 0, [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$Dy),0), [UIntPtr]::Zero); Start-Sleep -Milliseconds 80 }
        "wheel $Dy x $Steps on $GamePid"
    }
    'drag' {
        $h = Get-MainWindow $GamePid
        Assert-Foreground $GamePid $h
        if ($X -or $Y) {
            $p = New-Object Native.U+POINT; $p.X = $X; $p.Y = $Y
            [void][Native.U]::ClientToScreen($h, [ref]$p)
            [void][Native.U]::SetCursorPos($p.X, $p.Y); Start-Sleep -Milliseconds 150
        }
        [Native.U]::mouse_event(2, 0, 0, 0, [UIntPtr]::Zero); Start-Sleep -Milliseconds 120
        1..$Steps | ForEach-Object { [Native.U]::mouse_event(1, [int]($Dx / $Steps), [int]($Dy / $Steps), 0, [UIntPtr]::Zero); Start-Sleep -Milliseconds 25 }
        Start-Sleep -Milliseconds 120; [Native.U]::mouse_event(4, 0, 0, 0, [UIntPtr]::Zero)
        "dragged $Dx,$Dy on $GamePid"
    }
    'lmb' {
        # A press of the left button with no cursor move (an attack in the world).
        $h = Get-MainWindow $GamePid
        Assert-Foreground $GamePid $h
        [Native.U]::mouse_event(2, 0, 0, 0, [UIntPtr]::Zero); Start-Sleep -Milliseconds $HoldMs
        [Native.U]::mouse_event(4, 0, 0, 0, [UIntPtr]::Zero)
        "left button for $HoldMs ms on $GamePid"
    }
    'mmb' {
        # A press of the middle button with no cursor move (focus on a named NPC).
        $h = Get-MainWindow $GamePid
        Assert-Foreground $GamePid $h
        [Native.U]::mouse_event(0x20, 0, 0, 0, [UIntPtr]::Zero); Start-Sleep -Milliseconds $HoldMs
        [Native.U]::mouse_event(0x40, 0, 0, 0, [UIntPtr]::Zero)
        "middle button for $HoldMs ms on $GamePid"
    }
    'dclick' {
        $h = Get-MainWindow $GamePid
        Assert-Foreground $GamePid $h
        $p = New-Object Native.U+POINT; $p.X = $X; $p.Y = $Y
        [void][Native.U]::ClientToScreen($h, [ref]$p)
        [void][Native.U]::SetCursorPos($p.X, $p.Y); Start-Sleep -Milliseconds 250
        foreach ($n in 1..2) { [Native.U]::mouse_event(2, 0, 0, 0, [UIntPtr]::Zero); Start-Sleep -Milliseconds 60; [Native.U]::mouse_event(4, 0, 0, 0, [UIntPtr]::Zero); Start-Sleep -Milliseconds 90 }
        "double-clicked on $GamePid"
    }
    'click' {
        $h = Get-MainWindow $GamePid
        Assert-Foreground $GamePid $h
        $p = New-Object Native.U+POINT; $p.X = $X; $p.Y = $Y
        [void][Native.U]::ClientToScreen($h, [ref]$p)
        [void][Native.U]::SetCursorPos($p.X, $p.Y); Start-Sleep -Milliseconds 200
        [Native.U]::mouse_event(2, 0, 0, 0, [UIntPtr]::Zero); Start-Sleep -Milliseconds 80
        [Native.U]::mouse_event(4, 0, 0, 0, [UIntPtr]::Zero)
        "clicked ($X,$Y) on $GamePid"
    }
}


