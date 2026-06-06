# Pagefile Parasites

Lab-safe demonstration of **section-backed payload execution** for internal BAS
presentations.

This version is intentionally constrained: it demonstrates a minimal PE32+
manual mapping flow for a benign stub payload, with clear validation and failure
messages. It does not claim stealth or evasion properties.

## What It Demonstrates

- Creates a pagefile-backed section sized to `OptionalHeader.SizeOfImage`.
- Maps that section into the local process and a suspended target process.
- Builds a PE in-memory image layout instead of copying the raw on-disk file:
  - copies headers to image base offset `0`;
  - copies each section from `PointerToRawData` to `VirtualAddress`;
  - leaves BSS/zero-fill areas zeroed when `VirtualSize > SizeOfRawData`;
  - validates section bounds against `SizeOfImage`.
- Queues execution to `RemoteBase + AddressOfEntryPoint`.
- Defaults the target process to `C:\Windows\System32\notepad.exe`, configurable
  with `-TargetBinary`.

## Usage

Validate only, without process creation:

```powershell
.\pagefile_parasites.ps1 -PayloadPath .\payload.exe -ValidateOnly
```

Run the lab demo:

```powershell
.\pagefile_parasites.ps1 -PayloadPath .\payload.exe -TargetBinary C:\Windows\System32\notepad.exe
```

## Payload Contract

This is **minimal PE manual mapping**, not shellcode execution and not a full
Windows loader. The payload must be:

- PE32+ (`OptionalHeader.Magic == 0x20B`);
- architecture-matched to the host process (`AMD64` or `ARM64`);
- benign and deterministic;
- no-import, because import resolution is intentionally not implemented;
- relocatable if Windows maps the section away from `OptionalHeader.ImageBase`.

If the payload contains imports, the script fails clearly before process
creation. If the payload maps at a non-preferred base and has no relocation
directory, the script fails clearly because relocations are required.

## Sample Benign Payload Build

Example no-import x64 stub with MSVC tools. It exits with code `42`.

```cmd
ml64 /c benign_exit.asm
link /subsystem:windows /entry:Start /nodefaultlib /dynamicbase /out:payload.exe benign_exit.obj
```

`benign_exit.asm`:

```asm
option casemap:none

.code
Start proc
    mov eax, 42
    ret
Start endp
end
```

For a marker-file payload, use a normal imported executable instead and keep it
outside this mapper, or extend the lab with explicit import resolution. This
demo intentionally rejects imported payloads.

## Self-Test Mode

`-ValidateOnly` performs deterministic validation and exits before target
process creation:

- payload architecture;
- DOS, NT, COFF, and PE32+ OptionalHeader fields;
- `SizeOfHeaders`, `SizeOfImage`, `ImageBase`, `AddressOfEntryPoint`;
- `SectionAlignment` and `FileAlignment`;
- section raw-to-virtual mapping bounds;
- computed entrypoint VA at the preferred image base;
- non-empty Import Directory rejection.

## Known Unsupported

- TLS callbacks.
- Complex imports and delayed imports.
- SEH and unwinding edge cases.
- ARM64 runtime behavior if not explicitly tested in your lab.
- Non-relocatable images when mapped away from `OptionalHeader.ImageBase`.
- Normal `.exe` payloads that rely on the Windows loader for imports, CRT
  startup, TLS, loader lists, activation contexts, or subsystem setup.

## Safety Scope

This repository is for controlled internal lab education only. The script does
not include stealth, evasion, AMSI/ETW patching, obfuscation, persistence,
credential access, network callbacks, random sleeps, or anti-analysis behavior.
