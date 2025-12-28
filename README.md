# Pagefile Parasites

**ParasiteView** introduces a process injection technique that swaps the entire address space of a suspended process with a malicious payload while preserving the process execution context. Unlike traditional injection methods that write foreign code into existing memory, ParasiteView leverages named sections and APC queuing to achieve execution continuity that appears identical to legitimate process initialization.

---

## What's new

Memory Swapping vs Traditional Injection

Traditional Process Injection:

WriteProcessMemory() -> CreateRemoteThread()
- Modifies existing process memory
- Creates anomalous threads
- Leaves clear forensic artifacts
- Easily detected by modern EDRs

ParasiteView (Memory Swapping):

NtCreateSection() -> Memory Mirroring -> APC Execution
- Swaps entire address space via named sections
- Preserves process context (tokens, handles, PEB)
- No remote memory writes or thread creation
- Appears as normal process startup to EDRs

## 🔧 Technique Overview

This PoC uses the following Windows syscalls:

- `NtCreateSection` with `SEC_COMMIT`, Pagefile-backed named extension
- `NtMapViewOfSection` mirror same phisycal memory in two processes
- `NtMapViewOfSection` remove original process image 
- `NtQueueApcThread` execute via asynchronous procedure call
- `NtUnmapViewOfSection` -> unmap original image
- `GetThreadContext` -> preserve execution state for fallback

---

## ✅ Features

- Process Continuity Preservation (Maintains original security tokens and handles, preserves parent-child process relationships, keeps PEB structure intact, no impersonation or token stealing required)
- Cross-Process Memory Mirroring
(
    // Same physical memory, two virtual mappings
Section = NtCreateSection(Named);
NtMapViewOfSection(Section, LocalProcess, &LocalBase);
NtMapViewOfSection(Section, RemoteProcess, &RemoteBase);

)
- Timed based evation

Random delay (3-10s) between process creation and memory swap
Process appears "legitimately suspended" during delay
Memory swap and execution happen instantaneously post-delay

- EDR-unfriendly by design:
No VirtualAllocEx or WriteProcessMemory calls
No remote thread creation via CreateRemoteThread
No module stomping or hollowing patterns
Memory appears as legitimate image mapping


## 📊 Comparison with Existing Techniques

Comparison with Existing Techniques

Process Hollowing
- Detection vectors:
  * Unmap/Map memory pattern
  * Modified PEB
- ParasiteView evasion:
  ✓ Uses shared sections
  ✓ Preserves original PEB

APC Injection
- Detection vectors:
  * QueueUserAPC hooks
  * Reliance on alertable threads
- ParasiteView evasion:
  ✓ Uses NtQueueApcThread directly
  ✓ Does not require alertable state

Module Stomping
- Detection vectors:
  * Modified loaded modules
  * LDR list inconsistencies
- ParasiteView evasion:
  ✓ No module stomping
  ✓ No LDR list modifications

Thread Hijacking
- Detection vectors:
  * Suspicious thread context changes
  * Direct RIP/EIP patching
- ParasiteView evasion:
  ✓ Execution via legitimate APC delivery
  ✓ No direct thread context overwrite

---

## 💡 Notes

- Payload must be a valid PE file (e.g. raw `exe`) smaller than 2MB
- Target binary must exist (e.g. `notepad.exe`)
- EntryPoint is extracted from the PE header manually

---

## 📎 Disclaimer

This code is for educational and research purposes only.

---

by **@nexxus67**, 2025

"The art of stealth lies not in hiding, but in appearing as something you're not."


