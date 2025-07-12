# Pagefile Parasites

**ParasiteView** is a fileless injection technique that executes a PE payload from a memory section backed by the system pagefile. No files are dropped. No classic API calls. No noise.

---

## 🔧 Technique Overview

This PoC uses the following Windows syscalls:

- `NtCreateSection` with `SEC_COMMIT` and `FileHandle = NULL` → pagefile-backed memory
- `NtMapViewOfSection` in the current process → write payload
- `NtMapViewOfSection` in suspended remote process → inject payload
- `NtUnmapViewOfSection` → unmap original image
- `SetThreadContext` → patch `RIP` to payload entrypoint
- `ResumeThread` → execute

---

## ✅ Features

- Single PowerShell file, no external dependencies
- No `VirtualAllocEx`, no `WriteProcessMemory`, no `CreateRemoteThread`
- Payload stays in memory only
- EDR-unfriendly by design

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

