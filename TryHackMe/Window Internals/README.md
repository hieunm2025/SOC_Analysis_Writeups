
## Summary of Key Learnings

**Processes**

* Processes = execution instances of programs.
* Components: Virtual address space, code, handles, security context, PID, threads.
* Attack techniques: process injection, hollowing, masquerading.
* Example tools: Task Manager, Procmon, Process Hacker.
* Lab answers:

  * `notepad.exe` PID → **5984**
  * Parent PID → **3412**
  * Integrity level → **High**

**Threads**

* Smallest execution unit in a process.
* Components: stack, TLS, stack argument, context.
* Common abuse target in malware.
* Lab answers:

  * First thread ID → **5908**
  * Stack argument → **6584**

**Virtual Memory**

* Each process gets private virtual address space.
* Translated via Memory Manager, prevents collisions.
* 32-bit max: **4 GB**, split user/kernel.
* 64-bit max: **256 TB**.
* `increaseUserVA` can reallocate address space.
* Lab answers:

  * Base address of `notepad.exe` → **0x7ff652ec0000**

**Dynamic Link Libraries (DLLs)**

* Shared code/data between programs.
* Loading methods: load-time vs run-time.
* Attack vectors: DLL hijacking, side-loading, injection.
* Lab answers:

  * Base address of `ntdll.dll` → **0x7ffd0be20000**
  * Size of `ntdll.dll` → **0x1ec000**
  * DLLs loaded by notepad → **51**

**Portable Executable (PE) Format**

* Structure of Windows executables.
* Components: DOS Header, DOS Stub, PE Header, Section Table.
* Sections: `.text` (code), `.data` (vars), `.rdata/.idata` (imports), `.reloc`, `.rsrc`.
* Lab answers:

  * DOS Stub prints “This program cannot be run in DOS mode”.
  * Entry point (DiE) → **000000014001acd0**
  * `NumberOfSections` → **6**
  * Virtual Address of `.data` → **00024000**
  * String at offset `0001f99c` → **Microsoft.Notepad**

**Interacting with Windows Internals**

* Interaction via Windows API → Win32 API.
* Kernel vs user mode: system calls switch contexts.
* Proof of concept → allocate memory, write payload, run with `CreateRemoteThread`.
* Lab answer: Flag → **THM{1Nj3c7\_4lL\_7H3\_7h1NG2}**

**Conclusion**

* Windows Internals = foundation of OS operation.
* Core target for red teams (injection, hollowing, DLL attacks).
* Concepts also applicable in Unix (different implementations).

---

## Citations

* [Microsoft Docs – Windows Internals & Processes](https://learn.microsoft.com/en-us/windows/win32/procthread/processes-and-threads)
* [TryHackMe: Windows Internals Room](https://tryhackme.com/room/windowsinternals)
* [Medium Writeup by jamdagnya, 2022](https://medium.com/@jamdagnya/windows-internals-room-tryhackme-solutions-xxxx)