# api-hooking

Windows x64 API hooking engine in C.

Built from scratch for learning and research.

## Techniques
| Branch | Technique | Status |
|--------|-----------|--------|
| `main` | IAT Hooking |  ✅  |
| `detour` | Inline Detour Patching |  🔜  |
| `syscall` | Direct Syscall Hook |  🔜  |

## How IAT Hooking Works
When a PE is loaded, Windows fills the **Import Address Table (IAT)**
with the resolved addresses of every imported function.

```
[caller code]
    CALL QWORD PTR [IAT_slot]
        [user32.dll!MessageBoxA]
```

By patchinjg the pointer in that slot we redirect every call
```
[caller code]
    CALL QWORD PTR [IAT_slot]
        [out hook] -> logs args -> calls original
```

No code is modified, only a pointer in a data section.

## Build

**MSCV (x64 Native Tools Command Prompt)**
```
mkdir build && cd build
cmake .. -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release
nmake
```

**MinGW-w64**
```
mkdir build && cd build
cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
mingw32-make
```

## Demo output
```
[+] Calling MessageBoxA before Hook
[+] Installing IAT hook on MessageBoxA
[*] Hook installed, original ptr -> 00007FFE4CBDCAB0

[+] Calling MessageBoxA after Hook
[HOOK] MessageBoxA intercepted
 hwnd -> 0000000000000000
 text -> "Hello from hooked"
 desc -> "After hook"
 type -> 0x00000001
 RSP -> 0x
 original -> 0x00007FFE4CBDCAB0

[+] Removing hook
[*] Hook removed

[+] Calling MessageBoxA restored
```

## Next steps
- [ ] Hook `CreateFileA` -> log filesystem access
- [ ] Hook `RegSetValueExA` -> detect persistence
- [ ] Hook `VirtualAllocEx` -> detect injection attempts
- [ ] Add detour branch (inline x64 ASM trampoline)

## References
- [PE Format - Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [MalwareTech - IAT Hooking](https://malwaretech.com/2015/01/inline-hooking-for-programmers-part-1.html)