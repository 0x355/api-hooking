# api-hooking

Windows x64 API hooking engine in C.

Built from scratch for learning and research.

## Techniques
| Featurre | Technique | Status |
|--------|-----------|--------|
| `IAT` | IAT Hooking |  ✅  |
| `detour` | Inline Detour Patching |  ✅  |
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
[*] No-operand instructions
  [PASS] NOP                                           len=1
  [PASS] RET                                           len=1
  [PASS] INT3                                          len=1
  [PASS] PUSH RBP  (50+r)                              len=1
  [PASS] POP  RBP  (58+r)                              len=1
  [PASS] HLT                                           len=1
  [PASS] RDTSC  (0F 31)                                len=2
  [PASS] UD2    (0F 0B)                                len=2

[*] REX + PUSH/POP
  [PASS] PUSH R12                                      len=2
  [PASS] POP  R12                                      len=2
  [PASS] PUSH RBX                                      len=1

[*] MOV reg, imm
  [PASS] MOV EAX, 1                                    len=5
  [PASS] MOV RAX, imm64                                len=10
  [PASS] MOV RCX, imm64                                len=10
  [PASS] MOV AL, 0x42                                  len=2

[*] MOV with ModRM
  [PASS] MOV [RSP+0x28], RCX                           len=5
  [PASS] MOV RAX, [RCX]                                len=3
  [PASS] MOV [RIP+disp32], EAX                         len=6
  [PASS] LEA RCX, [RIP+disp32]                         len=7

[*] ALU instructions
  [PASS] SUB RSP, imm8                                 len=4
  [PASS] ADD RAX, RCX                                  len=3
  [PASS] XOR EAX, EAX                                  len=2
  [PASS] CMP RCX, imm8                                 len=4
  [PASS] AND EAX, imm32                                len=5

[*] JMP / CALL
  [PASS] JMP short                                     len=2
  [PASS] JMP rel32                                     len=5
  [PASS] CALL rel32                                    len=5
  [PASS] JMP [RIP+disp32]                              len=6
  [PASS] CALL [RIP+disp32]                             len=6
  [PASS] JE rel32 (0F 84)                              len=6

[*] Jcc short
  [PASS] JE  short (74)                                len=2
  [PASS] JNE short (75)                                len=2
  [PASS] JL  short (7C)                                len=2
  [PASS] JGE short (7D)                                len=2

[*] SIB addressing
  [PASS] MOV [RSP+8], RAX                              len=5
  [PASS] MOV [RSP], RBP                                len=4

[*] Typical Win64 API prologue
  [PASS] MOV [RSP+8],  RCX                             len=5
  [PASS] MOV [RSP+16], RDX                             len=5
  [PASS] PUSH RBP                                      len=1
  [PASS] PUSH RBX                                      len=1
  [PASS] SUB RSP, 0x28                                 len=4

[*] SETcc / CMOVcc
  [PASS] SETE  AL       (0F 94 C0)                     len=3
  [PASS] SETNE [RAX]    (0F 95 00)                     len=3
  [PASS] CMOVE RAX, RCX (48 0F 44 C1)                  len=4

ldisasm results: 44 passed, 0 failed

[+] Calling MessageBoxA before hook
[+] Installing IAT hook on MessageBoxA
[*] Hook installed, original ptr -> 00007FFE4CBDCAB0

[+] Calling MessageBoxA after hook
[IAT HOOK] MessageBoxA intercepted
  hwnd     -> 0000000000000000
  text     -> "Hello from hooked"
  caption  -> "After hook"
  type     -> 0x00000001
  RSP      -> 0x000000690D10FB18
  original -> 00007FFE4CBDCAB0

[+] Removing hook
[*] Hook removed

[+] Calling MessageBoxA restored

[*] MessageBoxA -> 00007FFE4CBDCAB0
[*] Bytes before patch: 48 83 EC 38 45 33 DB 44 39 1D 56 3D 04 00 74 25

[+] Calling MessageBoxA before detour
[+] Installing detour on MessageBoxA
[*] Target page infos:
 base -> 00007FFE4CBDC000
 size -> 122880
 protect -> PAGE_EXECUTE_READ (0x00000020)
 type -> MEM_IMAGE
 state -> MEM_COMMIT

[*] Bytes after patch:  48 B8 60 3B C2 7C F7 7F 00 00 FF E0 90 7F 74 25
[*] Trampoline -> 00007FFE4CB40000  stolen -> 14 bytes

[+] Calling MessageBoxA after detour
[DETOUR HOOK] MessageBoxA intercepted
  hwnd       -> 0000000000000000
  text       -> "Hello from detoured"
  caption    -> "After detour"
  type       -> 0x00000001
  RSP        -> 0x000000690D10FB08
  trampoline -> 00007FFE4CB40000
  stolen     -> 14 bytes

[+] Removing detour
[*] Bytes after restore: 48 83 EC 38 45 33 DB 44 39 1D 56 3D 04 00 74 25

[+] Calling MessageBoxA restored
```

## References
- [PE Format - Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [MalwareTech - IAT Hooking](https://malwaretech.com/2015/01/inline-hooking-for-programmers-part-1.html)