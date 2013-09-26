Input: <a PE library(DLL/EXE/..) path> [FunctionName] [NUmberOfInstructions]

Output::Release

[*] Mapped Address: 00320000
[*] ExportDirectory RVA:  000101E8
[*] ExportDirectory Size: 63153
[*] Section for Export Table:
[*] Name: .text
[*] RVA:  00010000
[*] PtrToRawData:  00000400
[*] SizeOfRawData: 875008
[*] LoadLibrary address: 77770000
[*] GetProcAddress(NtCreateFile): 777900B4
[*] Decoded Instructions...
 777900b4 (05) b852000000               MOV EAX, 0x52
 777900b9 (02) 33c9                     XOR ECX, ECX
 777900bb (04) 8d542404                 LEA EDX, [ESP+0x4]
 777900bf (07) 64ff15c0000000           CALL DWORD [FS:0xc0]
 777900c6 (03) 83c404                   ADD ESP, 0x4
 777900c9 (03) c22c00                   RET 0x2c
 777900cc (05) b853000000               MOV EAX, 0x53
 777900d1 (02) 33c9                     XOR ECX, ECX
 777900d3 (04) 8d542404                 LEA EDX, [ESP+0x4]
 777900d7 (07) 64ff15c0000000           CALL DWORD [FS:0xc0]
[*] Decoded Instruction Size: 42
[*] Parsing Export Table...
[*] Exports Name: ntdll.dll
[*] Function Found @ 003304B4
[*] Decoded Instructions...
 777900b4 (05) b852000000               MOV EAX, 0x52
 777900b9 (02) 33c9                     XOR ECX, ECX
 777900bb (04) 8d542404                 LEA EDX, [ESP+0x4]
 777900bf (07) 64ff15c0000000           CALL DWORD [FS:0xc0]
 777900c6 (03) 83c404                   ADD ESP, 0x4
 777900c9 (03) c22c00                   RET 0x2c
 777900cc (05) b853000000               MOV EAX, 0x53
 777900d1 (02) 33c9                     XOR ECX, ECX
 777900d3 (04) 8d542404                 LEA EDX, [ESP+0x4]
 777900d7 (07) 64ff15c0000000           CALL DWORD [FS:0xc0]
[*] Decoded Instruction Size: 42


Processing:

* Load Dll using LoadLibrary()
* LoadProcAddr = GetProcAddress()
* Map Library to Memory -> MapViewOfFile()
* Parse Export Table and FindProc
* Disassmble instructions form both the addresses.


TODO:
Process Reloactions
