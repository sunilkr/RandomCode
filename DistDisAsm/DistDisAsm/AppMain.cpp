#include <stdio.h>
#include <Windows.h>
#include "decode.h"
#include "PE.h"

PIMAGE_NT_HEADERS NtHeaders;

int main(int argc, char** argv)
{
	if (argc < 2)
	{
		printf("DLL Name is required");
		return -1;
	}

	LPSTR lpFunction = (argc > 2) ? argv[2] : "DllMain";

	DWORD InstrCount = (argc > 3) ? atoi(argv[3]) : 10;

	HANDLE hDll = CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hDll == INVALID_HANDLE_VALUE)
	{
		printf("[X] Failed to open %s.", argv[1]);
		return -2;
	}

	LPVOID MappedBase = MapDllToMemory(hDll);
	printf("\n[*] Mapped Address: %08X", MappedBase);

	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER) MappedBase;
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("\n[X] Invalid DOS_SIGNATURE.");
		return -2;
	}

	NtHeaders = (PIMAGE_NT_HEADERS) ((DWORD) MappedBase + DosHeader->e_lfanew);

#ifdef _DEBUG
	LPVOID BaseOfCode = GetImageBaseOfCode(MappedBase);
	if (BaseOfCode == NULL)
	{
		printf("\n[X] Error in GetBaseOfCode");
		return -3;
	}
	else
		printf("\n[*] Base Of Code: %08X", BaseOfCode);

	printf("\n[*] Default Load Address: %08X", NtHeaders->OptionalHeader.ImageBase);
#endif
	
	PIMAGE_SECTION_HEADER ExportSection = GetExportSection(MappedBase);
	PIMAGE_EXPORT_DIRECTORY ExportDir = GetExportDirectory(ExportSection, MappedBase);

	LPVOID LoadProcAddr = NULL;
	HMODULE hLoadDll = LoadLibrary(argv[1]);
	if (hLoadDll != INVALID_HANDLE_VALUE)
	{
		printf("\n[*] LoadLibrary address: %08X", hLoadDll);
		LoadProcAddr = GetProcAddress(hLoadDll, lpFunction);
		printf("\n[*] GetProcAddress(%s): %08X", lpFunction, LoadProcAddr);
		DWORD Size = DecodeInstructions((PBYTE) LoadProcAddr, InstrCount, LoadProcAddr, NULL, 250);
		printf("\n[*] Decoded Instruction Size: %d", Size);
	}

	LPVOID lpProcAddress = FindProcAddressByName(lpFunction, MappedBase, ExportDir);

	//CHAR InstrBuff[250] = {0};
	if (lpProcAddress)
	{
		DWORD Size = DecodeInstructions((PBYTE) lpProcAddress, InstrCount, LoadProcAddr, NULL, 250);
		printf("\n[*] Decoded Instruction Size: %d", Size);
	}

	printf("\n");
	return 0;
}
