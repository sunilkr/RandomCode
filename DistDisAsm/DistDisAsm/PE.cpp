#include <Windows.h>
#include <stdio.h>
#include <strsafe.h>
#include "PE.h"

extern PIMAGE_NT_HEADERS NtHeaders;

//LPVOID GetTextOffset(HANDLE hDll)
//{
//	DWORD dwResult;
//	return NULL;
//}

PIMAGE_SECTION_HEADER GetRvaEnclosingSection(DWORD Rva)
{
	PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);

	for (int i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++, Section++)
	{
		DWORD Size = Section->Misc.VirtualSize;
		if (Size == 0)
			Size = Section->SizeOfRawData;

		if (Rva >= Section->VirtualAddress && Rva < (Section->VirtualAddress + Size))
		{
#ifdef _DEBUG
			printf("\n[?] Found RVA in Section : %s [%08X]", Section->Name, Section->VirtualAddress);
#endif
			return Section;
		}
	}
	printf("\n[X] RVA %08X does not belong to any section.", Rva);
	return NULL;
}

LPVOID GetPtrFromRVA(DWORD Rva, LPVOID ImageBase)
{
	PIMAGE_SECTION_HEADER Section = GetRvaEnclosingSection(Rva);
	if (!Section)
		return NULL;

	INT Delta = Section->VirtualAddress - Section->PointerToRawData;
	return (LPVOID) ((DWORD)ImageBase + Rva - Delta);
}

LPVOID MapDllToMemory(HANDLE hDll)
{
	DWORD dwFileSize = GetFileSize(hDll, NULL);
	
	HANDLE hMapping = CreateFileMapping(hDll, NULL, PAGE_READONLY, 0, 0, NULL);

	if (hMapping == INVALID_HANDLE_VALUE)
		return NULL;

	return MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, dwFileSize);
}


LPVOID GetImageBaseOfCode(LPVOID ImageBase)
{
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER) ImageBase;
	PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS) ((DWORD)ImageBase + DosHeader->e_lfanew);
	if (NtHeaders->Signature == IMAGE_NT_SIGNATURE)
	{
		return (LPVOID) ((DWORD) ImageBase + NtHeaders->OptionalHeader.BaseOfCode);
	}
	else
		printf("\n[X] Invalid NT_SIGNATURE");
	return NULL;
}

PIMAGE_SECTION_HEADER GetExportSection(LPVOID ImageBase)
{
	CHAR SectionName[9] = {0};

	DWORD ExportRVA = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD ExportSize = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	printf("\n[*] ExportDirectory RVA:  %08X", ExportRVA);
	printf("\n[*] ExportDirectory Size: %d", ExportSize);

	//PIMAGE_SECTION_HEADER Section = (PIMAGE_SECTION_HEADER) ((DWORD) NtHeaders + sizeof(IMAGE_NT_HEADERS));
	PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders); //Predefined Macro

#ifdef _DEBUG
	printf("\n[?] First Section Offset: %08X(%d)", ((DWORD) Section - (DWORD) ImageBase), ((DWORD) Section - (DWORD) ImageBase));
	StringCbCopy((STRSAFE_LPSTR) SectionName, 8, (STRSAFE_LPCSTR) Section->Name);
	printf("\n[?] Name: %s", SectionName);
	printf("\n[?] RVA:  %08X", Section->VirtualAddress);
	printf("\n[?] PtrToRawData:  %08X", Section->PointerToRawData);
	printf("\n[?] SizeOfRawData: %d", Section->SizeOfRawData);
#endif // DEBUG

	PIMAGE_SECTION_HEADER ExportSection = GetRvaEnclosingSection(ExportRVA);
	if (ExportSection)
	{
		printf("\n[*] Section for Export Table:");
		printf("\n[*] Name: %s", ExportSection->Name);
		printf("\n[*] RVA:  %08X", ExportSection->VirtualAddress);
		printf("\n[*] PtrToRawData:  %08X", ExportSection->PointerToRawData);
		printf("\n[*] SizeOfRawData: %d", ExportSection->SizeOfRawData);
	}
	return ExportSection;
}

PIMAGE_EXPORT_DIRECTORY GetExportDirectory(PIMAGE_SECTION_HEADER ExportSection, LPVOID ImageBase)
{
	DWORD ExportOffset = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress - ExportSection->VirtualAddress;
	return (PIMAGE_EXPORT_DIRECTORY) ((ULONG_PTR) ImageBase + ExportSection->PointerToRawData + ExportOffset);
}

LPVOID FindProcAddressByName(LPSTR ProcName, LPVOID ImageBase, PIMAGE_EXPORT_DIRECTORY ExportDirectory)
{
	LPVOID ProcAddress = NULL;
	
	printf("\n[*] Parsing Export Table...");
	printf("\n[*] Exports Name: %s", GetPtrFromRVA(ExportDirectory->Name, ImageBase));

#ifdef _DEBUG
	printf("\n[?] Ordinal Base: %d", ExportDirectory->Base);
#endif

	PDWORD AddressOfNames = (PDWORD) GetPtrFromRVA(ExportDirectory->AddressOfNames, ImageBase);
	PWORD AddressOfOrdinals = (PWORD) GetPtrFromRVA(ExportDirectory->AddressOfNameOrdinals, ImageBase);
	PDWORD AddressOfFunctions = (PDWORD) GetPtrFromRVA(ExportDirectory->AddressOfFunctions,ImageBase);

	for (DWORD i = 0; i < ExportDirectory->NumberOfFunctions; i++)
	{
		LPCSTR FunctionName = (LPCSTR) GetPtrFromRVA(AddressOfNames[i], ImageBase);
		WORD Ordinal = AddressOfOrdinals[i];
		ProcAddress = GetPtrFromRVA(AddressOfFunctions[Ordinal - ExportDirectory->Base + 1], ImageBase);
#ifdef _DEBUG
		printf("\n[?] Found Function: %s", FunctionName);
		printf("\n[?] Ordinal: %d, RVA: %08X", Ordinal, AddressOfFunctions[Ordinal]);
		printf("\n[?] Function Entry Ptr: %08X\n[?]--", ProcAddress);
#endif
		if (strcmp(ProcName,FunctionName) == 0)
		{
			printf("\n[*] Function Found @ %08X", ProcAddress);
			return ProcAddress;
		}
	}
	printf("\n[X] Function %s is not exported.");
	return NULL;
}