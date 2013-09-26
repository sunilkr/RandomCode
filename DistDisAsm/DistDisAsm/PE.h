#include<Windows.h>

LPVOID MapDllToMemory(HANDLE hDll);
LPVOID GetImageEntryPoint(LPVOID ImageBase);
LPVOID GetImageBaseOfCode(LPVOID ImageBase);
LPVOID FindProcAddressByName(LPSTR ProcName, LPVOID ImageBase, PIMAGE_EXPORT_DIRECTORY ExportDirectory);
LPVOID GetPtrFromRVA(DWORD Rva, LPVOID ImageBase);

PIMAGE_SECTION_HEADER	GetRvaEnclosingSection(DWORD Rva);
PIMAGE_SECTION_HEADER	GetExportSection(LPVOID ImageBase);
PIMAGE_EXPORT_DIRECTORY GetExportDirectory(PIMAGE_SECTION_HEADER ExportSection, LPVOID ImageBase);
