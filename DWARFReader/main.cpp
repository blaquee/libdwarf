#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <winternl.h>
#include "libdwarf.h"


static bool file_contains_dwarf(const char* filePath);

Dwarf_Obj_Access_Interface *PeDwarfInterface = 0;


static bool file_contains_dwarf(const TCHAR* filePath)
{
	HANDLE hFileHandle = nullptr;
	HANDLE hFileMapping = nullptr;
	LPVOID lpMappedBase = nullptr;

	PIMAGE_DOS_HEADER pDos = nullptr;
	PIMAGE_NT_HEADERS pNtHeader = nullptr;
	PIMAGE_SECTION_HEADER pSections;
	PIMAGE_SYMBOL pSymbolTable;
	PSTR pStringTablePointer;
	LARGE_INTEGER szFileSize;
	SIZE_T nFileSize;
	PBYTE lpStartAddress;


	bool ret = false;

	if(!filePath)
		goto fini;

	hFileHandle = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(!hFileHandle)
		goto fini;

	// Create the mapping
	hFileMapping = CreateFileMapping(hFileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
	if(!hFileMapping)
		goto fini;
	
	lpStartAddress = (PBYTE)MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if(!lpStartAddress)
		goto fini;

	if(!GetFileSizeEx(hFileHandle, &szFileSize))
		goto fini;

	nFileSize = szFileSize.LowPart;
	printf("File Size: %d\n", nFileSize);

	pDos = (PIMAGE_DOS_HEADER)lpStartAddress;
	pNtHeader = (PIMAGE_NT_HEADERS)(lpStartAddress + pDos->e_lfanew);
	pSections = (PIMAGE_SECTION_HEADER)((PBYTE)pNtHeader + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
		pNtHeader->FileHeader.SizeOfOptionalHeader);

	// Enumerate Section for names starting with '/', 
	// then see if there are corresponding section names in the string table

	// POinter to Symbol Table
	pSymbolTable = (PIMAGE_SYMBOL)(lpStartAddress + pNtHeader->FileHeader.PointerToSymbolTable);

	// Check boundary of end of Symbol table
	if(pNtHeader->FileHeader.PointerToSymbolTable +
		pNtHeader->FileHeader.NumberOfSymbols * sizeof(IMAGE_SYMBOL) > nFileSize)
	{
		printf("Bad Pointer to symbols\n");
		goto fini;
	}

	// get a pointer to byte after the symbol Table
	pStringTablePointer = (PSTR)&pSymbolTable[pNtHeader->FileHeader.NumberOfSymbols];

fini:
	if(hFileMapping)
		CloseHandle(hFileMapping);
	if(hFileHandle)
		CloseHandle(hFileHandle);


}



int main(int argc, char** argv)
{
	Dwarf_Debug dbg = 0;
	//int fd = -1;
	FILE* fd = nullptr;


	const char * filepath = "hello_print.exe";
	int res = DW_DLV_ERROR;
	Dwarf_Error err;
	Dwarf_Handler errhandler = 0;
	Dwarf_Ptr errarg = 0;

	// open the file
	if(!fopen_s(&fd, filepath, "r"))
	{
		printf("Failed to open file...\n");
		return 0;
	}

	return 0;
}

static void read_cu_list(Dwarf_Debug dbg)
{
	Dwarf_Unsigned cu_header_length = 0;
	Dwarf_Half version_stamp = 0;
	Dwarf_Unsigned abbrev_offset = 0;
	Dwarf_Half address_size = 0;
}