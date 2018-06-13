#ifndef _PE_HELPER_H
#define _PE_HELPER_H

#include <windows.h>
#include "libdwarf.h"

#ifdef __cplusplus
extern "C"
{
#endif

int dwarf_pe_init(HANDLE hFile, TCHAR* chFilePath,
	Dwarf_Handler errHandler, Dwarf_Ptr errArg,
	Dwarf_Debug *retDbg, Dwarf_Error *dwErr);

int dwarf_pe_finish(Dwarf_Debug dbg, Dwarf_Error err);

#ifdef __cplusplus
}
#endif

#endif