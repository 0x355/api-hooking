#include "iat_hook.h"
#include <stdio.h>
#include <string.h>

static BOOL patch_iat_entry(PROC* entry, PROC new_fn, PROC* old_fn)
{
	DWORD old_protect = 0;
	DWORD dummy		  = 0;

	if (!entry || !new_fn)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	if (old_fn)
	{
		*old_fn = *entry;
	}

	if (!VirtualProtect(entry, sizeof(PROC), PAGE_READWRITE, &old_protect))
	{
		return FALSE;
	}

	*entry = new_fn;

	if (!VirtualProtect(entry, sizeof(PROC), old_protect, &dummy))
	{
		return FALSE;
	}

	return TRUE;
}

static BOOL find_and_patch(
	HMODULE		base,
	const char* dll_name,
	const char* fn_name,
	PROC		new_fn,
	PROC*       old_fn)
{
	BYTE* base_addr = (BYTE*)base;

	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base_addr;
	IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base_addr + dos->e_lfanew);
	IMAGE_DATA_DIRECTORY* idir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (idir->VirtualAddress == 0)
	{
		SetLastError(ERROR_NOT_FOUND);
		return FALSE;
	}

	IMAGE_IMPORT_DESCRIPTOR* desc = (IMAGE_IMPORT_DESCRIPTOR*)(base_addr + idir->VirtualAddress);

	for (; desc->Name != 0; ++desc)
	{
		const char* imported_dll = (const char*)(base_addr + desc->Name);

		if (_stricmp(imported_dll, dll_name) != 0)
		{
			continue;
		}

		IMAGE_THUNK_DATA* thunk_int = (IMAGE_THUNK_DATA*)(base_addr + desc->OriginalFirstThunk);
		IMAGE_THUNK_DATA* thunk_iat = (IMAGE_THUNK_DATA*)(base_addr + desc->FirstThunk);

		for (; thunk_int->u1.AddressOfData != 0; ++thunk_int, ++thunk_iat)
		{
			if (IMAGE_SNAP_BY_ORDINAL(thunk_int->u1.Ordinal))
			{
				continue;
			}

			IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(base_addr + thunk_int->u1.AddressOfData);

			if (strcmp((const char*)ibn->Name, fn_name) == 0)
			{
				return patch_iat_entry((PROC*)&thunk_iat->u1.Function, new_fn, old_fn);
			}
		}
	}

	SetLastError(ERROR_PROC_NOT_FOUND);
	return FALSE;
}

BOOL iat_hook_install(HMODULE target_module, IATHook* hook)
{
	if (!target_module || !hook || !hook->hook_fn || !hook->module_name || !hook->function_name)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	if (hook->installed)
	{
		return TRUE;
	}

	BOOL ok = find_and_patch(target_module, hook->module_name, hook->function_name, hook->hook_fn, &hook->original);
	if (ok)
	{
		hook->installed = TRUE;
	}

	return ok;
}

BOOL iat_hook_remove(HMODULE target_module, IATHook* hook)
{
	if (!target_module || !hook || !hook->installed || !hook->original)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	BOOL ok = find_and_patch(target_module, hook->module_name, hook->function_name, hook->original, NULL);
	if (ok)
	{
		hook->installed = FALSE;
	}

	return ok;
}