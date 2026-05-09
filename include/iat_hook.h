#ifndef IAT_HOOK_H
#define IAT_HOOK_H

#include <Windows.h>
#include <stdint.h>

typedef struct
{
	const char* module_name;	// user32.dll
	const char* function_name;  // MessageBoxA
	PROC		original;		// original pointer
	PROC		hook_fn;		// replacement
	BOOL		installed;		// installation state
} IATHook;

BOOL iat_hook_install(HMODULE target_module, IATHook* hook);
BOOL iat_hook_remove(HMODULE target_module, IATHook* hook);

#endif // IAT_HOOK_H