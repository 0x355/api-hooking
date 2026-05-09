#include "iat_hook.h"
#include <stdio.h>
#include <stdlib.h>

static IATHook g_msgbox_hook = {
	.module_name = "user32.dll",
	.function_name = "MessageBoxA",
	.original = NULL,
	.hook_fn = NULL,
	.installed = FALSE,
};

static int WINAPI hooked_MessageBoxA(
	HWND hwnd,
	LPCSTR text,
	LPCSTR caption,
	UINT type)
{
	uintptr_t rsp_at_entry = 0;

#if defined(_MSC_VER) && defined(_M_X64)
	rsp_at_entry = (uintptr_t)_AddressOfReturnAddress();
#elif defined(__GNUC__) && defined(__x86_64__)
	__asm__ volatile (
		"movq %%rsp, %0"
		: "=r"(rsp_at_entry)
		:
		:
	);
#endif

	// Logs
	printf("[HOOK] MessageBoxA intercepted\n");
	printf(" hwnd -> %p\n", (void*)hwnd);
	printf(" text -> \"%s\"\n", text ? text : "(null)");
	printf(" desc -> \"%s\"\n", caption ? caption : "(null)");
	printf(" type -> 0x%08X\n", type);
	printf(" RSP -> 0x%016\n", (unsigned long long)rsp_at_entry);
	printf(" original -> 0x%p\n\n", (void*)g_msgbox_hook.original);

	typedef int (WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
	MessageBoxA_t real_fn = (MessageBoxA_t)g_msgbox_hook.original;

	return real_fn(hwnd, text, caption, type);
}

int main(void)
{
	HMODULE exe_module = GetModuleHandleA(NULL);
	if (!exe_module)
	{
		fprintf(stderr, "GetModuleHandleA failed -> %lu\n", GetLastError());
		return EXIT_FAILURE;
	}

	g_msgbox_hook.hook_fn = (PROC)hooked_MessageBoxA;

	printf("[+] Calling MessageBoxA before Hook\n");
	MessageBoxA(NULL, "Hello from original", "Before hook", MB_OK);

	printf("[+] Installing IAT hook on MessageBoxA\n");
	if (!iat_hook_install(exe_module, &g_msgbox_hook))
	{
		fprintf(stderr, "iat_hook_install failed -> %lu\n", GetLastError());
		return EXIT_FAILURE;
	}

	printf("[*] Hook installed, original ptr -> %p\n\n", (void*)g_msgbox_hook.original);

	printf("[+] Calling MessageBoxA after Hook\n");
	MessageBoxA(NULL, "Hello from hooked", "After hook", MB_OKCANCEL);

	printf("[+] Removing hook\n");
	if (!iat_hook_remove(exe_module, &g_msgbox_hook))
	{
		fprintf(stderr, "iat_hook_remoe failed -> %lu\n", GetLastError());
		return EXIT_FAILURE;
	}

	printf("[*] Hook removed\n\n");

	printf("[+] Calling MessageBoxA restored\n");
	MessageBoxA(NULL, "Hello from restored", "Hook restored", MB_OK);

	return EXIT_SUCCESS;
}