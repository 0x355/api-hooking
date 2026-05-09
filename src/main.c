#include "iat_hook.h"
#include "ldisasm.h"
#include "detour.h"
#include <stdio.h>
#include <stdlib.h>

static int g_passed = 0;
static int g_failed = 0;

static void run_test(const char* desc, const uint8_t* bytes, size_t expected)
{
	size_t got = ldisasm(bytes);
	if (got == expected)
	{
		printf("  [PASS] %-45s len=%zu\n", desc, got);
		g_passed++;
	}
	else
	{
		printf("  [FAIL] %-45s expected=%zu got=%zu  bytes:", desc, expected, got);
		for (size_t i = 0; i < expected + 2 && i < 15; i++)
			printf(" %02X", bytes[i]);
		printf("\n");
		g_failed++;
	}
}

#define TEST(desc, expected, ...) \
	do { \
		const uint8_t _b[] = { __VA_ARGS__ }; \
		run_test(desc, _b, expected); \
	} while (0)

static void run_ldisasm_tests(void)
{
	printf("\n[*] No-operand instructions\n");
	TEST("NOP", 1, 0x90);
	TEST("RET", 1, 0xC3);
	TEST("INT3", 1, 0xCC);
	TEST("PUSH RBP  (50+r)", 1, 0x55);
	TEST("POP  RBP  (58+r)", 1, 0x5D);
	TEST("HLT", 1, 0xF4);
	TEST("RDTSC  (0F 31)", 2, 0x0F, 0x31);
	TEST("UD2    (0F 0B)", 2, 0x0F, 0x0B);

	printf("\n[*] REX + PUSH/POP\n");
	TEST("PUSH R12", 2, 0x41, 0x54);
	TEST("POP  R12", 2, 0x41, 0x5C);
	TEST("PUSH RBX", 1, 0x53);

	printf("\n[*] MOV reg, imm\n");
	TEST("MOV EAX, 1", 5, 0xB8, 0x01, 0x00, 0x00, 0x00);
	TEST("MOV RAX, imm64", 10, 0x48, 0xB8,
		0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE);
	TEST("MOV RCX, imm64", 10, 0x48, 0xB9,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88);
	TEST("MOV AL, 0x42", 2, 0xB0, 0x42);

	printf("\n[*] MOV with ModRM\n");
	TEST("MOV [RSP+0x28], RCX", 5, 0x48, 0x89, 0x4C, 0x24, 0x28);
	TEST("MOV RAX, [RCX]", 3, 0x48, 0x8B, 0x01);
	TEST("MOV [RIP+disp32], EAX", 6, 0x89, 0x05, 0x00, 0x00, 0x00, 0x00);
	TEST("LEA RCX, [RIP+disp32]", 7, 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00);

	printf("\n[*] ALU instructions\n");
	TEST("SUB RSP, imm8", 4, 0x48, 0x83, 0xEC, 0x28);
	TEST("ADD RAX, RCX", 3, 0x48, 0x03, 0xC1);
	TEST("XOR EAX, EAX", 2, 0x33, 0xC0);
	TEST("CMP RCX, imm8", 4, 0x48, 0x83, 0xF9, 0x00);
	TEST("AND EAX, imm32", 5, 0x25, 0xFF, 0x00, 0x00, 0x00);

	printf("\n[*] JMP / CALL\n");
	TEST("JMP short", 2, 0xEB, 0x10);
	TEST("JMP rel32", 5, 0xE9, 0x00, 0x01, 0x00, 0x00);
	TEST("CALL rel32", 5, 0xE8, 0x11, 0x22, 0x33, 0x44);
	TEST("JMP [RIP+disp32]", 6, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00);
	TEST("CALL [RIP+disp32]", 6, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00);
	TEST("JE rel32 (0F 84)", 6, 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00);

	printf("\n[*] Jcc short\n");
	TEST("JE  short (74)", 2, 0x74, 0x05);
	TEST("JNE short (75)", 2, 0x75, 0xFA);
	TEST("JL  short (7C)", 2, 0x7C, 0x10);
	TEST("JGE short (7D)", 2, 0x7D, 0x10);

	printf("\n[*] SIB addressing\n");
	TEST("MOV [RSP+8], RAX", 5, 0x48, 0x89, 0x44, 0x24, 0x08);
	TEST("MOV [RSP], RBP", 4, 0x48, 0x89, 0x2C, 0x24);

	printf("\n[*] Typical Win64 API prologue\n");
	TEST("MOV [RSP+8],  RCX", 5, 0x48, 0x89, 0x4C, 0x24, 0x08);
	TEST("MOV [RSP+16], RDX", 5, 0x48, 0x89, 0x54, 0x24, 0x10);
	TEST("PUSH RBP", 1, 0x55);
	TEST("PUSH RBX", 1, 0x53);
	TEST("SUB RSP, 0x28", 4, 0x48, 0x83, 0xEC, 0x28);

	printf("\n[*] SETcc / CMOVcc\n");
	TEST("SETE  AL       (0F 94 C0)", 3, 0x0F, 0x94, 0xC0);
	TEST("SETNE [RAX]    (0F 95 00)", 3, 0x0F, 0x95, 0x00);
	TEST("CMOVE RAX, RCX (48 0F 44 C1)", 4, 0x48, 0x0F, 0x44, 0xC1);

	printf("\nldisasm results: %d passed, %d failed\n\n",
		g_passed, g_failed);
}

static IATHook g_msgbox_hook = {
	.module_name = "user32.dll",
	.function_name = "MessageBoxA",
	.original = NULL,
	.hook_fn = NULL,
	.installed = FALSE,
};

static int WINAPI hooked_MessageBoxA_iat(
	HWND   hwnd,
	LPCSTR text,
	LPCSTR caption,
	UINT   type)
{
	uintptr_t rsp_at_entry = 0;
#if defined(_MSC_VER) && defined(_M_X64)
	rsp_at_entry = (uintptr_t)_AddressOfReturnAddress();
#elif defined(__GNUC__) && defined(__x86_64__)
	__asm__ volatile ("movq %%rsp, %0" : "=r"(rsp_at_entry) : : );
#endif
	printf("[IAT HOOK] MessageBoxA intercepted\n");
	printf("  hwnd     -> %p\n", (void*)hwnd);
	printf("  text     -> \"%s\"\n", text ? text : "(null)");
	printf("  caption  -> \"%s\"\n", caption ? caption : "(null)");
	printf("  type     -> 0x%08X\n", type);
	printf("  RSP      -> 0x%016llX\n", (unsigned long long)rsp_at_entry);
	printf("  original -> %p\n\n", (void*)g_msgbox_hook.original);

	typedef int (WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
	MessageBoxA_t real_fn = (MessageBoxA_t)g_msgbox_hook.original;
	return real_fn(hwnd, text, caption, type);
}

static void demo_iat_hook(void)
{
	HMODULE exe_module = GetModuleHandleA(NULL);
	if (!exe_module)
	{
		fprintf(stderr, "GetModuleHandleA failed -> %lu\n", GetLastError());
		return;
	}

	g_msgbox_hook.hook_fn = (PROC)hooked_MessageBoxA_iat;

	printf("[+] Calling MessageBoxA before hook\n");
	MessageBoxA(NULL, "Hello from original", "Before hook", MB_OK);

	printf("[+] Installing IAT hook on MessageBoxA\n");
	if (!iat_hook_install(exe_module, &g_msgbox_hook))
	{
		fprintf(stderr, "iat_hook_install failed -> %lu\n", GetLastError());
		return;
	}
	printf("[*] Hook installed, original ptr -> %p\n\n",
		(void*)g_msgbox_hook.original);

	printf("[+] Calling MessageBoxA after hook\n");
	MessageBoxA(NULL, "Hello from hooked", "After hook", MB_OKCANCEL);

	printf("[+] Removing hook\n");
	if (!iat_hook_remove(exe_module, &g_msgbox_hook))
	{
		fprintf(stderr, "iat_hook_remove failed -> %lu\n", GetLastError());
		return;
	}
	printf("[*] Hook removed\n\n");

	printf("[+] Calling MessageBoxA restored\n");
	MessageBoxA(NULL, "Hello from restored", "Hook restored", MB_OK);
	printf("\n");
}

static Detour g_detour_msgbox = { 0 };

static int WINAPI hooked_MessageBoxA_detour(
	HWND   hwnd,
	LPCSTR text,
	LPCSTR caption,
	UINT   type)
{
	uintptr_t rsp_at_entry = 0;
#if defined(_MSC_VER) && defined(_M_X64)
	rsp_at_entry = (uintptr_t)_AddressOfReturnAddress();
#elif defined(__GNUC__) && defined(__x86_64__)
	__asm__ volatile ("movq %%rsp, %0" : "=r"(rsp_at_entry) : : );
#endif
	printf("[DETOUR HOOK] MessageBoxA intercepted\n");
	printf("  hwnd       -> %p\n", (void*)hwnd);
	printf("  text       -> \"%s\"\n", text ? text : "(null)");
	printf("  caption    -> \"%s\"\n", caption ? caption : "(null)");
	printf("  type       -> 0x%08X\n", type);
	printf("  RSP        -> 0x%016llX\n", (unsigned long long)rsp_at_entry);
	printf("  trampoline -> %p\n", g_detour_msgbox.trampoline);
	printf("  stolen     -> %zu bytes\n\n", g_detour_msgbox.stolen_size);

	typedef int (WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
	MessageBoxA_t trampoline = (MessageBoxA_t)g_detour_msgbox.trampoline;
	return trampoline(hwnd, text, caption, type);
}

static void demo_detour(void)
{
	HMODULE user32 = GetModuleHandleA("user32.dll");
	if (!user32)
	{
		fprintf(stderr, "GetModuleHandleA(user32) failed -> %lu\n", GetLastError());
		return;
	}

	void* target = (void*)GetProcAddress(user32, "MessageBoxA");
	if (!target)
	{
		fprintf(stderr, "GetProcAddress(MessageBoxA) failed -> %lu\n", GetLastError());
		return;
	}

	printf("[*] MessageBoxA -> %p\n", target);

	printf("[*] Bytes before patch: ");
	const uint8_t* p = (const uint8_t*)target;
	for (int i = 0; i < 16; i++) printf("%02X ", p[i]);
	printf("\n\n");

	g_detour_msgbox.target = target;
	g_detour_msgbox.hook_fn = (void*)hooked_MessageBoxA_detour;

	printf("[+] Calling MessageBoxA before detour\n");
	MessageBoxA(NULL, "Hello from original", "Before detour", MB_OK);

	printf("[+] Installing detour on MessageBoxA\n");
	DetourError err = detour_install(&g_detour_msgbox);
	if (err != DETOUR_OK)
	{
		fprintf(stderr, "detour_install failed -> %s\n", detour_error_str(err));
		return;
	}

	printf("[*] Bytes after patch:  ");
	for (int i = 0; i < 16; i++) printf("%02X ", p[i]);
	printf("\n");
	printf("[*] Trampoline -> %p  stolen -> %zu bytes\n\n",
		g_detour_msgbox.trampoline, g_detour_msgbox.stolen_size);

	printf("[+] Calling MessageBoxA after detour\n");
	MessageBoxA(NULL, "Hello from detoured", "After detour", MB_OKCANCEL);

	printf("[+] Removing detour\n");
	err = detour_remove(&g_detour_msgbox);
	if (err != DETOUR_OK)
	{
		fprintf(stderr, "detour_remove failed -> %s\n", detour_error_str(err));
		return;
	}

	printf("[*] Bytes after restore: ");
	for (int i = 0; i < 16; i++) printf("%02X ", p[i]);
	printf("\n\n");

	printf("[+] Calling MessageBoxA restored\n");
	MessageBoxA(NULL, "Hello from restored", "Detour restored", MB_OK);
	printf("\n");
}

int main(void)
{
	run_ldisasm_tests();
	if (g_failed > 0)
	{
		fprintf(stderr, "[!] ldisasm tests failed, aborting\n");
		return EXIT_FAILURE;
	}

	demo_iat_hook();
	demo_detour();

	return EXIT_SUCCESS;
}