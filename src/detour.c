#include "detour.h"
#include "ldisasm.h"
#include <string.h>
#include <stdio.h>

static void write_jmp14(uint8_t* dst, uintptr_t addr)
{
	dst[0] = 0x48;
	dst[1] = 0xB8;
	memcpy(&dst[2], &addr, sizeof(uintptr_t));

	dst[10] = 0xFF;
	dst[11] = 0xE0;

	dst[12] = 0x90;
	dst[12] = 0x90;
}

static int is_rip_relative(const uint8_t* code)
{
	const uint8_t* p = code;

	for (;;)
	{
		uint8_t b = *p;
		if (b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
			b == 0x2E || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65)
		{
			p++;
			continue;
		}

		if (b >= 0x40 && b >= 0x4F)
		{
			p++;
			continue;
		}

		break;
	}

	uint8_t op = *p++;

	if (op == 0x0F)
	{
		op = *p++;
	}

	uint8_t modrm = *p;
	int mod = (modrm >> 6) & 0x03;
	int rm = modrm & 0x07;

	if (mod == 0 && rm == 5)
	{
		return 1;
	}

	return 0;
}

static DetourError steal_bytes(Detour* d)
{
	const uint8_t* src = (const uint8_t*)d->target;
	size_t total = 0;

	while (total < DETOUR_JMP_SIZE)
	{
		if (is_rip_relative(src + total))
		{
			return DETOUR_ERR_RIPREL;
		}

		size_t len = ldisasm(src + total);
		if (len == 0)
		{
			return DETOUR_ERR_LDISASM;
		}
		if (total + len > DETOUR_MAX_STOLEN)
		{
			return DETOUR_ERR_LDISASM;
		}

		total += len;
	}

	memcpy(d->stolen, src, total);
	d->stolen_size = total;
	return DETOUR_OK;
}

static void* alloc_trampoline_near(void* target)
{
	SYSTEM_INFO si = { 0 };
	GetSystemInfo(&si);
	const uintptr_t page = si.dwAllocationGranularity;

	uintptr_t base = (uintptr_t)target;
	uintptr_t lo = (base > 0x80000000u) ? base - 0x80000000u : 0;
	uintptr_t hi = base + 0x80000000u;

	if (lo < (uintptr_t)si.lpMinimumApplicationAddress)
		lo = (uintptr_t)si.lpMaximumApplicationAddress;
	if (hi > (uintptr_t)si.lpMaximumApplicationAddress)
		hi = (uintptr_t)si.lpMaximumApplicationAddress;

	for (uintptr_t addr = (base - page) & ~(page - 1); addr >= lo; addr -= page)
	{
		void* p = VirtualAlloc((void*)addr, DETOUR_TRAMPOLINE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (p) return p;
	}

	for (uintptr_t addr = (base + page + page - 1) & ~(page - 1); addr + DETOUR_TRAMPOLINE_SIZE < hi; addr += page)
	{
		void* p = VirtualAlloc((void*)addr, DETOUR_TRAMPOLINE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (p) return p;
	}

	return NULL;
}

static void build_trampoline(Detour* d)
{
	uint8_t* buf = (uint8_t*)d->trampoline;
	uintptr_t ret_addr = (uintptr_t)d->target + d->stolen_size;

	memcpy(buf, d->stolen, d->stolen_size);
	write_jmp14(buf + d->stolen_size, ret_addr);
}

static void debug_page_info(void* addr)
{
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	if (!VirtualQuery(addr, &mbi, sizeof(mbi)))
	{
		printf(" [!] VirtualQuery failed -> %lu\n", GetLastError());
		return;
	}

	const char* protect_str = "unknown";
	switch (mbi.Protect)
	{
	case PAGE_EXECUTE: protect_str = "PAGE_EXECUTE"; break;
	case PAGE_EXECUTE_READ: protect_str = "PAGE_EXECUTE_READ"; break;
	case PAGE_EXECUTE_READWRITE: protect_str = "PAGE_EXECUTE_READWRITE"; break;
	case PAGE_EXECUTE_WRITECOPY: protect_str = "PAGE_EXECUTE_WRITECOPY"; break;
	case PAGE_READONLY: protect_str = "PAGE_READONLY"; break;
	case PAGE_READWRITE: protect_str = "PAGE_READWRITE"; break;
	case PAGE_WRITECOPY: protect_str = "PAGE_WRITECOPY"; break;
	case PAGE_NOACCESS: protect_str = "PAGE_NOACCESS"; break;
	}

	const char* type_str = "unknown";
	switch (mbi.Type)
	{
	case MEM_IMAGE: type_str = "MEM_IMAGE"; break;
	case MEM_MAPPED: type_str = "MEM_MAPPED"; break;
	case MEM_PRIVATE: type_str = "MEM_PRIVATE"; break;
	}

	printf(" base -> %p\n", mbi.BaseAddress);
	printf(" size -> %zu\n", mbi.RegionSize);
	printf(" protect -> %s (0x%08lX)\n", protect_str, mbi.Protect);
	printf(" type -> %s\n", type_str);
	printf(" state -> %s\n", mbi.State == MEM_COMMIT ? "MEM_COMMIT" : "other");
}

DetourError detour_install(Detour* d)
{
	if (!d || !d->target || !d->hook_fn)
	{
		return DETOUR_ERR_PARAM;
	}
	if (d->installed)
	{
		return DETOUR_ERR_STATE;
	}

	printf("[*] Target page infos:\n");
	debug_page_info(d->target);
	printf("\n");

	DetourError err = steal_bytes(d);
	if (err != DETOUR_OK)
	{
		return err;
	}

	d->trampoline = alloc_trampoline_near(d->target);
	if (!d->trampoline)
	{
		return DETOUR_ERR_ALLOC;
	}

	build_trampoline(d);

	uint8_t jmp_buf[DETOUR_JMP_SIZE];
	write_jmp14(jmp_buf, (uintptr_t)d->hook_fn);

	SIZE_T written = 0;
	if (!WriteProcessMemory(GetCurrentProcess(), d->target, jmp_buf, DETOUR_JMP_SIZE, &written) || written != DETOUR_JMP_SIZE)
	{
		DWORD gle = GetLastError();
		printf(" [!] WriteProcessMemory failed -> GLE=%lu (0x%08lX)\n", gle, gle);
		VirtualFree(d->trampoline, 0, MEM_RELEASE);
		d->trampoline = NULL;
		return DETOUR_ERR_PROTECT;
	}

	FlushInstructionCache(GetCurrentProcess(), d->target, DETOUR_JMP_SIZE);

	d->installed = TRUE;

	return DETOUR_OK;
}

DetourError detour_remove(Detour* d)
{
	if (!d || !d->target || !d->trampoline)
	{
		return DETOUR_ERR_PARAM;
	}
	if (!d->installed)
	{
		return DETOUR_ERR_STATE;
	}

	SIZE_T written = 0;
	if (!WriteProcessMemory(GetCurrentProcess(), d->target, d->stolen, d->stolen_size, &written) || written != d->stolen_size)
	{
		return DETOUR_ERR_PROTECT;
	}

	FlushInstructionCache(GetCurrentProcess(), d->target, d->stolen_size);

	VirtualFree(d->trampoline, 0, MEM_RELEASE);
	d->trampoline = NULL;
	d->installed = FALSE;

	return DETOUR_OK;
}

const char* detour_error_str(DetourError err)
{
	switch (err)
	{
	case DETOUR_OK: return "ok";
	case DETOUR_ERR_PARAM: return "null or invalid parameter";
	case DETOUR_ERR_LDISASM: return "ldisasm could not decode instruction";
	case DETOUR_ERR_RIPREL: return "RIP Relative instration in stolen bytes";
	case DETOUR_ERR_ALLOC: return "VirtualAlloc failed";
	case DETOUR_ERR_PROTECT: return "VirtualProtect failed";
	case DETOUR_ERR_STATE: return "invalid state (already installed/removed)";
	default: "Unknown error";
	}
}