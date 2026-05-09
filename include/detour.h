#ifndef DETOUR_H
#define DETOUR_H

#include <Windows.h>
#include <stdint.h>
#include <stddef.h>

#define DETOUR_JMP_SIZE	  14u
#define DETOUR_MAX_STOLEN 64u
#define DETOUR_TRAMPOLINE_SIZE (DETOUR_MAX_STOLEN + DETOUR_JMP_SIZE)

typedef enum {
	DETOUR_OK		   = 0,
	DETOUR_ERR_PARAM   = -1,
	DETOUR_ERR_LDISASM = -2,
	DETOUR_ERR_RIPREL  = -3,
	DETOUR_ERR_ALLOC   = -4,
	DETOUR_ERR_PROTECT = -5,
	DETOUR_ERR_STATE   = -6,
} DetourError;

typedef struct {
	void*	target;
	void*	hook_fn;
	void*   trampoline;
	uint8_t stolen[DETOUR_MAX_STOLEN];
	size_t  stolen_size;
	BOOL	installed;
} Detour;

DetourError detour_install(Detour* d);
DetourError detour_remove(Detour* d);

const char* detour_error_str(DetourError err);

#endif // DETOUR_H