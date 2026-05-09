#ifndef LDISASM_H
#define LDISASM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

	size_t  ldisasm(const uint8_t* code);

#ifdef __cplusplus
}
#endif

#endif // LDISASM_H