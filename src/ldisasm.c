#include "ldisasm.h"
#include <stdint.h>
#include <stddef.h>

typedef struct {
    const uint8_t* start;
    const uint8_t* p;

    int pfx_66;
    int pfx_67;
    int pfx_rex;
    int rex_w;
    int rex_r;
    int rex_x;
    int rex_b;
} decode_state;

static inline uint8_t read_u8(decode_state* s)
{
    return *s->p++;
}

static inline size_t current_length(const decode_state* s)
{
    return (size_t)(s->p - s->start);
}

static inline int modrm_mod(uint8_t b) { return (b >> 6) & 0x03; }
static inline int modrm_reg(uint8_t b) { return (b >> 3) & 0x07; }
static inline int modrm_rm(uint8_t b) { return  b & 0x07; }

static inline int sib_base(uint8_t b) { return  b & 0x07; }

static void consume_prefixes(decode_state* s)
{
    for (;;) {
        uint8_t b = *s->p;

        switch (b) {
        case 0xF0: case 0xF2: case 0xF3:
        case 0x2E: case 0x3E: case 0x26:
        case 0x64: case 0x65:
            s->p++;
            continue;

        case 0x66:
            s->pfx_66 = 1;
            s->p++;
            continue;

        case 0x67:
            s->pfx_67 = 1;
            s->p++;
            continue;

        default:
            break;
        }

        if (b >= 0x40 && b <= 0x4F) {
            s->pfx_rex = 1;
            s->rex_w = (b >> 3) & 1;
            s->rex_r = (b >> 2) & 1;
            s->rex_x = (b >> 1) & 1;
            s->rex_b = b & 1;
            s->p++;
        }

        break;
    }
}

static void consume_modrm(decode_state* s, uint8_t modrm)
{
    int mod = modrm_mod(modrm);
    int rm = modrm_rm(modrm);

    if (mod == 3) {
        return;
    }

    int have_sib = (rm == 4);
    uint8_t sib = 0;

    if (have_sib) {
        sib = read_u8(s);
    }

    if (mod == 1) {
        s->p += 1;
    }
    else if (mod == 2) {
        s->p += 4;
    }
    else {
        if (rm == 5) {
            s->p += 4;
        }
        else if (have_sib && sib_base(sib) == 5) {
            s->p += 4;
        }
    }
}

static inline size_t imm_size_default(const decode_state* s)
{
    if (s->pfx_66)  return 2;
    return 4;
}

static size_t decode_1byte(decode_state* s, uint8_t op)
{
    switch (op) {
    case 0x06: case 0x07:
    case 0x0E:
    case 0x16: case 0x17:
    case 0x1E: case 0x1F:
    case 0x27: case 0x2F:
    case 0x37: case 0x3F:
    case 0x40: case 0x41: case 0x42: case 0x43:
    case 0x44: case 0x45: case 0x46: case 0x47:
    case 0x48: case 0x49: case 0x4A: case 0x4B:
    case 0x4C: case 0x4D: case 0x4E: case 0x4F:
    case 0x50: case 0x51: case 0x52: case 0x53:
    case 0x54: case 0x55: case 0x56: case 0x57:
    case 0x58: case 0x59: case 0x5A: case 0x5B:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F:
    case 0x60: case 0x61:
    case 0x90:
    case 0x91: case 0x92: case 0x93:
    case 0x94: case 0x95: case 0x96: case 0x97:
    case 0x98: case 0x99:
    case 0x9B: case 0x9C: case 0x9D:
    case 0x9E: case 0x9F:
    case 0xA4: case 0xA5:
    case 0xA6: case 0xA7:
    case 0xAA: case 0xAB:
    case 0xAC: case 0xAD:
    case 0xAE: case 0xAF:
    case 0xC3:
    case 0xC9:
    case 0xCB: case 0xCF:
    case 0xCC:
    case 0xF1:
    case 0xF4:
    case 0xF5:
    case 0xF8: case 0xF9:
    case 0xFA: case 0xFB:
    case 0xFC: case 0xFD:
        return current_length(s);

    case 0x04: case 0x0C: case 0x14: case 0x1C:
    case 0x24: case 0x2C: case 0x34: case 0x3C:
    case 0x6A:
    case 0x6B:
        if (op == 0x6B) { read_u8(s); consume_modrm(s, s->p[-1]); }
        s->p += 1;
        return current_length(s);

    case 0x70: case 0x71: case 0x72: case 0x73:
    case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7A: case 0x7B:
    case 0x7C: case 0x7D: case 0x7E: case 0x7F:
    case 0xEB:
    case 0xE0: case 0xE1: case 0xE2: case 0xE3:
    case 0xCD:
        s->p += 1;
        return current_length(s);

    case 0xB0: case 0xB1: case 0xB2: case 0xB3:
    case 0xB4: case 0xB5: case 0xB6: case 0xB7:
        s->p += 1;
        return current_length(s);

    case 0xC0: case 0xC1:
    case 0xD0: case 0xD1:
    case 0xD2: case 0xD3: {
        uint8_t modrm = read_u8(s);
        consume_modrm(s, modrm);
        if (op == 0xC0 || op == 0xC1) s->p += 1;
        return current_length(s);
    }

    case 0x05: case 0x0D: case 0x15: case 0x1D:
    case 0x25: case 0x2D: case 0x35: case 0x3D:
        s->p += imm_size_default(s);
        return current_length(s);

    case 0x68:
        s->p += imm_size_default(s);
        return current_length(s);

    case 0x69: {
        uint8_t modrm = read_u8(s);
        consume_modrm(s, modrm);
        s->p += imm_size_default(s);
        return current_length(s);
    }

    case 0xE8:
    case 0xE9:
        s->p += 4;
        return current_length(s);

    case 0xA8:
        s->p += 1;
        return current_length(s);

    case 0xA9:
        s->p += imm_size_default(s);
        return current_length(s);

    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF:
        if (s->rex_w)       s->p += 8;
        else if (s->pfx_66) s->p += 2;
        else                s->p += 4;
        return current_length(s);

    case 0x00: case 0x01: case 0x02: case 0x03:
    case 0x08: case 0x09: case 0x0A: case 0x0B:
    case 0x10: case 0x11: case 0x12: case 0x13:
    case 0x18: case 0x19: case 0x1A: case 0x1B:
    case 0x20: case 0x21: case 0x22: case 0x23:
    case 0x28: case 0x29: case 0x2A: case 0x2B:
    case 0x30: case 0x31: case 0x32: case 0x33:
    case 0x38: case 0x39: case 0x3A: case 0x3B:
    case 0x62:
    case 0x63:
    case 0x84: case 0x85:
    case 0x86: case 0x87:
    case 0x88: case 0x89: case 0x8A: case 0x8B:
    case 0x8C: case 0x8D: case 0x8E:
    case 0x8F:
    case 0xD8: case 0xD9: case 0xDA: case 0xDB:
    case 0xDC: case 0xDD: case 0xDE: case 0xDF:
    case 0xFE: case 0xFF: {
        uint8_t modrm = read_u8(s);
        consume_modrm(s, modrm);
        return current_length(s);
    }

    case 0x80: case 0x82: case 0x83: {
        uint8_t modrm = read_u8(s);
        consume_modrm(s, modrm);
        s->p += 1;
        return current_length(s);
    }

    case 0x81: {
        uint8_t modrm = read_u8(s);
        consume_modrm(s, modrm);
        s->p += imm_size_default(s);
        return current_length(s);
    }

    case 0xC2: case 0xCA:
        s->p += 2;
        return current_length(s);

    case 0xC6: {
        uint8_t modrm = read_u8(s);
        consume_modrm(s, modrm);
        s->p += 1;
        return current_length(s);
    }
    case 0xC7: {
        uint8_t modrm = read_u8(s);
        consume_modrm(s, modrm);
        s->p += imm_size_default(s);
        return current_length(s);
    }

    case 0xD4: case 0xD5:
        s->p += 1;
        return current_length(s);

    case 0xE4: case 0xE5:
    case 0xE6: case 0xE7:
        s->p += 1;
        return current_length(s);

    case 0xEA:
        s->p += (s->pfx_66 ? 4 : 6);
        return current_length(s);

    case 0x9A:
        s->p += (s->pfx_66 ? 4 : 6);
        return current_length(s);

    case 0xEC: case 0xED:
    case 0xEE: case 0xEF:
        return current_length(s);

    case 0x0F:
        return 0;

    default:
        return 0;
    }
}

static size_t decode_2byte(decode_state* s)
{
    uint8_t op = read_u8(s);

    switch (op) {
    case 0x06: case 0x08: case 0x09:
    case 0x0B:
    case 0x30: case 0x31: case 0x32:
    case 0x33: case 0x34: case 0x35:
    case 0x77:
    case 0xA0: case 0xA1:
    case 0xA8: case 0xA9:
    case 0xAA:
        return current_length(s);

    case 0x80: case 0x81: case 0x82: case 0x83:
    case 0x84: case 0x85: case 0x86: case 0x87:
    case 0x88: case 0x89: case 0x8A: case 0x8B:
    case 0x8C: case 0x8D: case 0x8E: case 0x8F:
        s->p += 4;
        return current_length(s);

    case 0x90: case 0x91: case 0x92: case 0x93:
    case 0x94: case 0x95: case 0x96: case 0x97:
    case 0x98: case 0x99: case 0x9A: case 0x9B:
    case 0x9C: case 0x9D: case 0x9E: case 0x9F: {
        uint8_t modrm = read_u8(s);
        consume_modrm(s, modrm);
        return current_length(s);
    }

    case 0x00: case 0x01: case 0x02: case 0x03:
    case 0xA3: case 0xA5: case 0xAB: case 0xAD:
    case 0xB0: case 0xB1: case 0xB3: case 0xB6: case 0xB7:
    case 0xBB: case 0xBC: case 0xBD: case 0xBE: case 0xBF:
    case 0xC0: case 0xC1:
    case 0xD0: case 0xD1: case 0xD2: case 0xD3:
    case 0xD4: case 0xD5: case 0xD6: case 0xD7:
    case 0xD8: case 0xD9: case 0xDA: case 0xDB:
    case 0xDC: case 0xDD: case 0xDE: case 0xDF:
    case 0xE0: case 0xE1: case 0xE2: case 0xE3:
    case 0xE4: case 0xE5: case 0xE6: case 0xE7:
    case 0xE8: case 0xE9: case 0xEA: case 0xEB:
    case 0xEC: case 0xED: case 0xEE: case 0xEF:
    case 0xF0: case 0xF1: case 0xF2: case 0xF3:
    case 0xF4: case 0xF5: case 0xF6: case 0xF7:
    case 0xF8: case 0xF9: case 0xFA: case 0xFB:
    case 0xFC: case 0xFD: case 0xFE: case 0xFF:
    case 0x10: case 0x11: case 0x12: case 0x13:
    case 0x14: case 0x15: case 0x16: case 0x17:
    case 0x18: case 0x28: case 0x29: case 0x2A:
    case 0x2B: case 0x2C: case 0x2D: case 0x2E:
    case 0x2F: case 0x40: case 0x41: case 0x42:
    case 0x43: case 0x44: case 0x45: case 0x46:
    case 0x47: case 0x48: case 0x49: case 0x4A:
    case 0x4B: case 0x4C: case 0x4D: case 0x4E:
    case 0x4F: case 0x50: case 0x51: case 0x52:
    case 0x53: case 0x54: case 0x55: case 0x56:
    case 0x57: case 0x58: case 0x59: case 0x5A:
    case 0x5B: case 0x5C: case 0x5D: case 0x5E:
    case 0x5F: case 0x60: case 0x61: case 0x62:
    case 0x63: case 0x64: case 0x65: case 0x66:
    case 0x67: case 0x68: case 0x69: case 0x6A:
    case 0x6B: case 0x6C: case 0x6D: case 0x6E:
    case 0x6F: {
        uint8_t modrm = read_u8(s);
        consume_modrm(s, modrm);
        return current_length(s);
    }

    case 0x70: case 0x71: case 0x72: case 0x73:
    case 0xA4: case 0xAC:
    case 0xBA:
    case 0xC2: case 0xC4: case 0xC5: case 0xC6: {
        uint8_t modrm = read_u8(s);
        consume_modrm(s, modrm);
        s->p += 1;
        return current_length(s);
    }

    case 0xAF: {
        uint8_t modrm = read_u8(s);
        consume_modrm(s, modrm);
        return current_length(s);
    }

    case 0x38: case 0x3A: {
        read_u8(s);
        uint8_t modrm = read_u8(s);
        consume_modrm(s, modrm);
        if (op == 0x3A) s->p += 1;
        return current_length(s);
    }

    default:
        return 0;
    }
}

size_t ldisasm(const uint8_t* code)
{
    if (!code) return 0;

    decode_state s = {
        .start = code,
        .p = code,
        .pfx_66 = 0,
        .pfx_67 = 0,
        .pfx_rex = 0,
        .rex_w = 0,
        .rex_r = 0,
        .rex_x = 0,
        .rex_b = 0
    };

    consume_prefixes(&s);

    uint8_t op = read_u8(&s);

    if (op == 0x0F)
    {
        return decode_2byte(&s);
    }

    return decode_1byte(&s, op);
}