#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <inttypes.h>
#include "ripe_attack_generator.h"

static const char * const bin4b[16] = {"0000", "0001", "0010", "0011",
                                       "0100", "0101", "0110", "0111",
                                       "1000", "1001", "1010", "1011",
                                       "1100", "1101", "1110", "1111"};

static const char *hex_to_bin(char c);
static void hex_to_string(char * str, size_t val);
static void format_instruction(uint8_t *dest, size_t insn);

/*
RIPE shellcode uses the following instructions:
la <reg>, <addr of func()>
jalr <reg>

The first la instruction is disassembled to:
lui <reg>, <upper 20 bits>
addi <reg>, <reg>, <lower 12 bits>

Thus, the shellcode follows the pattern
shown in the following encodings:

LUI: xxxx xxxx xxxx xxxx xxxx xxxx x011 0111
     \                  / \    /\      /
             imm value         reg#  opcode


ADDI: xxxx xxxx xxxx xxxx x000 xxxx x011 0011
      \        / \    /    \    /\      /
        imm value     reg#      reg#  opcode


JALR: 0000 0000 0000 xxxx x000 0000 1110 0111
                     \    /          \      /
                      reg#            opcode

The shellcode is formatted so that:
  1. All instructions are stored to a single string
  2. Byte order is converted to little-endian
*/
void
build_shellcode(uint8_t **shellcode, size_t *size_shellcode)
{
    static uint8_t shellcode_nonop[12];
    *shellcode = shellcode_nonop;

    // Do not count for the null terminator since a null in the shellcode will
    // terminate any string function in the standard library
    *size_shellcode = sizeof(shellcode_nonop);

    char attack_addr[9], low_bits[4], high_bits[6];  // target address and its components
    // fix shellcode when lower bits would become negative
    if (((uintptr_t)&shellcode_target & 0x00000fff) >= 0x800)
        hex_to_string(attack_addr, (uintptr_t)&shellcode_target + 0x1000);
    else
        hex_to_string(attack_addr, (uintptr_t)&shellcode_target);

    // split attack address into low and high bit strings
    strncpy(low_bits, &attack_addr[5], 3);
    low_bits[3] = '\0'; // unnecessary (unlike below)
    strncpy(high_bits, attack_addr, 5);
    high_bits[5] = '\0';

    char lui_bin[33], addi_bin[33]; // binary insn encodings (as strings)
    lui_bin[0] = '\0';
    addi_bin[0] = '\0';

    // generate 20 imm bits for the LUI insn
    for (int i = 0; i < 5; i++) {
        strncat(lui_bin, hex_to_bin(high_bits[i]), 4);
    }

    uint32_t lui_val, addi_val, jalr_val = 0x000300e7; // raw binary insn encodings
    // append reg and opcode bits, then convert to raw binary
    strncat(lui_bin, "001100110111", 12);
    lui_val = strtoul(lui_bin, 0, 2);

    // generate binary for ADDI insn
    for (int i = 0; i < 3; i++) {
        strncat(addi_bin, hex_to_bin(low_bits[i]), 4);
    }

    strncat(addi_bin, "00110000001100010011", 20);
    addi_val = strtoul(addi_bin, 0, 2);

    format_instruction(shellcode_nonop, lui_val);
    format_instruction(shellcode_nonop + 4, addi_val);
    format_instruction(shellcode_nonop + 8, jalr_val);

    char lui_s[9], addi_s[9]; // hex insn encodings
    hex_to_string(lui_s, lui_val);
    lui_s[8] = '\0';
    hex_to_string(addi_s, addi_val);
    addi_s[8] = '\0';

    if (g.output_debug_info) {
        printf("----------------\n");
        printf("Shellcode instructions:\n");
        printf("%s0x%-20s%14s\n", "lui t1,  ", high_bits, lui_s);
        printf("%s0x%-20s%10s\n", "addi t1, t1, ", low_bits, addi_s);
        printf("%s%30s%08"PRIx32"\n", "jalr t1", " ", jalr_val);
        printf("----------------\n");
    }
}

static const char *
hex_to_bin(char c) {
    if (c >= '0' && c <= '9')
        return bin4b[c - '0'];
    if (c >= 'a' && c <= 'f')
        return bin4b[10 + c - 'a'];
    return NULL;
}

// convert a 32-bit hex value to 0-padded, 8-char string
static void
hex_to_string(char * str, size_t val)
{
    snprintf(str, 9, "%08zx", val);
}

// format instruction and append to destination string
static void
format_instruction(uint8_t * dest, size_t insn)
{
    uint8_t insn_bytes[4];

    insn_bytes[0] = (insn >> 24) & 0xff;
    insn_bytes[1] = (insn >> 16) & 0xff;
    insn_bytes[2] = (insn >> 8) & 0xff;
    insn_bytes[3] = insn & 0xff;

    for (int i = 3; i >= 0; i--) {
        dest[3 - i] = insn_bytes[i];
    }
}

// For RETURN_ORIENTED_PROGRAMMING we skip over the prologue code of
// rop_target() to simulate return-oriented programming gadget
#ifndef PROLOGUE_OFF
  #define PROLOGUE_OFF 0
#endif
#ifdef __riscv_compressed
  #define PROLOGUE_LENGTH (8+PROLOGUE_OFF)
#else
  #define PROLOGUE_LENGTH (16+PROLOGUE_OFF)
#endif

size_t prologue_length (void) {
  return PROLOGUE_LENGTH;
}
