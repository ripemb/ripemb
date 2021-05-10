/* RIPE was originally developed by John Wilander (@johnwilander)
 * and was debugged and extended by Nick Nikiforakis (@nicknikiforakis)
 *
 * The RISC-V port of RIPE was developed by John Merrill.
 *
 * Released under the MIT license (see file named LICENSE)
 *
 * This program is part the paper titled
 * RIPE: Runtime Intrusion Prevention Evaluator
 * Authored by: John Wilander, Nick Nikiforakis, Yves Younan,
 *              Mariam Kamkar and Wouter Joosen
 * Published in the proceedings of ACSAC 2011, Orlando, Florida
 *
 * Please cite accordingly.
 */

/**
 * @author John Wilander
 * 2007-01-16
 */

#ifndef RIPE_ATTACK_GENERATOR_H
#define RIPE_ATTACK_GENERATOR_H

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <stdint.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>

typedef int boolean;
enum booleans {FALSE=0, TRUE};

extern boolean output_debug_info;

#define ARR_ELEMS(a) (sizeof(a)/sizeof(a[0]))

/* Enumerations for typing of attack form parameters                        */
/* Each enumeration has its own integer space to provide better type safety */
enum techniques    {DIRECT=100, INDIRECT};
enum inject_params {INJECTED_CODE_NO_NOP=200, RETURN_INTO_LIBC,
                    RETURN_ORIENTED_PROGRAMMING, DATA_ONLY};

enum code_ptrs     {RET_ADDR=300, FUNC_PTR_STACK_VAR, FUNC_PTR_STACK_PARAM,
                    FUNC_PTR_HEAP, FUNC_PTR_BSS, FUNC_PTR_DATA,
                    LONGJMP_BUF_STACK_VAR, LONGJMP_BUF_STACK_PARAM,
                    LONGJMP_BUF_HEAP, LONGJMP_BUF_BSS, LONGJMP_BUF_DATA,
                    STRUCT_FUNC_PTR_STACK,STRUCT_FUNC_PTR_HEAP,
                    STRUCT_FUNC_PTR_DATA,STRUCT_FUNC_PTR_BSS, VAR_BOF, VAR_IOF, VAR_LEAK};
enum locations     {STACK=400, HEAP, BSS, DATA};
enum functions     {MEMCPY=500, STRCPY, STRNCPY, SPRINTF, SNPRINTF,
                    STRCAT, STRNCAT, SSCANF, HOMEBREW};

typedef struct attack_form ATTACK_FORM;
struct attack_form {
        enum techniques technique;
        enum inject_params inject_param;
        enum code_ptrs code_ptr;
        enum locations location;
        enum functions function;
};
extern ATTACK_FORM attack;

typedef struct char_payload CHARPAYLOAD;
struct char_payload {
        enum inject_params inject_param;
        size_t size;
        void *overflow_ptr; /* Points to code pointer (direct attack) */
                            /* or general pointer (indirect attack)   */
        char *buffer;

        jmp_buf *jmp_buffer;

        long stack_jmp_buffer_param;
        size_t offset_to_copied_base_ptr;
        size_t offset_to_fake_return_addr;
        long *fake_return_addr;
        long *ptr_to_correct_return_addr;
};

struct attackme {
        char buffer[256];
        int (*func_ptr)(const char *, int);
};

/**
 * main
 * -t technique
 * -i injection parameter
 * -c code pointer
 * -l memory location
 * -f function to overflow with
 * -d output debug info
 */
int parse_ripe_params(int argc, char ** argv, struct attack_form *attack, boolean *debug);

int main(int argc, char **argv);
extern const char * const opt_techniques[];
extern size_t nr_of_techniques;
extern const char * const opt_inject_params[];
extern size_t nr_of_inject_params;
extern const char * const opt_code_ptrs[];
extern size_t nr_of_code_ptrs;
extern const char * const opt_locations[];
extern size_t nr_of_locations;
extern const char * const opt_funcs[];
extern size_t nr_of_funcs;



/* BUILD_PAYLOAD()                                                  */
/*                                                                  */
/* Simplified example of payload (exact figures are just made up):  */
/*                                                                  */
/*   size      = 31 (the total payload size)                        */
/*   size_sc   = 12 (size of shellcode incl NOP)                    */
/*   size_addr = 4  (size of address to code)                       */
/*   size_null = 1  (size of null termination)                      */
/*                                                                  */
/*    ------------ ----------------- ------------- -                */
/*   | Shell code | Padded bytes    | Address     |N|               */
/*   | including  |                 | back to     |u|               */
/*   | optional   |                 | NOP sled or |l|               */
/*   | NOP sled   |                 | shell code  |l|               */
/*    ------------ ----------------- ------------- -                */
/*    |          | |               | |           | |                */
/*    0         11 12             25 26         29 30               */
/*              /   \             /   \             \               */
/*     size_sc-1     size_sc     /     \             size-size_null */
/*                              /       \                           */
/*  (size-1)-size_addr-size_null         size-size_addr-size_null   */
/*                                                                  */
/* This means that we should pad with                               */
/* size - size_sc - size_addr - size_null = 31-12-4-1 = 14 bytes    */
/* and start the padding at index size_sc                           */
boolean build_payload(CHARPAYLOAD *payload);

boolean set_technique(char *choice, enum techniques *t);
boolean set_inject_param(char *choice, enum inject_params *i);
boolean set_code_ptr(char *choice, enum code_ptrs *c);
boolean set_location(char *choice, enum locations *l);
boolean set_function(char *choice, enum functions *f);


boolean is_attack_possible();
void homebrew_memcpy(void *dst, const void *src, size_t len);

/*
RIPE shellcode uses the following instructions:
la <reg>, <addr of shellcode_func()>
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
  1. Byte order is converted to little-endian
*/
void build_shellcode(char *shellcode);
void format_instruction(char *dest, size_t insn);

#endif /* !RIPE_ATTACK_GENERATOR_H */
