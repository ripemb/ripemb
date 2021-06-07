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

#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdlib.h>
#include <stdbool.h>

#define ARR_ELEMS(a) (sizeof(a)/sizeof(a[0]))
#define PRIxPTR_WIDTH ((int)(sizeof(uintptr_t)*2))

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

struct attack_form {
        enum techniques technique;
        enum inject_params inject_param;
        enum code_ptrs code_ptr;
        enum locations location;
        enum functions function;
};

struct payload {
        size_t size;
        void *overflow_ptr; /* Points to code pointer (direct attack) */
                            /* or general pointer (indirect attack)   */
        char *buffer;
};

typedef void (func_t)(void);
#define STRUCT_BUF_SIZE 256
struct attackme {
        uint8_t buffer[STRUCT_BUF_SIZE];
        func_t * func_ptr;
};

/**
 * -t technique
 * -i injection parameter
 * -c code pointer
 * -l memory location
 * -f function to overflow with
 * -d output debug info
 */
int parse_ripe_params(int argc, char ** argv, struct attack_form *attack, bool *debug);

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

#ifndef RIPE_HEAP_SAFE_SIZE
    #define RIPE_HEAP_SAFE_SIZE (32*1024)
#endif
/* Take a snapshot of to current heap area and save it into heap_safe. */
void save_heap(uint8_t *heap_safe);
/* Restore the heap area from the snapshot saved in heap_safe. */
void restore_heap(uint8_t *heap_safe);

enum RIPE_RET {
    RET_ATTACK_SUCCESS = 42,
    RET_ATTACK_FAIL,
    RET_RT_IMPOSSIBLE,
    RET_ERR,
};


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
bool build_payload(struct payload *payload, ptrdiff_t offset);

bool set_technique(char *choice, enum techniques *t);
bool set_inject_param(char *choice, enum inject_params *i);
bool set_code_ptr(char *choice, enum code_ptrs *c);
bool set_location(char *choice, enum locations *l);
bool set_function(char *choice, enum functions *f);


bool is_attack_possible(void);
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
void build_shellcode(uint8_t *shellcode);

#endif /* !RIPE_ATTACK_GENERATOR_H */
