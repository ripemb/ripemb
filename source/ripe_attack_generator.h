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
enum techniques    {DIRECT, INDIRECT};
enum inject_params {INJECTED_CODE_NO_NOP, RETURN_INTO_LIBC, INJECTED_CODE_NO_NOP_JR, RETURN_INTO_LIBC_JR,
                    RETURN_ORIENTED_PROGRAMMING, RETURN_INTO_ANCESTOR, RETURN_INTO_ANCESTOR_ROP, DATA_ONLY};

enum code_ptrs     {RET_ADDR, FUNC_PTR_STACK_VAR, FUNC_PTR_STACK_PARAM,
                    FUNC_PTR_HEAP, FUNC_PTR_BSS, FUNC_PTR_DATA,
                    LONGJMP_BUF_STACK_VAR, LONGJMP_BUF_STACK_PARAM,
                    LONGJMP_BUF_HEAP, LONGJMP_BUF_BSS, LONGJMP_BUF_DATA,
                    VAR_BOF, VAR_LEAK};
enum locations     {STACK, HEAP, BSS, DATA};
enum functions     {MEMCPY, HOMEBREW, SSCANF, STRCPY, STRNCPY, SPRINTF, SNPRINTF,
                    STRCAT, STRNCAT};

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
    #ifndef RIPE_SAFE_HEAP
        #define RIPE_HEAP_SAFE_SIZE (1)
    #else
        #define RIPE_HEAP_SAFE_SIZE (32*1024)
    #endif
#endif
/* Take a snapshot of to current heap area and save it into heap_safe. */
void save_heap(uint8_t *heap_safe);
/* Restore the heap area from the snapshot saved in heap_safe. */
void restore_heap(uint8_t *heap_safe);
/* Define how much we skip over the prologue code of rop_target() to simulate RETURN_ORIENTED_PROGRAMMING. */
size_t prologue_length (void);

/* To keep mandatory control variables out of harm, we need to make sure their
 * addresses are safe, i.e. are not between overflown buffers and their targets.
 * This is only possible in C by stuffing everything in structs... */
extern struct ripe_globals {
    bool output_debug_info;
    bool output_reasons;
    unsigned int possible;
    unsigned int impossible;
    unsigned int rtimpossible;
    unsigned int error;
    unsigned int successful;
    unsigned int failed;
    unsigned int detected;
    unsigned int illegal_instr;
    struct attack_form attack;
    struct payload payload;
    uint8_t heap_safe[RIPE_HEAP_SAFE_SIZE];
    /* Store target address after and before overflowing for debugging */
    uintptr_t target, prev_target;
    void * jump_target, * of_target, * ancestor_ret;
} g;

enum RIPE_RET {
    RET_ATTACK_SUCCESS = 42,
    RET_ATTACK_FAIL,
    RET_ATTACK_FAIL_ILLEGAL_INSTR,
    RET_ATTACK_DETECTED,
    RET_RT_IMPOSSIBLE,
    RET_ERR,
};

extern struct ripe_globals g;

/* Print out only if output_debug_info is set */
void dbg(const char *fmt, ...) __attribute__((format(__printf__, 1, 2)));
void err(const char *fmt, ...) __attribute__((format(__printf__, 1, 2)));

extern jmp_buf control_jmp_buffer;
/* longjmp implementation that does not enforce any security mechanism to
 * allow undisturbed returning via control_jmp_buffer. */
void longjmp_no_enforce (jmp_buf, int);

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
bool build_payload(struct payload *payload, ptrdiff_t offset, uint8_t * shellcode, size_t size_shellcode);

bool set_technique(char *choice, enum techniques *t);
bool set_inject_param(char *choice, enum inject_params *i);
bool set_code_ptr(char *choice, enum code_ptrs *c);
bool set_location(char *choice, enum locations *l);
bool set_function(char *choice, enum functions *f);


char *is_attack_possible(void);
void homebrew_memcpy(void *dst, const void *src, size_t len);

void build_shellcode(uint8_t **shellcode, size_t *size_shellcode, func_t *shellcode_target);

// control data destinations
void
shellcode_target(void);
void
indirect_target(void);
void
ret2libc_target(void);
void
rop_target(void);
void
dop_target(uint32_t auth);

#endif /* !RIPE_ATTACK_GENERATOR_H */
