/*
 * Standalone RISC-V compatible implementation of RIPE
 *
 * Attack params:
 * --------------
 * technique = direct, indirect
 * inject parameter = ret2libc, shellcode injection, ROP, data only
 * code pointer = return address, function pointer, vulnerable struct, longjmp buffer,
 *         non-control data variable
 * location = stack, heap, data, bss
 * function = memcpy, strcpy, strncpy, strcat, strncat, sprintf, snprintf,
 *         sscanf, homebrew memcpy
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <inttypes.h>

#include "ripe_attack_generator.h"

#define print_reason(s) // fprintf(stderr, s)

// shellcode is generated in perform_attack()
static uint8_t shellcode_nonop[12];

#ifndef RIPE_DEF_TECHNIQUE
    #define RIPE_DEF_TECHNIQUE DIRECT
#endif
#ifndef RIPE_DEF_INJECT
    #define RIPE_DEF_INJECT RETURN_ORIENTED_PROGRAMMING
#endif
#ifndef RIPE_DEF_CODE_PTR
    #define RIPE_DEF_CODE_PTR RET_ADDR
#endif
#ifndef RIPE_DEF_LOCATION
    #define RIPE_DEF_LOCATION STACK
#endif
#ifndef RIPE_DEF_FUNCTION
    #define RIPE_DEF_FUNCTION MEMCPY
#endif

// For RETURN_ORIENTED_PROGRAMMING we skip over the prologue code of
// rop_target() to simulate return-oriented programming gadget
#ifdef __riscv_compressed
  #define PROLOGUE_LENGTH 8
#else
  #define PROLOGUE_LENGTH 16
#endif

#define SECRET_STRING_START "Secret data "
#define MAX_SECRET_LEN (32)

static void attack_once(void);
static enum RIPE_RET attack_wrapper(void);
static enum RIPE_RET perform_attack(func_t **stack_func_ptr_param,
                                    jmp_buf *stack_jmp_buffer_param);
static void dummy_function(void);
static const char *hex_to_bin(char c);
static void hex_to_string(char * str, size_t val);
static void format_instruction(uint8_t *dest, size_t insn);

/* To keep mandatory control variables out of harm, we need to make sure their
 * addresses are safe, i.e. are not between overflown buffers and their targets.
 * This is only possible in C by stuffing everything in structs... */
static struct {
    bool output_debug_info;
    unsigned int possible;
    unsigned int impossible;
    unsigned int rtimpossible;
    unsigned int successful;
    unsigned int detected;
    unsigned int illegal_instr;
    struct attack_form attack;
    struct payload payload;
    uint8_t heap_safe[RIPE_HEAP_SAFE_SIZE];
} g = {
    .output_debug_info = true,
};
jmp_buf control_jmp_buffer; // We use long jmp to get back from attacks.

static struct {
    uint32_t dop_dest; // FIXME: make this global?
    /* DATA SEGMENT TARGETS
        Vulnerable struct
        FIXME: sdata is not a thing - unless we can exploit it on some platform productively.
        Overflow buffers (buffer1 for .data, buffer2 for .sdata)
        Arbitrary read data
        DOP flag
        Two general pointers for indirect attack
        Function pointer
        Longjmp buffer
    */
    struct attackme data_struct;
    uint8_t data_buffer1[256];
    uint8_t data_buffer2[8];
    char data_secret[MAX_SECRET_LEN];
    uint32_t data_flag;
    uint8_t * data_mem_ptr_aux[256];
    uint8_t * data_mem_ptr[256];
    func_t * data_func_ptr;
    jmp_buf data_jmp_buffer;
} d;

static void
init_d(void)
{
    d.dop_dest = 0xdeadc0de; // data-only target pointer

    d.data_struct = (struct attackme){ "AAAA", &dummy_function };
    strcpy((char *)d.data_buffer1, "d");
    strcpy((char *)d.data_buffer2, "dummy");
    strcpy((char *)d.data_secret, SECRET_STRING_START "DATA");
    d.data_flag = 0;
    *(uintptr_t *) d.data_mem_ptr_aux = (uintptr_t) &dummy_function;
    *(uintptr_t *) d.data_mem_ptr = (uintptr_t) &dummy_function;
    d.data_func_ptr = &dummy_function;
}

/* BSS TARGETS
    Vulnerable Struct
    Overflow buffer
    Arbitrary read data
    DOP flag
    Two general pointers for indirect attack
    Function pointer
    Longjmp buffer
*/
struct bss {
    struct attackme bss_struct;
    uint8_t bss_buffer[256];
    char bss_secret[MAX_SECRET_LEN];
    uint32_t bss_flag;
    uint8_t * bss_mem_ptr_aux;
    uint8_t * bss_mem_ptr;
    func_t * bss_func_ptr;
    jmp_buf bss_jmp_buffer;
};

static void
init_bss(struct bss *b)
{
    b->bss_struct = (struct attackme){ "AAAA", &dummy_function };
    b->bss_buffer[0] = '\0';
    strcpy(b->bss_secret, SECRET_STRING_START "BSS");
    b->bss_flag = 0;
    *(uintptr_t *) b->bss_mem_ptr_aux = (uintptr_t) &dummy_function;
    *(uintptr_t *) b->bss_mem_ptr = (uintptr_t) &dummy_function;
    b->bss_func_ptr = &dummy_function;
}

/* HEAP TARGETS
    Vulnerable struct
    Overflow buffers
    DOP flag
    Two general pointers for indirect attack
    Arbitrary read data
    Function pointer array
    Longjmp buffer
*/
struct heap_targets {
    struct attackme * heap_struct;

    // FIXME: "slightly" outdated. 3 buffers and no function pointer array
    /* Two buffers declared to be able to chose buffer that gets allocated    */
    /* first on the heap. The other buffer will be set as a target, i.e. a    */
    /* heap array of function pointers.                                       */
    uint8_t * heap_buffer1;
    uint8_t * heap_buffer2;
    uint8_t * heap_buffer3;

    uint32_t * heap_flag;
    uint8_t * heap_mem_ptr_aux;
    uint8_t * heap_mem_ptr;
    char * heap_secret;
    func_t ** heap_func_ptr_ptr;
    jmp_buf * heap_jmp_buffer;
};

static const char * const bin4b[16] = {"0000", "0001", "0010", "0011",
                                       "0100", "0101", "0110", "0111",
                                       "1000", "1001", "1010", "1011",
                                       "1100", "1101", "1110", "1111"};

// Do not count for the null terminator since a null in the shellcode will
// terminate any string function in the standard library
static size_t size_shellcode_nonop = sizeof(shellcode_nonop);

// control data destinations
void
shellcode_target(void);
void
ret2libc_target(void);
void
rop_target(void);
void
dop_target(uint8_t * buf, uint32_t auth);

// integer overflow vulnerability
void
iof(uint8_t * buf, uint32_t iv);

// arbitrary read bug
void
data_leak(uint8_t *buf);

// forces length param to register and jumps before return for stack param attacks
void
homebrew_memcpy_param(void * dst, const void * src, register size_t length);

// longjmp() is called from here
void
lj_func(jmp_buf lj_buf);

// get ret address
// ra written to stack one word higher than bp
#define OLD_BP_PTR   __builtin_frame_address(0)
#define RET_ADDR_PTR ((uintptr_t *) OLD_BP_PTR - 1)

void
set_attack_indices(size_t t, size_t i, size_t c, size_t l, size_t f)
{
    printf("Trying %zd/%zd/%zd/%zd/%zd:  ", t, i, c, l, f);
    printf("%s/%s/%s/%s/%s\n", opt_techniques[t], opt_inject_params[i], opt_code_ptrs[c], opt_locations[l], opt_funcs[f]);
    g.attack.technique = 100 + t;
    g.attack.inject_param = 200 + i;
    g.attack.code_ptr = 300 + c;
    g.attack.location = 400 + l;
    g.attack.function = 500 + f;
}

int
main(int argc, char ** argv)
{
    save_heap(g.heap_safe);

    // Set defaults
    g.attack.technique = RIPE_DEF_TECHNIQUE;
    g.attack.inject_param = RIPE_DEF_INJECT;
    g.attack.code_ptr = RIPE_DEF_CODE_PTR;
    g.attack.location = RIPE_DEF_LOCATION;
    g.attack.function = RIPE_DEF_FUNCTION;

#ifndef RIPE_NO_CLI
    if (parse_ripe_params(argc, argv, &g.attack, &g.output_debug_info) != 0) {
        fprintf(stderr, "Could not parse command line arguments\n");
        return 1;
    }
    attack_once();
    return 0;
#endif

#ifndef RIPE_DEF_ONLY
    for (size_t t = 0; t < nr_of_techniques; t++) {
        for (size_t i = 0; i < nr_of_inject_params; i++) {
            for (size_t c = 0; c < nr_of_code_ptrs; c++) {
                for (size_t l = 0; l < nr_of_locations; l++) {
                    for (size_t f = 0; f < nr_of_funcs; f++) {
                        printf("==========================================================================================\n");
                        set_attack_indices(t, i, c, l, f);
#else
#endif
                        attack_once();
                        restore_heap(g.heap_safe);
#ifndef RIPE_DEF_ONLY
                    }
                }
            }
        }
    }
    printf("%d/%d statically possible, %d are dynamically impossible, %d actually worked, %d were detected, and %d led to illegal instructions.\n",
           g.possible, g.possible+g.impossible, g.rtimpossible, g.successful, g.detected, g.illegal_instr);
#endif

    return 0;
} /* main */


__attribute__ ((weak)) void
longjmp_no_enforce (jmp_buf jb, int rv) {
    longjmp(jb, rv);
}

static void
attack_once(void) {
    if (!is_attack_possible()) {
        g.impossible++;
        return;
    }
    g.possible++;
    init_d();
    int sj = setjmp(control_jmp_buffer);
    if (sj == 0) {
        enum RIPE_RET ret = attack_wrapper();
        fprintf(stderr, "attack_wrapper() returned %d (", ret);
        switch (ret) {
            case RET_ATTACK_FAIL: fprintf(stderr, "attack failed)\n"); break;
            case RET_RT_IMPOSSIBLE: g.rtimpossible++; fprintf(stderr, "run-time check says no)\n"); break;
            case RET_ERR: fprintf(stderr, "setup error)\n"); break;
            default: fprintf(stderr, "WTF?)\n"); break;
        }
    } else {
        if (sj != RET_ATTACK_SUCCESS)
            fprintf(stderr, "setjmp() returned via longjmp %d (", sj);
        switch (sj) {
            case RET_ATTACK_SUCCESS:
                g.successful++;
                break;
            case RET_ATTACK_DETECTED:
                g.detected++;
                fprintf(stderr, "attack detected)\n");
                break;
            case RET_ATTACK_FAIL:
                fprintf(stderr, "attack failed)\n");
                break;
            case RET_ATTACK_FAIL_ILLEGAL_INSTR:
                g.illegal_instr++;
                fprintf(stderr, "illegal instruction)\n");
                break;
            default:
                fprintf(stderr, "WTF?)\n");
                break;
        }
    }
}

__attribute__ ((noinline)) // Make sure this function has its own stack frame
static enum RIPE_RET
attack_wrapper(void) {
    jmp_buf stack_jmp_buffer_param;
    func_t *stack_func_ptr_param = dummy_function;
    return perform_attack(&stack_func_ptr_param, &stack_jmp_buffer_param);
}

/********************/
/* PERFORM_ATTACK() */
/********************/
static enum RIPE_RET
perform_attack(
    func_t ** stack_func_ptr_param,
    jmp_buf *stack_jmp_buffer_param)
{
    /* STACK TARGETS
        Function Pointer
        Two general pointers for indirect attack
        DOP flag
        Arbitrary read data
        Overflow buffer
        Vulnerable struct
        Long jump buffer
    */
    struct {
        struct attackme stack_struct;
        uint8_t stack_buffer[1024];
        char stack_secret[MAX_SECRET_LEN];
        uint32_t stack_flag;
        uint8_t * stack_mem_ptr_aux;
        uint8_t * stack_mem_ptr;
        func_t * stack_func_ptr;
        jmp_buf stack_jmp_buffer;
    } stack;
    strcpy(stack.stack_secret, SECRET_STRING_START "STACK");
    stack.stack_struct.func_ptr = &dummy_function;
    stack.stack_func_ptr = &dummy_function;
    stack.stack_flag = 0;

    struct heap_targets * heap = malloc(sizeof(struct heap_targets));
    if (heap == NULL) {
        fprintf(stderr, "malloc()ing heap_targets failed!\n");
        exit(1);
    }
    memset(heap, 0, sizeof(struct heap_targets));

    heap->heap_struct = malloc(sizeof(*heap->heap_struct));
    heap->heap_buffer1 = malloc(256 + sizeof(long));
    heap->heap_buffer2 = malloc(256 + sizeof(long));
    heap->heap_buffer3 = malloc(256 + sizeof(long));
    heap->heap_flag = malloc(sizeof(int *));
    if (heap->heap_struct == NULL ||
        heap->heap_buffer1 == NULL ||
        heap->heap_buffer2 == NULL ||
        heap->heap_buffer3 == NULL ||
        heap->heap_flag == NULL) {
        fprintf(stderr, "A heap malloc() failed!\n");
        exit(1);
    }
    heap->heap_struct->func_ptr = &dummy_function;
    heap->heap_func_ptr_ptr = NULL;
    heap->heap_flag = 0;

    static struct bss b;
    init_bss(&b);

    /* Pointer to buffer to overflow */
    uint8_t * buffer;
    char * buf_name;
    /* Address to target for direct (part of) overflow */
    void * target_addr;
    char * target_name;
    /* Address for second overflow (indirect ret2libc attack) */
    void * target_addr_aux;

    // write shellcode with correct jump address
    build_shellcode(shellcode_nonop);

    switch (g.attack.location) {
        case STACK:
            // Special case for stack_struct
            if (g.attack.code_ptr == STRUCT_FUNC_PTR_STACK &&
              g.attack.technique == DIRECT)
            {
                buffer = stack.stack_struct.buffer;
                buf_name = "stack.stack_struct.buffer";
            } else {
                buffer = stack.stack_buffer;
                buf_name = "stack.stack_buffer";
            }

            // set up stack ptr with DOP target
            if (g.attack.inject_param == DATA_ONLY) {
                stack.stack_mem_ptr = (uint8_t *)&stack.stack_flag;
            }

            // Also set the location of the function pointer and the
            // longjmp buffer on the heap (the same since only choose one)
            heap->heap_func_ptr_ptr   = (func_t **)(uintptr_t)heap->heap_buffer1;
            heap->heap_jmp_buffer = (jmp_buf *)heap->heap_buffer1;
            break;
        case HEAP:
            /* Injection into heap buffer                            */

            // Special case for heap_struct
            if (g.attack.code_ptr == STRUCT_FUNC_PTR_HEAP &&
              g.attack.technique == DIRECT)
            {
                buffer = heap->heap_struct->buffer;
                buf_name = "heap->heap_struct->buffer";
                break;
            }

            if (((uintptr_t) heap->heap_buffer1 < (uintptr_t) heap->heap_buffer2) &&
              ((uintptr_t) heap->heap_buffer2 < (uintptr_t) heap->heap_buffer3))
            {
                if (g.output_debug_info) {
                    fprintf(stderr,
                      "heap buffers 1-3: 0x%0*" PRIxPTR ", 0x%0*" PRIxPTR ", 0x%0*" PRIxPTR ".\n",
                      PRIxPTR_WIDTH, (uintptr_t)heap->heap_buffer1,
                      PRIxPTR_WIDTH, (uintptr_t)heap->heap_buffer2,
                      PRIxPTR_WIDTH, (uintptr_t)heap->heap_buffer3);
                }
                buffer = heap->heap_buffer1;
                buf_name = "heap->heap_buffer1";
                // Set the location of the memory pointer on the heap
                heap->heap_mem_ptr     = heap->heap_buffer2;
                heap->heap_mem_ptr_aux = heap->heap_buffer3;

                if (g.attack.code_ptr == VAR_LEAK) {
                    heap->heap_secret = (char *)heap->heap_buffer2;
                    strcpy(heap->heap_secret, SECRET_STRING_START "HEAP");
                }
                // Also set the location of the function pointer and the
                // longjmp buffer on the heap (the same since only choose one)
                heap->heap_func_ptr_ptr = (func_t **)(uintptr_t)heap->heap_buffer3;

                // allocate the jump buffer
                heap->heap_jmp_buffer = (jmp_buf *)heap->heap_buffer3;
            } else {
                if (g.output_debug_info) {
                    fprintf(stderr,
                      "Error: Heap buffers allocated in the wrong order.\n");
                }
                return RET_ERR;
            }

            // set up heap ptr with DOP target
            if (g.attack.inject_param == DATA_ONLY) {
                heap->heap_mem_ptr = (uint8_t *)heap->heap_flag;
            }
            break;
        case DATA:
            /* Injection into data segment buffer                    */

            // Special case for stack_struct
            if (g.attack.code_ptr == STRUCT_FUNC_PTR_DATA) {
                buffer = d.data_struct.buffer;
                buf_name = "d.data_struct.buffer";
                break;
            }

            if ((g.attack.code_ptr == FUNC_PTR_DATA ||
              g.attack.code_ptr == VAR_BOF) &&
              g.attack.technique == DIRECT)
            {
                buffer = d.data_buffer2;
                buf_name = "d.data_buffer2";
            } else {
                buffer = d.data_buffer1;
                buf_name = "d.data_buffer1";
            }

            // set up data ptr with DOP target
            if (g.attack.inject_param == DATA_ONLY) {
                *d.data_mem_ptr = (uint8_t *)&d.data_flag;
            }
            // Also set the location of the function pointer and the
            // longjmp buffer on the heap (the same since only choose one)
            heap->heap_jmp_buffer = (jmp_buf *)heap->heap_buffer1;
            break;
        case BSS:
            /* Injection into BSS buffer                             */

            // Special case for bss_struct
            if (g.attack.code_ptr == STRUCT_FUNC_PTR_BSS) {
                buffer = b.bss_struct.buffer;
                buf_name = "b.bss_struct.buffer";
                break;
            }

            buffer = b.bss_buffer;
            buf_name = "b.bss_buffer";

            b.bss_mem_ptr_aux = (uint8_t*)(uintptr_t)&dummy_function;
            b.bss_mem_ptr     = (uint8_t*)(uintptr_t)&dummy_function;

            // set up bss ptr with DOP target
            if (g.attack.inject_param == DATA_ONLY) {
                b.bss_mem_ptr = (uint8_t *)&b.bss_flag;
            }
            // Also set the location of the function pointer on the heap
            break;
    }

    // make sure we actually have an initialized function pointer on the heap
    if (heap->heap_func_ptr_ptr != NULL)
        *heap->heap_func_ptr_ptr = &dummy_function;

    // Set Target Address
    switch (g.attack.technique) {
        case DIRECT:
            switch (g.attack.code_ptr) {
                case RET_ADDR:
                    target_addr = RET_ADDR_PTR;
                    target_name = "RET_ADDR_PTR";
                    break;
                case FUNC_PTR_STACK_VAR:
                    target_addr = &stack.stack_func_ptr;
                    target_name = "&stack.stack_func_ptr";
                    break;
                case FUNC_PTR_STACK_PARAM:
                    target_addr = stack_func_ptr_param;
                    target_name = "stack_func_ptr_param";
                    break;
                case FUNC_PTR_HEAP:
                    target_addr = heap->heap_func_ptr_ptr;
                    target_name = "heap->heap_func_ptr_ptr";
                    break;
                case FUNC_PTR_BSS:
                    target_addr = &b.bss_func_ptr;
                    target_name = "&b.bss_func_ptr";
                    break;
                case FUNC_PTR_DATA:
                    target_addr = &d.data_func_ptr;
                    target_name = "&d.data_func_ptr";
                    break;
                case LONGJMP_BUF_STACK_VAR:
                    target_addr = stack.stack_jmp_buffer;
                    target_name = "stack.stack_jmp_buffer";
                    break;
                case LONGJMP_BUF_STACK_PARAM:
                    target_addr = stack_jmp_buffer_param;
                    target_name = "stack_jmp_buffer_param";
                    break;
                case LONGJMP_BUF_HEAP:
                    target_addr = heap->heap_jmp_buffer;
                    target_name = "heap->heap_jmp_buffer";
                    break;
                case LONGJMP_BUF_DATA:
                    target_addr = d.data_jmp_buffer;
                    target_name = "d.data_jmp_buffer";
                    break;
                case LONGJMP_BUF_BSS:
                    target_addr = b.bss_jmp_buffer;
                    target_name = "b.bss_jmp_buffer";
                    break;
                case STRUCT_FUNC_PTR_STACK:
                    target_addr = &stack.stack_struct.func_ptr;
                    target_name = "&stack.stack_struct.func_ptr";
                    break;
                case STRUCT_FUNC_PTR_HEAP:
                    target_addr = &heap->heap_struct->func_ptr;
                    target_name = "heap->heap_struct.func_ptr";
                    break;
                case STRUCT_FUNC_PTR_DATA:
                    target_addr = &d.data_struct.func_ptr;
                    target_name = "&d.data_struct.func_ptr";
                    break;
                case STRUCT_FUNC_PTR_BSS:
                    target_addr = &b.bss_struct.func_ptr;
                    target_name = "&b.bss_struct.func_ptr";
                    break;
                case VAR_BOF:
                // if data-only, location determines target
                case VAR_IOF:
                    switch (g.attack.location) {
                        case STACK:
                            target_addr = &stack.stack_flag;
                            target_name = "&stack.stack_flag";
                            break;
                        case HEAP:
                            target_addr = heap->heap_flag;
                            target_name = "heap->heap_flag";
                            break;
                        case DATA:
                            target_addr = &d.data_flag;
                            target_name = "&d.data_flag";
                            break;
                        case BSS:
                            target_addr = &b.bss_flag;
                            target_name = "&b.bss_flag";
                            break;
                    }
                    break;
                case VAR_LEAK:
                    switch (g.attack.location) {
                        case STACK:
                            target_addr = &stack.stack_secret;
                            target_name = "&stack.stack_secret";
                            break;
                        case HEAP:
                            target_addr = heap->heap_secret;
                            target_name = "heap->heap_secret";
                            break;
                        case DATA:
                            target_addr = &d.data_secret;
                            target_name = "&d.data_secret";
                            break;
                        case BSS:
                            target_addr = &b.bss_secret;
                            target_name = "&b.bss_secret";
                            break;
                    }
                    break;
            }
            break;

        case INDIRECT:
            switch (g.attack.location) {
                case STACK:
                    target_addr     = &stack.stack_mem_ptr;
                    target_addr_aux = &stack.stack_mem_ptr_aux;
                    target_name        = "&stack.stack_mem_ptr (indirect)";
                    break;
                case HEAP:
                    target_addr     = heap->heap_mem_ptr;
                    target_addr_aux = heap->heap_mem_ptr_aux;
                    target_name        = "heap->heap_mem_ptr (indirect)";
                    break;
                case DATA:
                    target_addr     = &d.data_mem_ptr;
                    target_addr_aux = &d.data_mem_ptr_aux;
                    target_name        = "&d.data_mem_ptr (indirect)";
                    break;
                case BSS:
                    target_addr     = &b.bss_mem_ptr;
                    target_addr_aux = &b.bss_mem_ptr_aux;
                    target_name        = "&b.bss_mem_ptr (indirect)";
                    break;
            }
            break;
    }

    // set longjmp buffers
    switch (g.attack.code_ptr) {
        case LONGJMP_BUF_STACK_VAR:
            if (setjmp(stack.stack_jmp_buffer) != 0) {
                /* setjmp() returns 0 if returning directly and non-zero when returning */
                /* from longjmp() using the saved context. Attack failed.               */
                printf("Longjmp attack failed. Returning normally...\n");
                return RET_ATTACK_FAIL;
            }
            break;
        case LONGJMP_BUF_STACK_PARAM:
            if (setjmp(*stack_jmp_buffer_param) != 0) {
                printf("Longjmp attack failed. Returning normally...\n");
                return RET_ATTACK_FAIL;
            }
            break;
        case LONGJMP_BUF_HEAP:
            if (setjmp(*heap->heap_jmp_buffer) != 0) {
                printf("Longjmp attack failed. Returning normally...\n");
                return RET_ATTACK_FAIL;
            }
            break;
        case LONGJMP_BUF_DATA:
            if (setjmp(d.data_jmp_buffer) != 0) {
                printf("Longjmp attack failed. Returning normally...\n");
                return RET_ATTACK_FAIL;
            }
            break;
        case LONGJMP_BUF_BSS:
            if (setjmp(b.bss_jmp_buffer) != 0) {
                printf("Longjmp attack failed. Returning normally...\n");
                return RET_ATTACK_FAIL;
            }
            break;
        default:
            break;
    }

    switch (g.attack.technique) {
        case DIRECT:
            switch (g.attack.inject_param) {
                case RETURN_INTO_LIBC:
                    // simulate ret2libc by invoking mock libc function
                    g.payload.overflow_ptr = (void *)(uintptr_t)&ret2libc_target;
                    break;
                case RETURN_ORIENTED_PROGRAMMING:
                    g.payload.overflow_ptr = (void *)((uintptr_t)&rop_target + PROLOGUE_LENGTH);
                    break;
                case INJECTED_CODE_NO_NOP:
                    g.payload.overflow_ptr = buffer;
                    break;
                case DATA_ONLY:
                    // corrupt variable with nonzero value
                    g.payload.overflow_ptr = (void *)0xdeadc0de;
                    break;
                default:
                    if (g.output_debug_info) {
                        fprintf(stderr, "Unknown choice of attack code");
                        return RET_ERR;
                    }
            }
            break;
        case INDIRECT:
            /* Here payload.overflow_ptr will point to the final pointer target   */
            /* since an indirect attack first overflows a general pointer that in */
            /* turn is dereferenced to overwrite the target pointer               */
            switch (g.attack.code_ptr) {
                case RET_ADDR:
                    g.payload.overflow_ptr = RET_ADDR_PTR;
                    break;
                case FUNC_PTR_STACK_VAR:
                    g.payload.overflow_ptr = &stack.stack_func_ptr;
                    break;
                case FUNC_PTR_STACK_PARAM:
                    g.payload.overflow_ptr = stack_func_ptr_param;
                    break;
                case FUNC_PTR_HEAP:
                    g.payload.overflow_ptr = (void *)(uintptr_t)heap->heap_func_ptr_ptr;
                    break;
                case FUNC_PTR_BSS:
                    g.payload.overflow_ptr = &b.bss_func_ptr;
                    break;
                case FUNC_PTR_DATA:
                    g.payload.overflow_ptr = &d.data_func_ptr;
                    break;
                case STRUCT_FUNC_PTR_STACK:
                    g.payload.overflow_ptr = &stack.stack_struct.func_ptr;
                    break;
                case STRUCT_FUNC_PTR_HEAP:
                    g.payload.overflow_ptr = &heap->heap_struct->func_ptr;
                    break;
                case STRUCT_FUNC_PTR_DATA:
                    g.payload.overflow_ptr = &d.data_struct.func_ptr;
                    break;
                case STRUCT_FUNC_PTR_BSS:
                    g.payload.overflow_ptr = &b.bss_struct.func_ptr;
                    break;
                case LONGJMP_BUF_STACK_VAR:
                    g.payload.overflow_ptr = stack.stack_jmp_buffer;
                    break;
                case LONGJMP_BUF_STACK_PARAM:
                    g.payload.overflow_ptr = stack_jmp_buffer_param;
                    break;
                case LONGJMP_BUF_HEAP:
                    g.payload.overflow_ptr = *heap->heap_jmp_buffer;
                    break;
                case LONGJMP_BUF_DATA:
                    g.payload.overflow_ptr = d.data_jmp_buffer;
                    break;
                case LONGJMP_BUF_BSS:
                    g.payload.overflow_ptr = b.bss_jmp_buffer;
                    break;
                // indirect attacks don't apply to int overflows or leaks
                case VAR_BOF:
                case VAR_IOF:
                case VAR_LEAK:
                    g.payload.overflow_ptr = &d.dop_dest;
                    break;
                default:
                    if (g.output_debug_info) {
                        fprintf(stderr,
                          "Error: Unknown choice of code pointer\n");
                    }
                    return RET_ERR;
            }
            break;
    }

    if (g.output_debug_info) {
        fprintf(stderr, "target_addr (%s) == %p\n", target_name, target_addr);
        fprintf(stderr, "buffer (%s) == %p\n", buf_name, (void *)buffer);
    }

    ptrdiff_t target_offset = target_addr - (void*)buffer;
    if (target_offset < 0) {
        if (g.output_debug_info)
            fprintf(stderr, "target_addr (0x%0*" PRIxPTR ") has to be > buffer (0x%0*" PRIxPTR "), but isn't.\n",
              PRIxPTR_WIDTH, (uintptr_t)target_addr, PRIxPTR_WIDTH, (uintptr_t)buffer);
        return RET_ERR;
    }

    /* Set first byte of buffer to null to allow concatenation functions to */
    /* start filling the buffer from that first byte                        */
    buffer[0] = '\0';

    if (!build_payload(&g.payload, target_offset)) {
        if (g.output_debug_info)
            fprintf(stderr, "Error: Could not build payload\n");
        return RET_RT_IMPOSSIBLE;
    }

    /****************************************/
    /* Overflow buffer with chosen function */
    /* Note: Here memory will be corrupted  */
    /****************************************/

    printf("\nCorrupting data and executing test...\n");

    uintptr_t attack_ret = 0;
    switch (g.attack.function) {
        case MEMCPY:
            // memcpy() shouldn't copy the terminating NULL, therefore - 1
            attack_ret = (uintptr_t)memcpy(buffer, g.payload.buffer, g.payload.size - 1);
            break;
        case STRCPY:
            attack_ret = (uintptr_t)strcpy((char *)buffer, g.payload.buffer);
            break;
        case STRNCPY:
            attack_ret = (uintptr_t)strncpy((char *)buffer, g.payload.buffer, g.payload.size);
            break;
        case SPRINTF:
             attack_ret = sprintf((char *)buffer, "%s", g.payload.buffer);
            break;
        case SNPRINTF:
            attack_ret = snprintf((char *)buffer, g.payload.size, "%s", g.payload.buffer);
            break;
        case STRCAT:
            attack_ret = (uintptr_t)strcat((char *)buffer, g.payload.buffer);
            break;
        case STRNCAT:
            attack_ret = (uintptr_t)strncat((char *)buffer, g.payload.buffer, g.payload.size);
            break;
        case SSCANF: {
            char fmt[16];
            snprintf(fmt, sizeof(fmt)-1, "%%%ic", g.payload.size);
            attack_ret = sscanf(g.payload.buffer, fmt, buffer);
            break;
        }
        case HOMEBREW:
            homebrew_memcpy(buffer, g.payload.buffer, g.payload.size - 1);
            break;
        default:
            if (g.output_debug_info)
                fprintf(stderr, "Error: Unknown choice of function\n");
            return RET_ERR;
    }
    if (attack_ret != 0 && g.output_debug_info)
        fprintf(stderr, "attack function returned %d/0x%x\n", attack_ret, attack_ret);

    /*******************************************/
    /* Ensure that code pointer is overwritten */
    /*******************************************/

    switch (g.attack.technique) {
        case DIRECT:
            /* Code pointer already overwritten */
            break;
        case INDIRECT:
            // zero out junk byte written to general pointer
            if (g.attack.function == SSCANF) {
                *(uint32_t *) target_addr <<= 8;
                *(uint32_t *) target_addr >>= 8;
            }

            if (g.attack.inject_param == RETURN_INTO_LIBC) {
                // auxilliary overflow to give attacker control of a second general ptr
                g.payload.overflow_ptr = (void *)(uintptr_t)&ret2libc_target;
                // FIXME
                ptrdiff_t indirect_offset = target_addr_aux - (void*)buffer;
                if (indirect_offset < 0) {
                    if (g.output_debug_info)
                        fprintf(stderr, "target_addr_aux (0x%0*" PRIxPTR ") has to be > buffer (0x%0*" PRIxPTR "), but isn't.\n",
                          PRIxPTR_WIDTH, (uintptr_t)target_addr_aux, PRIxPTR_WIDTH, (uintptr_t)buffer);
                    return RET_ERR;
                }

                printf("target_addr_aux: %p\n", target_addr_aux);
                build_payload(&g.payload, indirect_offset);
                memcpy(buffer, g.payload.buffer, g.payload.size - 1);

                switch (g.attack.location) {
                    case STACK:
                        *(uint32_t *) (*(uint32_t *) target_addr) =
                          (uintptr_t) stack.stack_mem_ptr_aux;
                        break;
                    case HEAP:
                        *(uint32_t *) (*(uint32_t *) target_addr) =
                          (uintptr_t) *heap->heap_mem_ptr_aux;
                        break;
                    case DATA:
                        *(uint32_t *) (*(uint32_t *) target_addr) =
                          (uintptr_t) *d.data_mem_ptr_aux;
                        break;
                    case BSS:
                        *(uint32_t *) (*(uint32_t *) target_addr) =
                          (uintptr_t) b.bss_mem_ptr_aux;
                        break;
                }
            } else if (g.attack.inject_param == INJECTED_CODE_NO_NOP) {
                *(uintptr_t *) (*(uintptr_t *) target_addr) =
                  (uintptr_t) buffer;
            }
            break;
        default:
            if (g.output_debug_info)
                fprintf(stderr, "Error: Unknown choice of attack technique.\n");
            return RET_ERR;
    }

    switch (g.attack.code_ptr) {
        case RET_ADDR:
            break;
        case FUNC_PTR_STACK_VAR:
            stack.stack_func_ptr();
            break;
        case FUNC_PTR_STACK_PARAM:
            (**stack_func_ptr_param)();
            break;
        case FUNC_PTR_HEAP:
            (*heap->heap_func_ptr_ptr)();
            break;
        case FUNC_PTR_BSS:
            (*b.bss_func_ptr)();
            break;
        case FUNC_PTR_DATA:
            (*d.data_func_ptr)();
            break;
        case LONGJMP_BUF_STACK_VAR:
            lj_func(stack.stack_jmp_buffer);
            break;
        case LONGJMP_BUF_STACK_PARAM:
            lj_func(*stack_jmp_buffer_param);
            break;
        case LONGJMP_BUF_HEAP:
            lj_func(*heap->heap_jmp_buffer);
            break;
        case LONGJMP_BUF_DATA:
            lj_func(d.data_jmp_buffer);
            break;
        case LONGJMP_BUF_BSS:
            lj_func(b.bss_jmp_buffer);
            break;
        case STRUCT_FUNC_PTR_STACK:
            (*stack.stack_struct.func_ptr)();
            break;
        case STRUCT_FUNC_PTR_HEAP:
            (*heap->heap_struct->func_ptr)();
            break;
        case STRUCT_FUNC_PTR_DATA:
            (*d.data_struct.func_ptr)();
            break;
        case STRUCT_FUNC_PTR_BSS:
            (*b.bss_struct.func_ptr)();
            break;
        case VAR_BOF:
        case VAR_IOF:
            switch (g.attack.location) {
                case STACK:
                    dop_target(buffer, *stack.stack_mem_ptr);
                    break;
                case HEAP:
                    dop_target(buffer, *heap->heap_mem_ptr);
                    break;
                case DATA:
                    dop_target(buffer, **d.data_mem_ptr);
                    break;
                case BSS:
                    dop_target(buffer, *b.bss_mem_ptr);
                    break;
            }
            break;
        case VAR_LEAK:
            data_leak(buffer);
            break;
    }
    return RET_ATTACK_FAIL;
} /* perform_attack */

/*******************/
/* BUILD_PAYLOAD() */
/*******************/
bool
build_payload(struct payload * payload, ptrdiff_t offset)
{
    size_t size_shellcode = 0, bytes_to_pad;
    uint8_t * shellcode = NULL;

    /* + 1 for null termination so that buffer can be */
    /* used with string functions in standard library */
    payload->size = (offset + sizeof(uintptr_t) + 1);

    switch (g.attack.inject_param) {
        case INJECTED_CODE_NO_NOP:
            if (payload->size < (size_shellcode_nonop + sizeof(func_t*))) {
                return false;
            }
            shellcode      = shellcode_nonop;
            size_shellcode = size_shellcode_nonop;
            break;
        case DATA_ONLY:
            // 256 padding bytes for unsigned 8bit IOF
            if (g.attack.code_ptr == VAR_IOF)
                payload->size = 256 + sizeof(long) + sizeof(char);
            
            if (g.attack.code_ptr == VAR_LEAK) {
                /* The buffer stores the offset ORed with a mask and the mask itself,
                 * simulating a data packet with an encoded length field.
                 * The mask ensures compatibility with string functions. */
                payload->size = 2*sizeof(size_t) + sizeof(char);
                payload->buffer = malloc(payload->size);
                size_t mask = (offset & 0x01010101);
                *(((size_t*)payload->buffer)+1) = mask | 0x10101010;
                *(size_t*)payload->buffer = offset | 0x01010101;
                payload->buffer[payload->size-1] = '\0';
                return true;
            } /* else fall through */
        case RETURN_ORIENTED_PROGRAMMING:
        case RETURN_INTO_LIBC:
            if (payload->size < sizeof(long))
                return false;
            break;
        default:
            return false;
    }
    /* Allocate payload buffer */
    payload->buffer = malloc(payload->size);

    /* Copy shellcode into payload buffer */
    memcpy(payload->buffer, shellcode, size_shellcode);

    /* Calculate number of bytes to pad with */
    /* size - shellcode - target address - null terminator */
    bytes_to_pad =
      (payload->size - size_shellcode - sizeof(void *) - sizeof(char));

    /* Pad payload buffer with dummy bytes */
    memset((payload->buffer + size_shellcode), 'A', bytes_to_pad);

    if (g.output_debug_info) {
        fprintf(stderr, "bytes to pad: %zd\n", bytes_to_pad);
        fprintf(stderr, "\noverflow_ptr: %p\n", payload->overflow_ptr);
    }

    /* Add the address to the direct or indirect target */
    if (g.attack.code_ptr != VAR_IOF) {
        memcpy(&(payload->buffer[size_shellcode + bytes_to_pad]),
          &payload->overflow_ptr,
          sizeof(void *));
    }

    char *first_null = memchr(payload->buffer, '\0', payload->size-1);
    if (first_null != NULL) {
        fprintf(stderr, "Payload contains null character at offset %"PRIdPTR"\n",
            (uintptr_t)first_null-(uintptr_t)payload->buffer);
        if (g.attack.function == SSCANF ||
            g.attack.function == STRCPY ||
            g.attack.function == STRNCPY ||
            g.attack.function == SPRINTF ||
            g.attack.function == SNPRINTF ||
            g.attack.function == STRCAT ||
            g.attack.function == STRNCAT) {
            fprintf(stderr, "This cannot work with string functions, aborting\n");
            return false;
        }
    }

    /* Finally, add the terminating null character at the end */
    memset((payload->buffer + payload->size - 1), '\0', 1);
    
    if (g.output_debug_info)
        fprintf(stderr, "payload of %d bytes created.\n", payload->size);
    return true;
} /* build_payload */

static void
dummy_function(void) {
    printf("Dummy function\n");
}

// call longjmp on a buffer in perform_attack()
void
lj_func(jmp_buf lj_buf)
{
    longjmp(lj_buf, 1111);
}

void
homebrew_memcpy(void * dst, const void * src, size_t length)
{
    char * d, * s;

    d = (char *) dst;
    s = (char *) src;

    while (length--) {
        *d++ = *s++;
    }
}

void
shellcode_target()
{
    printf("shellcode_target() reached.\n");
    longjmp_no_enforce(control_jmp_buffer, RET_ATTACK_SUCCESS);
}

void
ret2libc_target()
{
    printf("ret2libc_target() reached.\n");
    longjmp_no_enforce(control_jmp_buffer, RET_ATTACK_SUCCESS);
}

void
dop_target(uint8_t * buf, uint32_t auth)
{
    size_t auth_loc = auth;

    if (g.attack.code_ptr == VAR_IOF) {
        iof(buf, (uintptr_t)&auth_loc);
    }

    if (!auth_loc) {
        printf("DOP attack failed\n");
        longjmp_no_enforce(control_jmp_buffer, RET_ATTACK_FAIL);
    } else {
        printf("DOP memory corruption reached.\n");
        longjmp_no_enforce(control_jmp_buffer, RET_ATTACK_SUCCESS);
    }
}

__attribute__ ((optimize (0))) // Make sure prologue length does not change
void
rop_target(void)
{
    printf("ROP function reached.\n");
    longjmp_no_enforce(control_jmp_buffer, RET_ATTACK_SUCCESS);
}

void
iof(uint8_t * buf, uint32_t iv)
{
    char * map;
    uint32_t key = iv;
    size_t len  = strlen((char *)buf);

    // 0-length allocation and vulenrable hash operations
    map      = malloc(len * sizeof(uint8_t));
    key     -= (uintptr_t) map;
    key     &= (uint16_t) len - 1;
    map[key] = 0xa1;
}

void
data_leak(uint8_t *buf) {
    size_t size = *(size_t*)buf;
    size_t mask = *((size_t*)buf+1);
    size = (size & ~0x01010101) | (0x01010101 & mask);
    uint8_t *msg = malloc(size);
    if (msg == NULL) {
        fprintf(stderr, "malloc()ing data_leak buffer failed!\n");
        exit(1);
    }
    fprintf(stderr, "%s: allocated %zd B\n", __func__, size);

    size_t common_len = strlen(SECRET_STRING_START);
    const char *loc_string;
    switch (g.attack.location) {
        case BSS: loc_string = "BSS"; break;
        case DATA: loc_string = "DATA"; break;
        case HEAP: loc_string = "HEAP"; break;
        case STACK: loc_string = "STACK"; break;
        default:
            fprintf(stderr, "%s: location %d not implemented.\n",
            __func__, g.attack.location);
            return;
    }

    memcpy(msg, buf + size, size);
    if ((strncmp((char *)msg, SECRET_STRING_START, common_len) == 0) &&
        (strcmp((char *)(msg+common_len), loc_string) == 0)) {
        fprintf(stderr, "%s: found correct secret: \"%s\"\n", __func__, msg);
        longjmp_no_enforce(control_jmp_buffer, RET_ATTACK_SUCCESS);
    }
    fprintf(stderr, "msg does not match secret string\n");
}

/*********************/
/* BUILD_SHELLCODE() */
/*********************/
void
build_shellcode(uint8_t * shellcode)
{
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

    format_instruction(shellcode, lui_val);
    format_instruction(shellcode + 4, addi_val);
    format_instruction(shellcode + 8, jalr_val);

    char lui_s[9], addi_s[9]; // hex insn encodings
    hex_to_string(lui_s, lui_val);
    lui_s[8] = '\0';
    hex_to_string(addi_s, addi_val);
    addi_s[8] = '\0';

    if (g.output_debug_info) {
        printf("----------------\nShellcode instructions:\n");
        printf("%s0x%-20s%14s\n", "lui t1,  ", high_bits, lui_s);
        printf("%s0x%-20s%10s\n", "addi t1, t1, ", low_bits, addi_s);
        printf("%s%30s%08"PRIx32"\n", "jalr t1", " ", jalr_val);
    }
} /* build_shellcode */

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

bool
is_attack_possible()
{
    if ((g.attack.inject_param == INJECTED_CODE_NO_NOP) &&
      (!(g.attack.function == MEMCPY) && !(g.attack.function == HOMEBREW)))
    {
        print_reason("Error: Impossible to inject shellcode with string functions (for now)\n");
        return false;
    }

    if (g.attack.inject_param == RETURN_ORIENTED_PROGRAMMING &&
      g.attack.technique != DIRECT)
    {
        print_reason("Error: Impossible (theoretically) to perform indirect ROP attacks\n");
        return false;
    }

    if (g.attack.inject_param == DATA_ONLY) {
        if (g.attack.code_ptr != VAR_BOF &&
            g.attack.code_ptr != VAR_IOF &&
            g.attack.code_ptr != VAR_LEAK)
        {
            print_reason("Error: Misused DOP code pointer parameters.\n");
            return false;
        }

        if ((g.attack.code_ptr == VAR_LEAK || g.attack.code_ptr == VAR_IOF) && g.attack.technique == INDIRECT) {
            print_reason("Error: Impossible to do an indirect int overflow attack.\n");
            return false;
        }

        if (g.attack.location == HEAP && g.attack.technique == INDIRECT) {
            print_reason("Error: Impossible to indirect attack the heap flag.\n");
            return false;
        }
    } else if (g.attack.code_ptr == VAR_BOF ||
               g.attack.code_ptr == VAR_IOF ||
               g.attack.code_ptr == VAR_LEAK) {
        print_reason("Error: Must use \"dataonly\" injection parameter for DOP attacks.\n");
        return false;
    }

    // attacks targeting another memory location must be indirect
    switch (g.attack.location) {
        case STACK:
            if (g.attack.technique == DIRECT) {
                if ((g.attack.code_ptr == FUNC_PTR_HEAP) ||
                  (g.attack.code_ptr == FUNC_PTR_BSS) ||
                  (g.attack.code_ptr == FUNC_PTR_DATA) ||
                  (g.attack.code_ptr == LONGJMP_BUF_HEAP) ||
                  (g.attack.code_ptr == LONGJMP_BUF_DATA) ||
                  (g.attack.code_ptr == LONGJMP_BUF_BSS) ||
                  (g.attack.code_ptr == STRUCT_FUNC_PTR_HEAP) ||
                  (g.attack.code_ptr == STRUCT_FUNC_PTR_DATA) ||
                  (g.attack.code_ptr == STRUCT_FUNC_PTR_BSS) )
                {
                    print_reason("Error: Impossible to perform a direct attack on the stack into another memory segment.\n");
                    return false;
                }
            }
            break;

        case HEAP:
            if ((g.attack.technique == DIRECT) &&
              ((g.attack.code_ptr == RET_ADDR) ||
              (g.attack.code_ptr == FUNC_PTR_STACK_VAR) ||
              (g.attack.code_ptr == FUNC_PTR_STACK_PARAM) ||
              (g.attack.code_ptr == FUNC_PTR_BSS) ||
              (g.attack.code_ptr == FUNC_PTR_DATA) ||
              (g.attack.code_ptr == LONGJMP_BUF_STACK_VAR) ||
              (g.attack.code_ptr == LONGJMP_BUF_STACK_PARAM) ||
              (g.attack.code_ptr == LONGJMP_BUF_BSS) ||
              (g.attack.code_ptr == LONGJMP_BUF_DATA) ||
              (g.attack.code_ptr == STRUCT_FUNC_PTR_STACK) ||
              (g.attack.code_ptr == STRUCT_FUNC_PTR_DATA) ||
              (g.attack.code_ptr == STRUCT_FUNC_PTR_BSS) ))
            {
                print_reason("Error: Impossible to perform a direct attack on the heap into another memory segment.\n");
                return false;
            }
            break;

        case DATA:
            if ((g.attack.technique == DIRECT) &&
              ((g.attack.code_ptr == RET_ADDR) ||
              (g.attack.code_ptr == FUNC_PTR_STACK_VAR) ||
              (g.attack.code_ptr == FUNC_PTR_STACK_PARAM) ||
              (g.attack.code_ptr == FUNC_PTR_BSS) ||
              (g.attack.code_ptr == FUNC_PTR_HEAP) ||
              (g.attack.code_ptr == LONGJMP_BUF_STACK_VAR) ||
              (g.attack.code_ptr == LONGJMP_BUF_STACK_PARAM) ||
              (g.attack.code_ptr == LONGJMP_BUF_HEAP) ||
              (g.attack.code_ptr == LONGJMP_BUF_BSS) ||
              (g.attack.code_ptr == STRUCT_FUNC_PTR_STACK) ||
              (g.attack.code_ptr == STRUCT_FUNC_PTR_HEAP) ||
              (g.attack.code_ptr == STRUCT_FUNC_PTR_BSS) ))
            {
                print_reason("Error: Impossible to perform a direct attack on the data segment into another memory segment.\n");
                return false;
            }
            break;

        case BSS:
            if ((g.attack.technique == DIRECT) &&
              ((g.attack.code_ptr == RET_ADDR) ||
              (g.attack.code_ptr == FUNC_PTR_STACK_VAR) ||
              (g.attack.code_ptr == FUNC_PTR_STACK_PARAM) ||
              (g.attack.code_ptr == FUNC_PTR_DATA) ||
              (g.attack.code_ptr == FUNC_PTR_HEAP) ||
              (g.attack.code_ptr == LONGJMP_BUF_STACK_VAR) ||
              (g.attack.code_ptr == LONGJMP_BUF_STACK_PARAM) ||
              (g.attack.code_ptr == LONGJMP_BUF_HEAP) ||
              (g.attack.code_ptr == LONGJMP_BUF_DATA) ||
              (g.attack.code_ptr == STRUCT_FUNC_PTR_STACK) ||
              (g.attack.code_ptr == STRUCT_FUNC_PTR_HEAP) ||
              (g.attack.code_ptr == STRUCT_FUNC_PTR_DATA) ))
            {
                print_reason("Error: Impossible to perform a direct attack on the bss into another memory segment.\n");
                return false;
            }
            break;
    }

    return true;
} /* is_attack_possible */
