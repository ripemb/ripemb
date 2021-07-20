#ifndef RIPE_NO_CLI
    #define _POSIX_C_SOURCE 200809L
    #include <unistd.h>
#endif
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "ripe_attack_generator.h"

/* 2 overflow techniques */
__attribute__ ((section (".rodata")))
const char * const opt_techniques[] = {"direct", "indirect"};
size_t nr_of_techniques = ARR_ELEMS(opt_techniques);

/* 5 types of injection parameters */
__attribute__ ((section (".rodata")))
const char * const opt_inject_params[] = {"shellcode", "returnintolibc", "rop", "return_into_ancestor", "dataonly"};
size_t nr_of_inject_params = ARR_ELEMS(opt_inject_params);

/* 13 code pointers to overwrite */
__attribute__ ((section (".rodata")))
const char * const opt_code_ptrs[] = {"ret", "funcptrstackvar", "funcptrstackparam",
                                      "funcptrheap", "funcptrbss", "funcptrdata",
                                      "longjmpstackvar", "longjmpstackparam",
                                      "longjmpheap", "longjmpbss", "longjmpdata",
                                      "bof", "leak"};
size_t nr_of_code_ptrs = ARR_ELEMS(opt_code_ptrs);

/* 4 memory locations */
__attribute__ ((section (".rodata")))
const char * const opt_locations[] = {"stack", "heap", "bss", "data"};
size_t nr_of_locations = ARR_ELEMS(opt_locations);

/* 9 vulnerable functions */
__attribute__ ((section (".rodata")))
const char * const opt_funcs[] = {"memcpy", "homebrew", "sscanf", "strcpy", "strncpy", "sprintf", "snprintf",
                                  "strcat", "strncat"};
size_t nr_of_funcs = ARR_ELEMS(opt_funcs);

#ifndef RIPE_NO_CLI
int parse_ripe_params(int argc, char ** argv, struct attack_form *attack, bool *debug) {
    int rv = 0;
    int c;
    while ((c = getopt(argc, argv, "t:i:c:l:f:d")) != -1) {
        switch (c) {
            case 't':
                rv |= set_technique(optarg, &attack->technique);
                break;
            case 'i':
                rv |= set_inject_param(optarg, &attack->inject_param);
                break;
            case 'c':
                rv |= set_code_ptr(optarg, &attack->code_ptr);
                break;
            case 'l':
                rv |= set_location(optarg, &attack->location);
                break;
            case 'f':
                rv |= set_function(optarg, &attack->function);
                break;
            case 'd':
                *debug = true;
                fprintf(stderr, "debug info enabled\n");
                break;
            default:
                return 1;
        }
    }
    if (argv[optind] != NULL) {
        fprintf(stderr, "Error: unknown argument(s) after options: \"%s\"\n",
          argv[optind]);
        return 1;
    }
    return rv;
}

bool
set_technique(char * choice, enum techniques *t)
{
    if (strcmp(choice, opt_techniques[0]) == 0) {
        *t =  DIRECT;
    } else if (strcmp(choice, opt_techniques[1]) == 0) {
        *t =  INDIRECT;
    } else {
        fprintf(stderr, "Error: Unknown choice of technique \"%s\"\n",
          choice);
        return 1;
    }
    return 0;
}

bool
set_inject_param(char * choice, enum inject_params *i)
{
    if (strcmp(choice, opt_inject_params[0]) == 0) {
        *i = INJECTED_CODE_NO_NOP;
    } else if (strcmp(choice, opt_inject_params[1]) == 0) {
        *i = RETURN_INTO_LIBC;
    } else if (strcmp(choice, opt_inject_params[2]) == 0) {
        *i = RETURN_ORIENTED_PROGRAMMING;
    } else if (strcmp(choice, opt_inject_params[3]) == 0) {
        return RETURN_INTO_ANCESTOR;
    } else if (strcmp(choice, opt_inject_params[4]) == 0) {
        return DATA_ONLY;
    } else {
        fprintf(stderr,
          "Error: Unknown choice of injection parameter \"%s\"\n",
          choice);
        return 1;
    }
    return 0;
}

bool
set_code_ptr(char * choice, enum code_ptrs *c)
{
    if (strcmp(choice, opt_code_ptrs[0]) == 0) {
        *c = RET_ADDR;
    } else if (strcmp(choice, opt_code_ptrs[1]) == 0) {
        *c = FUNC_PTR_STACK_VAR;
    } else if (strcmp(choice, opt_code_ptrs[2]) == 0) {
        *c = FUNC_PTR_STACK_PARAM;
    } else if (strcmp(choice, opt_code_ptrs[3]) == 0) {
        *c = FUNC_PTR_HEAP;
    } else if (strcmp(choice, opt_code_ptrs[4]) == 0) {
        *c = FUNC_PTR_BSS;
    } else if (strcmp(choice, opt_code_ptrs[5]) == 0) {
        *c = FUNC_PTR_DATA;
    } else if (strcmp(choice, opt_code_ptrs[6]) == 0) {
        *c = LONGJMP_BUF_STACK_VAR;
    } else if (strcmp(choice, opt_code_ptrs[7]) == 0) {
        *c = LONGJMP_BUF_STACK_PARAM;
    } else if (strcmp(choice, opt_code_ptrs[8]) == 0) {
        *c = LONGJMP_BUF_HEAP;
    } else if (strcmp(choice, opt_code_ptrs[9]) == 0) {
        *c = LONGJMP_BUF_BSS;
    } else if (strcmp(choice, opt_code_ptrs[10]) == 0) {
        *c = LONGJMP_BUF_DATA;
    } else if (strcmp(choice, opt_code_ptrs[11]) == 0) {
        return VAR_BOF;
    } else if (strcmp(choice, opt_code_ptrs[12]) == 0) {
        return VAR_LEAK;
    } else {
        fprintf(stderr, "Error: Unknown choice of code pointer \"%s\"\n",
          choice);
        return 1;
    }
    return 0;
} /* set_code_ptr */

bool
set_location(char * choice, enum locations *l)
{
    if (strcmp(choice, opt_locations[0]) == 0) {
        *l = STACK;
    } else if (strcmp(choice, opt_locations[1]) == 0) {
        *l = HEAP;
    } else if (strcmp(choice, opt_locations[2]) == 0) {
        *l = BSS;
    } else if (strcmp(choice, opt_locations[3]) == 0) {
        *l = DATA;
    } else {
        fprintf(stderr, "Error: Unknown choice of memory location \"%s\"\n",
          choice);
        return 1;
    }
    return 0;
}

bool
set_function(char * choice, enum functions *f)
{
    if (strcmp(choice, opt_funcs[0]) == 0) {
        *f = MEMCPY;
    } else if (strcmp(choice, opt_funcs[1]) == 0) {
        *f = HOMEBREW;
    } else if (strcmp(choice, opt_funcs[2]) == 0) {
        *f = SSCANF;
    } else if (strcmp(choice, opt_funcs[3]) == 0) {
        *f = STRCPY;
    } else if (strcmp(choice, opt_funcs[4]) == 0) {
        *f = STRNCPY;
    } else if (strcmp(choice, opt_funcs[5]) == 0) {
        *f = SPRINTF;
    } else if (strcmp(choice, opt_funcs[6]) == 0) {
        *f = SNPRINTF;
    } else if (strcmp(choice, opt_funcs[7]) == 0) {
        *f = STRCAT;
    } else if (strcmp(choice, opt_funcs[8]) == 0) {
        *f = STRNCAT;
    } else {
        fprintf(stderr,
          "Error: Unknown choice of vulnerable function \"%s\"\n",
          choice);
        return 1;
    }
    return 0;
}
#endif
