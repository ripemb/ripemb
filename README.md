# RIPEMB: A Framework for Assessing Hardware-Assisted Security Schemes in Embedded Systems

This repository contains the stand-alone implementation of the security evaluation program RIPEMB derived from RIPE (Runtime Intrusion Prevention Evaluator).
RIPE was originally developed by John Wilander and Nick Nikiforakis and presented at the 2011 Annual Computer Security Applications Conference in Orlando, Florida (see [the original README](../HEAD/docs/README.ripe).
John Merrill has contributed major parts of the RISC-V port.

Unlike the previous incarnations RIPEMB is fully self-contained in a single program without the need for an operating system or Python

RIPEMB is free software and released under the MIT license (see file named [LICENSE](../HEAD/LICENSE)).

## Supported Hardware

Currently, the following devices are supported:

 - [ST STM32F4Discovery](https://www.st.com/en/evaluation-tools/stm32f4discovery.html)
 - [ST NUCLEO-L432KC](https://www.st.com/en/evaluation-tools/nucleo-l432kc.html)
 - [TI EK-TM4C1294XL](https://www.ti.com/tool/EK-TM4C1294XL)
 - [PULPissimo](https://github.com/pulp-platform/pulpissimo) of the [PULP project](https://pulp-platform.org/) 

## Supported Software

As of now, there is support for running RIPEMB on aforementioned ARM Cortex-M4 microcontrollers via [libopencm3](https://libopencm3.org/).
GCC and [newlibc](https://sourceware.org/newlib/) are to be used for compilation.

PULP's own SDK and GCC fork are supported on the RISC-V SoC.

## Further Expansion

Additional devices as well as environments can easily be added my providing makefiles and basic peripheral initialization code.
New ISAs require the implementation of a `build_shellcode()` function that generates the necessary instructions to jump to a given address at runtime.

## Compilation

The build system needs to be told about the target.
In the most simple case this can be done by passing the name of the compiler executable to `make`, e.g., `make CC=riscv32-unknown-elf-gcc`.
Alternatively, the concrete device can be specified via the `BOARD` variable.
The following values are implemented: `NUCLEO`, `DISCOVERY`, `TIVAC`.

### Attack Selection

Usually the attack selection happens at build time as well.
In the default configuration all attack dimensions but the functions are iterated.
Instead, `memcpy` is fixed as the function to be used to overwrite data in attacks.
For the intended use case of testing hardware-based protection schemes this is the better option as it speeds up execution without reducing expressiveness or validity of the results.

Fixing individual dimensions can be done in the same way as it is done for the function, i.e., by setting a preprocessor macro `RIPE_FUNCTION=MEMCPY` (cf. [common.mk](../HEAD/build_configs/common.mk)).
The types and values for the attack parameters are listed in the [Attack Parameters](#attack-parameters) section.

One other possibility to determine the attack to be executed is to set `RIPE_DEF_ONLY` and the various `DEF_*` variables, e.g., `DEF_TECHNIQUE=DIRECT`.

In theory it is also still possible to pass parameters to the program and use them to select individual attacks.
Since this is usually not viable in freestanding environments, it is disabled by defining `RIPE_NO_CLI` on default.

### Setjmp/Longjmp

The attacks based on non-local jumps require the type/size of elements stored in the `jmpbuf` (`RIPE_JMPBUF_TYPE`) and the offset (`RIPE_JMPBUF_IDX`) where the return address is stored.

### Heap Handling

Since RIPEMB supports attacks based on buffers on the heap that might corrupt not only the user data but also meta data but cannot simply restart after each attack there is a save/restore mechanism.
If enabled by defining `RIPE_SAFE_HEAP` a snapshot of the whole heap including necessary metadata is stored are the beginning of `main()`.
`RIPE_MAX_HEAP_SIZE` specifies the amount of memory to be reserved for this backup.
Optionally, `RIPE_HEAP_SECTION` can be set to a linker script section (if respective start and end symbols are defined) to put the heap into that section.

### Further Compile-Time Settings

The following list briefly explains other preprocessor macros used in ports.

 - `RIPE_NO_MAIN_WRAPPER`:
    By default, the build system provides a simply `main()` function that directly calls RIPEMB's main function `ripe()`.
    In case the startup code does not initialize all necessary peripherals, this can be overridden by setting `RIPE_NO_MAIN_WRAPPER` and implementing a custom `main()` function.
 - `RIPE_NO_SCANF`:
    Some SDKs/libc implementations for embedded systems do not provide the `scanf` family of standard C functions.
    Defining the macro will exclude the respective attack and allows for compiling RIPEMB even with these libraries.
 - `RIPE_BRANCH_OR_MASK`:
    Some architectures require certain bits of branch addresses set (e.g., ARM in thumb mode requires the LSB to be set).
    The value of this macro gets bit-wise ORed to the target address.
 - `RIPE_SET_RET_ADDR_PTR(x)`:
    In order to manipulate the return address of the current function the address where the spilled address is stored needs to be known.
    This macro needs to determine that location and store its address into `x`.

## Running

Depending on the target (build system) there might be make goals to load and execute the resulting binary.
In any case, after jumping into `ripe()` the configured attacks are being executing in succession.

### Test Results

The output depending on the selected verbosity gives information on the individual attacks.
At the very end a summary is printed containing the following numbers.

How many attacks…

 - are statically possible, 
 - were impossible due to run-time restrictions,
 - produced setup errors or illegal execution states (e.g., illegal instructions),
 - actually worked,
 - failed completely,
 - were detected by a defense mechanism.

## Attack Parameters

RIPEMB performs a series of exploits based on its five attack dimensions defined in [ripe_attack_generator.h](../HEAD/source/ripe_attack_generator.h)) and explained in the following sections.
See the RIPE paper for more details on the initial design and meaning of the values.

RIPEMB uses the following values for the respective attack dimensions:

 - Technique (`TECHNIQUE`): `DIRECT` or `INDIRECT`
 - Attack(ed) code (`INJECT`): `INJECTED_CODE_NO_NOP`, `RETURN_INTO_LIBC`, `INJECTED_CODE_NO_NOP_JR`, `RETURN_INTO_LIBC_JR, RETURN_ORIENTED_PROGRAMMING`, `RETURN_INTO_ANCESTOR`, `RETURN_INTO_ANCESTOR_ROP`, `DATA_ONLY`
 - Target pointer location (`CODE_PTR`): `RET_ADDR`, `FUNC_PTR_STACK_VAR`, `FUNC_PTR_STACK_PARAM`, `FUNC_PTR_HEAP`, `FUNC_PTR_BSS`, `FUNC_PTR_DATA`, `LONGJMP_BUF_STACK_VAR`, `LONGJMP_BUF_STACK_PARAM`, `LONGJMP_BUF_HEAP`, `LONGJMP_BUF_BSS`, `LONGJMP_BUF_DATA`, `VAR_BOF`, `VAR_LEAK`
 - Memory section (`LOCATION`): `STACK`, `HEAP`, `BSS`, `DATA`
 - Function (`FUNCTION`): `MEMCPY`, `HOMEBREW`, `SSCANF`, `STRCPY`, `STRNCPY`, `SPRINTF`, `SNPRINTF`, `STRCAT`, `STRNCAT`

In total, RIPEMB currently offers up to 2803 distinct attacks.
Depending on the address layout, specifically the amount of bytes with value 0 in the target addresses, this number might be lower in practice as many attack functions normally operate on null-terminated strings, which cannot succeed in these cases.
In its default configuration (with a single attack function that is not affected by that problem) 397 attacks are executed.

In the following sections the possible values of the individual dimensions are explained.

### Overflow Technique

Buffer overflows can be performed with or without indirection.

 - The _direct_ technique simply overwrites a target pointer in the same memory location as the overflow buffer.
 - The _indirect_ technique initially targets a generic pointer that is adjacent to the buffer.
    A dereference redirects this pointer to the attack code.
    Indirect overflows work between memory regions (e.g., from a stack buffer to a heap pointer).

### Attack code

The second dimension specifies how the attack is to be executed, i.e., how the vulnerability is to be exploited.
The possible attack codes in RIPEMB are:

 - A platform-dependent shellcode that is generated at runtime which performs a simple transfer of control flow.
   The function to be targeted can either be an independent function that is never legally called by indirect jumps (`INJECTED_CODE_NO_NOP`), or `indirect_target()` that is allowed to be reached indirectly (`INJECTED_CODE_NO_NOP_JR`).
 - A simulated return-into-libc attack that redirects the target pointer to the entry point of an otherwise inaccessible function (`RETURN_INTO_LIBC`).
    Alternatively, RIPEMB can also target a function that is called indirectly legally (`RETURN_INTO_LIBC_JR`).
 - A ROP-style attack (`RETURN_ORIENTED_PROGRAMMING`) that is similar to the return-into-libc attack code but jumps to an instruction that is *not* a function entry point.
 - Two variants that either call a function that is contained in the active backtrace (`RETURN_INTO_ANCESTOR`), or that jumps to a label in the caller of a function (`RETURN_INTO_ANCESTOR_ROP`).
 - The `DATA_ONLY` style manipulates non-control data, resulting in a mock privilege escalation or a data leak.

### Target Code Pointer

The target code pointer is overwritten by the overflow such that control of the program is transferred to the attack code.
RIPEMB uses the following target pointers:

 - The _return address_ of the `perform_attack()` function spilled to the stack where it can be overwritten before being restored and used to supposedly return back.
 - _Function pointers_ in various locations: one each in variables on the stack, heap, data, and bss section.
    Additionally, there is also a function pointer passed as parameter.
 - _Longjmp buffers_ contain the instruction address to return to after restoring the context in `longjmp()`.
    RIPEMB uses `longjmp` variables in the same locations as the aforementioned function pointers.
 - The data-only attacks use variables in the four usual locations.
   In the DOP attack a numerical variable is overflown that is later used as a branch condition.
   The leak attack simulates the exfiltration of data by encoding the offset of the target buffer that is later used to copy data from an unchecked location.

While the original RIPE differentiated between _normal_ variables and structs, RIPEMB does not make this distinctions in favor of being independent from implementation-defined behavior.

### Location

The attack location describes the memory section in which the target buffer is located.
RIPEMB supports attacks on stack, heap, data, and bss buffers.
The generic code of RIPEMB does not care about the sections the buffers are actually put into by the linker scripts/build systems and solely relies on the semantics of C to distinguish the locations.

### Function

There are nine functions available to be abused in attacks:

 - `memcpy`
 - `homebrew`, a loop-based, `memcpy` equivalent
 - `sscanf` via a format string vulnerability
 - C library string functions, including: `str(n)cpy`, `str(n)cat`, `s(n)printf`

Since the overall effect of the different overflow functions is basically the same and their individual details likely do not influence hardware-assisted mechanisms at all, the function dimension is the only one in RIPEMB that is fixed in the default configuration.
Unless make is stopped from passing `RIPE_FUNCTION=MEMCPY` to the preprocessor only `memcpy` is used to overflow buffers.
