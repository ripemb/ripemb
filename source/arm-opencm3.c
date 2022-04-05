#include <stdlib.h>
#include <stdio.h>

#include <libopencm3/cm3/vector.h> // for linker symbols, e.g., _edata
#include <libopencm3/cm3/mpu.h>
#include <libopencm3/cm3/scb.h>

#include "arm.h"
#include "ripe_attack_generator.h"

#define GET_MPU_SIZE(s,e) (32 - __builtin_clz((uintptr_t)e - (uintptr_t)s))
#define DATA_BASE (&_data)
#define DATA_END (&_edata)
#define DATA_SIZE GET_MPU_SIZE(DATA_BASE, DATA_END)
#define BSS_BASE (&_edata)
#define BSS_END (&_ebss)
#define BSS_SIZE GET_MPU_SIZE(BSS_BASE, BSS_END)
#define STACK_BASE (&_ebss)
#define STACK_END (&_stack)
#define STACK_SIZE GET_MPU_SIZE(STACK_BASE, STACK_END)

#ifdef RIPE_HEAP_SECTION
  #define _HEAP_BASE_SEC(s) _##s
  #define HEAP_BASE_SEC(s) _HEAP_BASE_SEC(s)
  #define _HEAP_END_SEC(s) _e##s
  #define HEAP_END_SEC(s) _HEAP_END_SEC(s)
  #define HEAP_SECTION_DECLS(section) extern unsigned HEAP_BASE_SEC(section), HEAP_END_SEC(section)
  #define HEAP_BASE (&HEAP_BASE_SEC(RIPE_HEAP_SECTION))
  #define HEAP_END (&HEAP_END_SEC(RIPE_HEAP_SECTION))
  #define HEAP_SIZE GET_MPU_SIZE(HEAP_BASE, HEAP_END)
#endif

static void print_mpu_range(const char *name, void *s, void *e) {
  dbg("XN enabled for %s: 0x%08x - 0x%08x\n", name, (uintptr_t)s, (uintptr_t)e);
}

void mpu_setup(void)
{
  MPU_CTRL = 0; // Disable MPU temporarily
  int secnum = 0;

  /* data section, R/W, XN */
  MPU_RNR = secnum++;
  MPU_RBAR = (uint32_t)DATA_BASE;
  MPU_RASR = MPU_RASR_ENABLE | (DATA_SIZE << MPU_RASR_SIZE_LSB) | MPU_RASR_ATTR_XN | MPU_RASR_ATTR_AP_PRW_URW;
  print_mpu_range("data", DATA_BASE, DATA_END);

  /* bss section, R/W, XN */
  MPU_RNR = secnum++;
  MPU_RBAR = (uint32_t)BSS_BASE;
  MPU_RASR = MPU_RASR_ENABLE | (BSS_SIZE << MPU_RASR_SIZE_LSB) | MPU_RASR_ATTR_XN | MPU_RASR_ATTR_AP_PRW_URW;
  print_mpu_range("bss", BSS_BASE, BSS_END);

  /* stack area (everything between end of RAM and end of BSS), R/W, XN */
  MPU_RNR = secnum++;
  MPU_RBAR = (uint32_t)STACK_BASE;
  MPU_RASR = MPU_RASR_ENABLE | (STACK_SIZE << MPU_RASR_SIZE_LSB) | MPU_RASR_ATTR_XN | MPU_RASR_ATTR_AP_PRW_URW;
  print_mpu_range("stack", STACK_BASE, STACK_END);

#ifdef RIPE_HEAP_SECTION
  /* heap area (if in its own section), R/W, XN */
  HEAP_SECTION_DECLS(RIPE_HEAP_SECTION);
  MPU_RNR = secnum++;
  MPU_RBAR = (uint32_t)HEAP_BASE;
  MPU_RASR = MPU_RASR_ENABLE | (HEAP_SIZE << MPU_RASR_SIZE_LSB) | MPU_RASR_ATTR_XN | MPU_RASR_ATTR_AP_PRW_URW;
  print_mpu_range("heap", HEAP_BASE, HEAP_END);
#endif

  // Enable MPU, default map for privileged mode, and enforcement during high-priority interrupts
  MPU_CTRL = MPU_CTRL_ENABLE | MPU_CTRL_PRIVDEFENA | MPU_CTRL_HFNMIENA;

  // Enable memory management fault handler
  SCB_SHCSR |= SCB_SHCSR_MEMFAULTENA | SCB_SHCSR_BUSFAULTENA | SCB_SHCSR_USGFAULTENA;

  // Data and instruction barrier to guarantee settings are applied
  __asm__ volatile("dsb;isb;");
}

int _write(int fd, char *ptr, int len) {
  int i;

  if (fd == 1 || fd == 2) { // stdout or stderr (avoid *_FILENO as it is in unistd.h)
    for (i = 0; i < len; i++) {
      if (ptr[i] == '\n') {
        uart_send_wrap('\r');
      }
      uart_send_wrap(ptr[i]);
    }
    return i;
  }
  return -1;
}

int main(void) {
  clock_setup();
  uart_setup();
  mpu_setup();
  ripe(0, NULL);
  while(1);
}

/* lj_from_handler is a simple assembly routine that works around ARM's
 * peculiar requirements for returning from exceptions.
 * It manipulates the stack and then returns from the exception effectively
 * calling longjmp_no_enforce(). */
__attribute__ ((noreturn)) void lj_from_handler(uint32_t);

/* Faults due to MPU violations.
 * Instruction faults are assumed to be due to XN.
 *
 * The assembly code mimics the following:
 *
 * uint32_t scb_cfsr = SCB_CFSR;
 * SCB_CFSR |= 0xFFFFFFFF;
 * if (scb_cfsr == SCB_CFSR_IACCVIOL)
 *   lj_from_handler(RET_ATTACK_DETECTED);
 * else
 *   lj_from_handler(RET_ATTACK_FAIL_ILLEGAL_INSTR);
 */
__attribute__ ((naked))
void mem_manage_handler(void) {
  register uint32_t tmp, tmp2;
  __asm__ volatile (
    // Push regs as C functions do because lj_from_handler pops them
    "push	{r7, lr} \n\t"

    // Load SCB_CFSR into register
    "ldr %[tmp], [%[scb_cfsr]] \n\t"

    // Clear any fault to re-enable it/them by writing all ones
    "ldr %[tmp2], =0xFFFFFFFF \n\t"
    "str %[tmp2], [%[scb_cfsr]] \n\t"

    // Test if we got the correct exception type and set r0 accordingly
    "cmp %[tmp], %[viol_off] \n\t"
    "ite eq \n\t"
    "moveq r0, %[lj_detect] \n\t"
    "movne r0, %[lj_illegal] \n\t"

    // "Call" the lj handler
    "b lj_from_handler \n\t"
    
    : // Outputs
      [tmp]"=&r"(tmp),
      [tmp2]"=&r"(tmp2)
    : // Inputs
      [scb_cfsr]"r"(&SCB_CFSR),
      [viol_off]"i"(SCB_CFSR_IACCVIOL),
      [lj_detect]"i"(RET_ATTACK_DETECTED),
      [lj_illegal]"i"(RET_ATTACK_FAIL_ILLEGAL_INSTR)
  );
}

/* Undefined instructions, illegal unaligned access, invalid execution states etc. */
__attribute__ ((noreturn))
void usage_fault_handler(void) {
  lj_from_handler(RET_ATTACK_FAIL_ILLEGAL_INSTR);
}

/* Mostly escalated exceptions, e.g., if an exception handler causes an exception. */
__attribute__ ((noreturn))
void hard_fault_handler(void){
  lj_from_handler(RET_ATTACK_FAIL_ILLEGAL_INSTR);
}

/* Faults related to bus/memory accesses. */
__attribute__ ((noreturn))
void bus_fault_handler(void){
  lj_from_handler(RET_ATTACK_FAIL_ILLEGAL_INSTR);
}
