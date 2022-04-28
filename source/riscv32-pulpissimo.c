#include "ripe_attack_generator.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include "rt/rt_api.h"

int __rt_fpga_fc_frequency = PULP_HZ; // e.g. 16000000 for 16MHz;
int __rt_fpga_periph_frequency = 10000000; // e.g. 10000000 for 10MHz;
unsigned int __rt_iodev_uart_baudrate = 115200;

#ifdef RIPE_SAFE_HEAP
void save_heap(uint8_t *heap_safe) {
  uint8_t *heap_base = rt_l2_shared_base();
  dbg("heap base=0x%0*" PRIxPTR ", size=0x%zx, safe base=0x%0*" PRIxPTR ", size=0x%zx\n",
      PRIxPTR_WIDTH, (uintptr_t)heap_base, rt_l2_shared_size(),
      PRIxPTR_WIDTH, (uintptr_t)heap_safe, RIPE_HEAP_SAFE_SIZE);
  int irq_en = rt_irq_disable();
  memcpy(heap_safe, &__rt_alloc_l2[2], sizeof(rt_alloc_t));
  memcpy(heap_safe+sizeof(rt_alloc_t), rt_l2_shared_base(), RIPE_HEAP_SAFE_SIZE-sizeof(rt_alloc_t));
  rt_irq_restore(irq_en);
}

void restore_heap(uint8_t *heap_safe) {
  int irq_en = rt_irq_disable();
  memcpy(&__rt_alloc_l2[2], heap_safe, sizeof(rt_alloc_t));
  memcpy(rt_l2_shared_base(), heap_safe+sizeof(rt_alloc_t), RIPE_HEAP_SAFE_SIZE-sizeof(rt_alloc_t));
  rt_irq_restore(irq_en);
}
#endif

void illegal_insn_handler_c(void){
  longjmp_no_enforce(control_jmp_buffer, RET_ATTACK_FAIL_ILLEGAL_INSTR);
}

void _atexit_hack(int status) {
  printf("exit status was %d\n\x04\n", status);
}
