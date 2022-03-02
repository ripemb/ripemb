#include <stdlib.h>

#include "arm.h"
#include "ripe_attack_generator.h"

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
  ripe(0, NULL);
  while(1);
}

/* Faults due to MPU violations. */
__attribute__ ((noreturn))
void mem_manage_handler(void) {while (1);}

/* Undefined instructions, illegal unaligned access, invalid execution states etc. */
__attribute__ ((noreturn))
void usage_fault_handler(void) {while (1);}

/* Mostly escalated exceptions, e.g., if an exception handler causes an exception. */
__attribute__ ((noreturn))
void hard_fault_handler(void){while (1);}

/* Faults related to bus/memory accesses. */
__attribute__ ((noreturn))
void bus_fault_handler(void){while (1);}
