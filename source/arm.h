#ifndef ARM_H
#define ARM_H

#include <stdint.h>

extern uint32_t ahb_freq;

void clock_setup(void);

void uart_setup(void);
void uart_send_wrap(uint16_t data);

#endif
