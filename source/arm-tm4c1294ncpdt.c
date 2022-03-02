#include <libopencm3/lm4f/systemcontrol.h>
#include <libopencm3/lm4f/gpio.h>
#include <libopencm3/lm4f/uart.h>

#include "arm.h"

#define UART UART0

uint32_t ahb_freq = 16000000;

void clock_setup(void) {
  /* Currently, libopencm3 does not fully support the TM4C family.
   * Frequency control registers are very different from previous versions.
   * Thus, we simply use the default configuration that runs at 16 MHz.
  rcc_sysclk_config(OSCSRC_MOSC, XTAL_25M, ...); */
}

void uart_setup(void) {
  /* Enable GPIOA in run mode. */
  periph_clock_enable(RCC_GPIOA);
  /* Mux PA0 and PA1 to UART (alternate function 1) */
  gpio_set_af(GPIOA, 1, GPIO0 | GPIO1);

  /* Enable the UART clock */
  periph_clock_enable(RCC_UART0);
  /* We need a brief delay before we can access UART config registers */
  __asm__("nop");
  /* Disable the UART while we mess with its setings */
  uart_disable(UART0);
  /* Configure the UART clock source as precision internal oscillator */
  uart_clock_from_piosc(UART0);
  /* Set communication parameters */
  uart_set_baudrate(UART0, BAUDRATE);
  uart_set_databits(UART0, 8);
  uart_set_parity(UART0, UART_PARITY_NONE);
  uart_set_stopbits(UART0, 1);
  /* Now that we're done messing with the settings, enable the UART */
  uart_enable(UART0);
}

void uart_send_wrap(uint16_t data) {
  uart_send_blocking(UART0, data);
}
