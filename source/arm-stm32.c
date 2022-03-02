#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/usart.h>
#include <libopencm3/stm32/rcc.h>
#include "arm.h"

void uart_setup(void) {
  /* Enable clocks for GPIOA and USART2. */
  rcc_periph_clock_enable(RCC_GPIOA);
  rcc_periph_clock_enable(RCC_USART2);

  /* Setup GPIO pins for USART2 transmit. */
  gpio_mode_setup(GPIOA, GPIO_MODE_AF, GPIO_PUPD_PULLUP, GPIO2);

  /* Setup USART2 TX pin as alternate function. */
  gpio_set_af(GPIOA, GPIO_AF7, GPIO2);

  /* Setup USART2 parameters. */
  usart_set_baudrate(USART2, BAUDRATE);
  usart_set_databits(USART2, 8);
  usart_set_stopbits(USART2, USART_STOPBITS_1);
  usart_set_mode(USART2, USART_MODE_TX);
  usart_set_parity(USART2, USART_PARITY_NONE);
  usart_set_flow_control(USART2, USART_FLOWCONTROL_NONE);

  /* Finally enable the USART. */
  usart_enable(USART2);
}

void uart_send_wrap(uint16_t data) {
  usart_send_blocking(USART2, data);
}
