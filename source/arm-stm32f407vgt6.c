#include <libopencm3/stm32/rcc.h>
#include "arm.h"

void clock_setup(void) {
  rcc_clock_setup_pll(&rcc_hse_8mhz_3v3[RCC_CLOCK_3V3_168MHZ]);
}
