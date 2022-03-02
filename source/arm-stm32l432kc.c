#include <libopencm3/stm32/flash.h>
#include <libopencm3/stm32/rcc.h>

void clock_setup(void) {
  flash_prefetch_enable();
  flash_set_ws(4); // 5 CPU cycles required for HCLK > 64 MHz

  // Enable HSI (internal 16 MHz RC oscillator)
  rcc_osc_on(RCC_HSI16);
  rcc_wait_for_osc_ready(RCC_HSI16);

  /* Set main PLL to 80MHz: 16MHz / 4 = > 4 * 40 = 160MHz VCO prescaled by 2 */
  rcc_set_main_pll(RCC_PLLCFGR_PLLSRC_HSI16, 4, 40, 0, 0, RCC_PLLCFGR_PLLR_DIV2);
  rcc_osc_on(RCC_PLL);
  rcc_wait_for_osc_ready(RCC_PLL);

  // Use PLL for sysclk, AHB and APB bus clocks
  rcc_set_sysclk_source(RCC_CFGR_SW_PLL);
  rcc_wait_for_sysclk_status(RCC_PLL);

  rcc_ahb_frequency = 80000000;
  rcc_apb1_frequency = 80000000;
  rcc_apb2_frequency = 80000000;
}
