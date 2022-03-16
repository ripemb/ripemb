pulp := $(shell echo | $(AS) -mchip=pulpino -o /dev/null - 2>/dev/null && echo PULP)

ifeq ($(pulp),)
  $(error Only PULP platforms are supported)
endif

# Disable CLI
CFLAGS += -DRIPE_NO_CLI

# RA written one word "higher" on the stack than BP
CFLAGS += -D'RIPE_SET_RET_ADDR_PTR(x)=do{x=(void *)(((uintptr_t)__builtin_frame_address(0)) - 4);}while(0)'

include $(BUILD_CONFIG_DIR)/riscv32-pulpissimo.mk
