pulp := $(shell echo | $(AS) -mchip=pulpino -o /dev/null - 2>/dev/null && echo PULP)

ifeq ($(pulp),)
  $(error Only PULP platforms are supported)
endif

# Disable CLI
CFLAGS += -DRIPE_NO_CLI

include $(BUILD_CONFIG_DIR)/riscv32-pulpissimo.mk
