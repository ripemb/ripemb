BAUDRATE = 921600

CFLAGS += -mcpu=cortex-m4

# Disable CLI
CFLAGS += -DRIPE_NO_CLI

CFLAGS += -DRIPE_JMPBUF_IDX=9
CFLAGS += -DRIPE_BRANCH_OR_MASK=1

# LR is pushed as the very first reg to the stack but the FP returned by the builtin is weird.
CFLAGS += -D'RIPE_SET_RET_ADDR_PTR(x)=do{x=(void*)((uintptr_t)__builtin_frame_address(1) - 6*4);}while(0)'

CFLAGS += -DBAUDRATE=$(BAUDRATE)

include $(BUILD_CONFIG_DIR)/arm-libopencm3.mk
