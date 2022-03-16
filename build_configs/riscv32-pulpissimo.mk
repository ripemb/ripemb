PULP_APP := ripemb

PULP_APP_SRCS := $(RIPE_SOURCES) \
                 $(SOURCE_DIR)/riscv32-pulpissimo.c

PULP_APP_ASM_SRCS := $(SOURCE_DIR)/riscv32_longjmp_no_enforce.S
PULP_CFLAGS += -DRIPE_JMPBUF_TYPE=long

PULP_CFLAGS += $(CFLAGS)
PULP_CFLAGS += -D PULP_HZ=16000000

PULP_CFLAGS += -Wno-unused-function
PULP_CFLAGS += -Dasm=__asm__

PULP_CFLAGS += -D'perror(s, ...)=printf(s "\n", \#\#__VA_ARGS__)'
PULP_CFLAGS += -D'fprintf(f, ...)=printf(__VA_ARGS__)'


PULP_CFLAGS += -flto
PULP_LDFLAGS += -flto
PULP_LDFLAGS += -Wno-lto-type-mismatch

include $(PULP_SDK_INSTALL)/rules/pulp_rt.mk

.DEFAULT_GOAL := build
