# Configure compiler stack protections
  # Disable stack buffer overflow protections
  CFLAGS += -fno-stack-protector
  # Force linker to make the stack executable
  CFLAGS += -z execstack

# Force the stack frames and CFG to remain as regular as possible
CFLAGS += -fno-optimize-sibling-calls -fno-omit-frame-pointer -Wno-frame-address

CFLAGS += -ggdb3
CFLAGS += -Wall -std=c99

CFLAGS += -DRIPE_SAFE_HEAP

# CFLAGS += -DRIPE_DEF_ONLY

CFLAGS += -DRIPE_DEF_TECHNIQUE=DIRECT
CFLAGS += -DRIPE_DEF_INJECT=INJECTED_CODE_NO_NOP
CFLAGS += -DRIPE_DEF_CODE_PTR=RET_ADDR
CFLAGS += -DRIPE_DEF_LOCATION=STACK
CFLAGS += -DRIPE_DEF_FUNCTION=MEMCPY

RIPE_SOURCES += $(SOURCE_DIR)/ripe_cli.c
RIPE_SOURCES += $(SOURCE_DIR)/ripe_attack_generator.c

