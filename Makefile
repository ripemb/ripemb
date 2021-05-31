RIPEMB_DIR:=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))/build_configs/../
SOURCE_DIR:=$(RIPEMB_DIR)/source/
BUILD_CONFIG_DIR:=$(RIPEMB_DIR)/build_configs/

# Set compiler if need be:
# default to riscv32 but allow it to be overridden too
ifeq ($(origin CC),default)
  CC = riscv32-unknown-elf-gcc
endif

# Extract toolchain triple and include respective makefile
_=$() $()
triple_raw := $(wordlist 1, 3, $(subst -, ,$(shell $(CC) -dumpmachine)))
triple := $(subst $(_),-,$(triple_raw))
RIPE_SOURCES += $(SOURCE_DIR)/$(firstword $(triple_raw)).c
AS = $(triple)-as
export CC AS

include $(BUILD_CONFIG_DIR)/common.mk
triple_mk := $(BUILD_CONFIG_DIR)/$(triple).mk
ifeq ($(wildcard $(triple_mk)),)
  $(error $(triple) architecture is not supported)
endif
include $(triple_mk)

# Disable implicit suffix and built-in rules (for performance and profit)
.SUFFIXES:
MAKEFLAGS += --no-builtin-rules

.PRECIOUS: %/
%/:
	@mkdir -p $@
