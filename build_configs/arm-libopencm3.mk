# Be silent per default, but 'make V=1' will show all compiler calls.
ifneq ($(V),1)
Q := @
# Do not print "Entering directory ...".
MAKEFLAGS += --no-print-directory
endif

OPENCM3_DIR := submodules/libopencm3
BUILD_DIR := build
PROJECT := ripemb

LIBOPENCM3_ALL :=

# STM32F4DISCOVERY (STM32F407VG)
CUR_LIB = stm32/f4
ifeq ($(BOARD),DISCOVERY)
  DEVICE = stm32f407vgt6
  CFILES += $(SOURCE_DIR)/arm-stm32.c $(SOURCE_DIR)/arm-stm32f407vgt6.c
  LIBOPENCM3_CUR := $(CUR_LIB)
  OPENOCD_CFG := board/stm32f4discovery.cfg
  UART_DEV := /dev/ttyUSB0
  LDFLAGS += -Wl,--defsym=ahb_freq=rcc_ahb_frequency
  # NB: The 64 kB core-coupled memory (section .ccm) is not executable
  CFLAGS += -DRIPE_MAX_HEAP_SIZE=32768
endif
LIBOPENCM3_ALL += $(CUR_LIB)

# NUCLEO-L432KC (STM32L432KC)
CUR_LIB = stm32/l4
ifeq ($(BOARD),NUCLEO)
  DEVICE = stm32l432kc
  CFILES += $(SOURCE_DIR)/arm-stm32.c $(SOURCE_DIR)/arm-stm32l432kc.c
  LIBOPENCM3_CUR := $(CUR_LIB)
  OPENOCD_CFG := board/st_nucleo_l476rg.cfg
  UART_DEV := /dev/ttyNucleo
  LDFLAGS += -Wl,--defsym=ahb_freq=rcc_ahb_frequency
  CFLAGS += -DRIPE_HEAP_SECTION=ram2 -DRIPE_MAX_HEAP_SIZE=16384
endif
LIBOPENCM3_ALL += $(CUR_LIB)

# EK-TM4C1294XL (TM4C1294NCPDT)
CUR_LIB = lm3s lm4f
ifeq ($(BOARD),TIVAC)
  DEVICE = tm4c1294ncpdt
  CFILES += $(SOURCE_DIR)/arm-tm4c1294ncpdt.c
  LIBOPENCM3_CUR := $(CUR_LIB)
  OPENOCD_CFG := board/ek-tm4c1294xl.cfg
  UART_DEV := /dev/ttyICDI
  CFLAGS += -DRIPE_MAX_HEAP_SIZE=16384
endif
LIBOPENCM3_ALL += $(CUR_LIB)

CFLAGS += -DRIPE_HEAP_SAFE_SIZE=RIPE_MAX_HEAP_SIZE
CFLAGS += -DRIPE_NO_MAIN_WRAPPER

LDFLAGS += -lc
LDFLAGS += -lnosys
LDFLAGS += -nostartfiles

CFILES += $(SOURCE_DIR)/libc-newlib.c
CFILES += $(RIPE_SOURCES) $(SOURCE_DIR)/arm-opencm3.c

LIBOPENCM3_LIB_GEN = $(OPENCM3_DIR)/lib/libopencm3_$(subst /,,$(t)).a
LIBOPENCM3_LIBS := $(foreach t,$(LIBOPENCM3_CUR),$(call LIBOPENCM3_LIB_GEN,$(t)))
LIBOPENCM3_LIBS_ALL := $(foreach t,$(LIBOPENCM3_ALL),$(call LIBOPENCM3_LIB_GEN,$(t)))

OBJS = $(CFILES:%.c=%.o)
.PRECIOUS: $(OBJS)

.DEFAULT_GOAL := all
.PHONY: all
all: $(BUILD_DIR)/$(PROJECT).elf

$(BUILD_DIR)/$(PROJECT).elf: | $(BUILD_DIR)/

ifneq (distclean,$(MAKECMDGOALS))
  ifneq (clean,$(MAKECMDGOALS))
    ifneq (prepare,$(MAKECMDGOALS))
      ifneq ($(LIBOPENCM3_LIBS_ALL),$(wildcard $(LIBOPENCM3_LIBS_ALL)))
        $(info Missing libopencm3 files, generating...)
        $(shell $(MAKE) -j$$(nproc) -C $(OPENCM3_DIR) TARGETS="$(LIBOPENCM3_ALL)" >/dev/null 2>&1)
        ifneq ($(.SHELLSTATUS),0)
          $(info failed!)
          $(error Could not build libopencm3 for $(LIBOPENCM3_ALL), try yourself:\
            $(MAKE) -j$$(nproc) -C $(OPENCM3_DIR) TARGETS="$(LIBOPENCM3_ALL)")
        endif
        $(info done.)
      endif
      ifeq (,$(BOARD))
        $(error No board selected)
      endif
      include $(OPENCM3_DIR)/mk/genlink-config.mk
      include $(OPENCM3_DIR)/mk/gcc-config.mk
    endif
  endif
endif

.PHONY: prepare
prepare:
	$(MAKE) -j$$(nproc) -C $(OPENCM3_DIR) "TARGETS=$(LIBOPENCM3_ALL)"

.PHONY: clean
clean:
	@rm -f $(OBJS) $(BUILD_DIR)/$(PROJECT).elf

.PHONY: distclean
distclean: clean
	@$(MAKE) -C $(OPENCM3_DIR) clean
	@rm -rf build/

.PHONY: gdb
gdb: $(BUILD_DIR)/$(PROJECT).elf
	$(Q)$(GDB) \
	  -ex "target extended-remote | openocd -d1 -c \"gdb_port pipe\" -f $(OPENOCD_CFG)"\
	  -ex "monitor reset halt" \
	  -ex "load" \
	  $(foreach impl,$(LIBOPENCM3_CUR),-ex "dir $(BUILD_DIR)/../submodules/libopencm3/lib/$(impl)/") \
	  -ex "break main" \
	  -ex "continue" \
	  --args "$(BUILD_DIR)/$(PROJECT).elf"

.PHONY: tty
tty:
	$(Q)picocom --imap lfcrlf -b $(BAUDRATE) $(UART_DEV)

include $(OPENCM3_DIR)/mk/genlink-rules.mk
include $(OPENCM3_DIR)/mk/gcc-rules.mk
