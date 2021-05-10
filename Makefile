# Makefile for RIPE

# Set compiler if need be:
# default to riscv32 but allow it to be overridden too
ifeq ($(origin CC),default)
  CC = riscv32-unknown-elf-gcc
  export CC
endif

#Depending on how you test your system you may want to comment, or uncomment
#the following
CFLAGS += -fno-stack-protector -z execstack

all: ripe_attack_generator

clean:
	rm -rf build/ out/

ripe_attack_generator: ./source/ripe_attack_generator.c
	mkdir -p build/ out/
	$(CC) \
		$^ $(CFLAGS) -o ./build/ripe_attack_generator
