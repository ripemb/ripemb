/*
 * SPDX-License-Identifier: Apache-2.0
 */

/* volatile void longjmp_no_enforce (jmp_buf, int);  */
  .globl  longjmp_no_enforce
  .type   longjmp_no_enforce, @function
longjmp_no_enforce:
	lw ra,  0*4(a0)
	lw s0,  1*4(a0)
	lw s1,  2*4(a0)
	lw s2,  3*4(a0)
	lw s3,  4*4(a0)
	lw s4,  5*4(a0)
	lw s5,  6*4(a0)
	lw s6,  7*4(a0)
	lw s7,  8*4(a0)
	lw s8,  9*4(a0)
	lw s9, 10*4(a0)
	lw s10,11*4(a0)
	lw s11,12*4(a0)
	lw sp, 13*4(a0)

#ifndef __riscv_float_abi_soft
	flw fs0, 14*4+ 0*8(a0)
	flw fs1, 14*4+ 1*8(a0)
	flw fs2, 14*4+ 2*8(a0)
	flw fs3, 14*4+ 3*8(a0)
	flw fs4, 14*4+ 4*8(a0)
	flw fs5, 14*4+ 5*8(a0)
	flw fs6, 14*4+ 6*8(a0)
	flw fs7, 14*4+ 7*8(a0)
	flw fs8, 14*4+ 8*8(a0)
	flw fs9, 14*4+ 9*8(a0)
	flw fs10,14*4+10*8(a0)
	flw fs11,14*4+11*8(a0)
#endif

	seqz a0, a1
	add  a0, a0, a1   # a0 = (a1 == 0) ? 1 : a1
	ret
	.size	longjmp_no_enforce, .-longjmp_no_enforce
