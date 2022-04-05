.syntax unified

.global  lj_from_handler
.type   lj_from_handler,"function"
.extern control_jmp_buffer
.extern longjmp_no_enforce
.text
lj_from_handler:
@ r0: contains RET_ATTACK_* from caller
@ First, LR and SP are restored (r7 is irrelevant).
@ Then, the registers spilled to stack by the exception are modified
@ to make returning from exception "call" longjmp with correct parameters.
@ Finally, return from exception with bx lr.
  pop {r7, lr}
  ldr r2, =control_jmp_buffer
  str r2, [sp, #0]
  str r0, [sp, #4]
  ldr r2, =longjmp_no_enforce
  str r2, [sp, #(6*4)]
  bx lr
