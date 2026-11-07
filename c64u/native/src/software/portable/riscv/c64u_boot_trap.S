/* C64U diagnostic fatal entry. No access to the interrupted stack or heap.
 * This unit is present only in the explicit C64U_BOOT_TRACE build. */
#if defined(C64U_BOOT_TRACE) && C64U_BOOT_TRACE
#if !defined(__riscv_xlen) || __riscv_xlen != 32
#error C64U boot capture requires RV32
#endif

.section .text.c64u_boot_trap,"ax",@progbits
.balign 4
.global c64u_boot_trap_entry
.type c64u_boot_trap_entry,@function
c64u_boot_trap_entry:
  csrrci zero, mstatus, 8
  addi a3, sp, 0
  csrr a0, mcause
  csrr a1, mepc
  csrr a2, mtval
  // Neither address may relax to a gp-relative operation: incoming gp and sp
  // can both be damaged. These AUIPC pairs depend only on the program counter.
  .option push
  .option norelax
  la gp, __global_pointer$
  la sp, __c64u_boot_emergency_stack_end
  .option pop
  andi sp, sp, -16
  call c64u_boot_fault
.Lc64u_boot_fault_returned:
  // The C API is noreturn. A broken implementation still cannot resume a fault.
  j .Lc64u_boot_fault_returned
.size c64u_boot_trap_entry, .-c64u_boot_trap_entry

.section .bss.c64u_boot_emergency_stack,"aw",@nobits
.balign 16
.global __c64u_boot_emergency_stack_start
.type __c64u_boot_emergency_stack_start,@object
__c64u_boot_emergency_stack_start:
  .zero 4096
.size __c64u_boot_emergency_stack_start, .-__c64u_boot_emergency_stack_start
.global __c64u_boot_emergency_stack_end
__c64u_boot_emergency_stack_end:

.section .note.GNU-stack,"",@progbits
#endif
