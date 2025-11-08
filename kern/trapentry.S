/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>

#include <kern/picirq.h>


###################################################################
# exceptions/interrupts
###################################################################

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */


#define TRAPHANDLER(name, num)						\
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushl $(num);							\
	jmp _alltraps

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
	.globl name;							\
	.type name, @function;					\
	.align 2;							\
	name:								\
	pushl $0;							\
	pushl $(num);							\
	jmp _alltraps

.text

/*
 * Lab 3: Your code here for generating entry points for the different traps.
 */
// 0~19: 处理器异常


#define TH(n)  TRAPHANDLER_NOEC(handler##n, n)
#define THE(n) TRAPHANDLER(handler##n, n)

.text
#include "trapentries.inc"


/*
 * Lab 3: Your code here for _alltraps
 */


_alltraps:
	pushl %ds // ds
	pushl %es // es
	pushal // tf_regs

	// 将 CS ds 和 es 都指向内核态的 selector 这是要求
	mov $GD_KD, %ax
	mov %ax, %ds
	mov %ax, %es 

	push %esp
	// 对于  x86-32 调用约定是用 stack 传递参数而不是 esp , 这和 15-213 不同
	call trap
trap_spin:
	jmp trap_spin // 此处不返回: reason:
	// 所以要陷入死循环
