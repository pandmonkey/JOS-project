/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/assert.h>

#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/syscall.h>
#include <kern/console.h>
#include <kern/sched.h>


// 用于检查 地址的 marco
// 检查虚拟地址的对齐性, 看是否成立
#define CHECK_ALIGIN_UVA(_va) do {\
	uintptr_t __tmp__ = (uintptr_t)(_va);\
	if (__tmp__>= UTOP || (__tmp__ & (PGSIZE - 1)))\
		return -E_INVAL;\
} while(0)
// 检查权限的情况
#define CHECK_SYSCALL_PERM(_perm) do {\
	int __tmp__ = perm; \
	if (!(__tmp__ & PTE_P) || !(__tmp__ & PTE_U) || (__tmp__ & ~PTE_SYSCALL))\
	return -E_INVAL;\
} while(0)


static int cnt_ipc_send = 0, cnt_ipc_try_send = 0, cnt_ipc_recv = 0;

static int ipc_send_page(struct Env*, struct Env*); 
// Print a string to the system console.
// The string is exactly 'len' characters long.
// Destroys the environment on memory errors.
static void
sys_cputs(const char *s, size_t len)
{
	// Check that the user has permission to read memory [s, s+len).
	// Destroy the environment if not.
	user_mem_assert(curenv, s, len, PTE_U); // 检查是否有权限
	// LAB 3: Your code here.
	
	// Print the string supplied by the user.
	cprintf("%.*s", len, s);
}

// Read a character from the system console without blocking.
// Returns the character, or 0 if there is no input waiting.
static int
sys_cgetc(void)
{
	return cons_getc();
}

// Returns the current environment's envid.
static envid_t
sys_getenvid(void)
{
	return curenv->env_id;
}

// Destroy a given environment (possibly the currently running environment).
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_destroy(envid_t envid)
{
	int r;
	struct Env *e;

	if ((r = envid2env(envid, &e, 1)) < 0)
		return r;
	env_destroy(e);
	return 0;
}

// Deschedule current environment and pick a different one to run.
static void
sys_yield(void)
{
	sched_yield();
}

// Allocate a new environment.
// Returns envid of new environment, or < 0 on error.  Errors are:
//	-E_NO_FREE_ENV if no free environment is available.
//	-E_NO_MEM on memory exhaustion.
static envid_t
sys_exofork(void)
{
	// Create the new environment with env_alloc(), from kern/env.c.
	// It should be left as env_alloc created it, except that
	// status is set to ENV_NOT_RUNNABLE, and the register set is copied
	// from the current environment -- but tweaked so sys_exofork
	// will appear to return 0.

	// LAB 4: Your code here.
	int allocated = 0;
	struct Env *p, *c;
	p = curenv;
	allocated = env_alloc(&c, p->env_id);
	if (allocated < 0) {
		return allocated;
	}

	c->env_status = ENV_NOT_RUNNABLE;
	c->env_tf = p->env_tf;
	c->env_tf.tf_regs.reg_eax = 0; // 模拟 Unix 的 fork()的返回值语义, 父进程中 fork()返回新子进程的 envid, 子进程中, fork()返回0
	return c->env_id;
	
}

// Set envid's env_status to status, which must be ENV_RUNNABLE
// or ENV_NOT_RUNNABLE.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if status is not a valid status for an environment.
static int
sys_env_set_status(envid_t envid, int status)
{
    struct Env *e;
    if (!(status == ENV_RUNNABLE || status == ENV_NOT_RUNNABLE))
        return -E_INVAL;

    int r = envid2env(envid, &e, 1);
    if (r < 0)
        return r;

    e->env_status = status;
    return 0;
}

// Set envid's trap frame to 'tf'.
// tf is modified to make sure that user environments always run at code
// protection level 3 (CPL 3), interrupts enabled, and IOPL of 0.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_set_trapframe(envid_t envid, struct Trapframe *tf)
{
	// LAB 5: Your code here.
	// Remember to check whether the user has supplied us with a good
	// address!
	panic("sys_env_set_trapframe not implemented");
}

// Set the page fault upcall for 'envid' by modifying the corresponding struct
// Env's 'env_pgfault_upcall' field.  When 'envid' causes a page fault, the
// kernel will push a fault record onto the exception stack, then branch to
// 'func'.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
// 为环境注册应该页错误处理函数 
// func 保存了页错误处理函数的入口地址
static int
sys_env_set_pgfault_upcall(envid_t envid, void *func)
{
	struct Env *e;
	int r = envid2env(envid, &e, 1);
	if (r < 0)
		return r;
	e->env_pgfault_upcall = func;
	return 0;

}

// Allocate a page of memory and map it at 'va' with permission
// 'perm' in the address space of 'envid'.
// The page's contents are set to 0.
// If a page is already mapped at 'va', that page is unmapped as a
// side effect.
//
// perm -- PTE_U | PTE_P must be set, PTE_AVAIL | PTE_W may or may not be set,
//         but no other bits may be set.  See PTE_SYSCALL in inc/mmu.h.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if va >= UTOP, or va is not page-aligned.
//	-E_INVAL if perm is inappropriate (see above).
//	-E_NO_MEM if there's no memory to allocate the new page,
//		or to allocate any necessary page tables.
static int
sys_page_alloc(envid_t envid, void *va, int perm)
{
	// Hint: This function is a wrapper around page_alloc() and
	//   page_insert() from kern/pmap.c.
	//   Most of the new code you write should be to check the
	//   parameters for correctness.
	//   If page_insert() fails, remember to free the page you
	//   allocated!
	int called;
	struct Env *e;
	struct PageInfo *pp;

	CHECK_ALIGIN_UVA(va);
	CHECK_SYSCALL_PERM(perm); //检查输入情况
	called = envid2env(envid, &e, 1);
	if (called < 0) {
		return called;
	}
	pp = page_alloc(ALLOC_ZERO);
	if (!pp) {
		return -E_NO_MEM; // 分配失败
	}
	called = page_insert(e->env_pgdir, pp, va, perm); // 映射构造失败
	if (called < 0) {
		page_free(pp);
		return called;
	}
	return 0;
	// LAB 4: Your code here.
}

// Map the page of memory at 'srcva' in srcenvid's address space
// at 'dstva' in dstenvid's address space with permission 'perm'.
// Perm has the same restrictions as in sys_page_alloc, except
// that it also must not grant write access to a read-only
// page.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if srcenvid and/or dstenvid doesn't currently exist,
//		or the caller doesn't have permission to change one of them.
//	-E_INVAL if srcva >= UTOP or srcva is not page-aligned,
//		or dstva >= UTOP or dstva is not page-aligned.
//	-E_INVAL is srcva is not mapped in srcenvid's address space.
//	-E_INVAL if perm is inappropriate (see sys_page_alloc).
//	-E_INVAL if (perm & PTE_W), but srcva is read-only in srcenvid's
//		address space.
//	-E_NO_MEM if there's no memory to allocate any necessary page tables.
static int
sys_page_map(envid_t srcenvid, void *srcva,
	     envid_t dstenvid, void *dstva, int perm)
{
	// Hint: This function is a wrapper around page_lookup() and
	//   page_insert() from kern/pmap.c.
	//   Again, most of the new code you write should be to check the
	//   parameters for correctness.
	//   Use the third argument to page_lookup() to
	//   check the current permissions on the page.
	int r;
	struct Env *srcenv, *dstenv;
	pte_t *pte;
	struct PageInfo *pp;

	CHECK_ALIGIN_UVA(srcva);
	CHECK_ALIGIN_UVA(dstva);
	CHECK_SYSCALL_PERM(perm);
	r = envid2env(srcenvid, &srcenv, 1);
	if (r < 0) {
		return r;
	}

	r = envid2env(dstenvid, &dstenv, 1);
	if (r < 0) {
		return r;
	}

	if (!(pp = page_lookup(srcenv->env_pgdir, srcva, &pte))) {
		return -E_INVAL;
	}

	if (!(*pte & PTE_W) && (perm & PTE_W)) {
		return -E_INVAL;
	}

	r = page_insert(dstenv->env_pgdir, pp, dstva, perm);
	if (r < 0) {
		return r;
	}
	return 0;
	// LAB 4: Your code here.
}

// Unmap the page of memory at 'va' in the address space of 'envid'.
// If no page is mapped, the function silently succeeds.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if va >= UTOP, or va is not page-aligned.
static int
sys_page_unmap(envid_t envid, void *va)
{
	// Hint: This function is a wrapper around page_remove().
	int r;
	struct Env *e;
	CHECK_ALIGIN_UVA(va);
	r = envid2env(envid, &e, 1);
	if (r < 0) {
		return r;
	}

	page_remove(e->env_pgdir, va);
	return 0;
}

// Try to send 'value' to the target env 'envid'.
// If srcva < UTOP, then also send page currently mapped at 'srcva',
// so that receiver gets a duplicate mapping of the same page.
//
// The send fails with a return value of -E_IPC_NOT_RECV if the
// target is not blocked, waiting for an IPC.
//
// The send also can fail for the other reasons listed below.
//
// Otherwise, the send succeeds, and the target's ipc fields are
// updated as follows:
//    env_ipc_recving is set to 0 to block future sends;
//    env_ipc_from is set to the sending envid;
//    env_ipc_value is set to the 'value' parameter;
//    env_ipc_perm is set to 'perm' if a page was transferred, 0 otherwise.
// The target environment is marked runnable again, returning 0
// from the paused sys_ipc_recv system call.  (Hint: does the
// sys_ipc_recv function ever actually return?)
//
// If the sender wants to send a page but the receiver isn't asking for one,
// then no page mapping is transferred, but no error occurs.
// The ipc only happens when no errors occur.
//
// Returns 0 on success, < 0 on error.
// Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist.
//		(No need to check permissions.)
//	-E_IPC_NOT_RECV if envid is not currently blocked in sys_ipc_recv,
//		or another environment managed to send first.
//	-E_INVAL if srcva < UTOP but srcva is not page-aligned.
//	-E_INVAL if srcva < UTOP and perm is inappropriate
//		(see sys_page_alloc).
//	-E_INVAL if srcva < UTOP but srcva is not mapped in the caller's
//		address space.
//	-E_INVAL if (perm & PTE_W), but srcva is read-only in the
//		current environment's address space.
//	-E_NO_MEM if there's not enough memory to map srcva in envid's
//		address space.



// Block until a value is ready.  Record that you want to receive
// using the env_ipc_recving and env_ipc_dstva fields of struct Env,
// mark yourself not runnable, and then give up the CPU.
//
// If 'dstva' is < UTOP, then you are willing to receive a page of data.
// 'dstva' is the virtual address at which the sent page should be mapped.
//
// This function only returns on error, but the system call will eventually
// return 0 on success.
// Return < 0 on error.  Errors are:
//	-E_INVAL if dstva < UTOP but dstva is not page-aligned.
static int
sys_ipc_recv(void *dstva)
{
	cnt_ipc_recv++;
    if (dstva < (void*)UTOP && ((uintptr_t)dstva & (PGSIZE - 1)))
        return -E_INVAL;
    curenv->env_ipc_dstva = dstva;

    // 优先处理等待队列
    if (curenv->env_ipc_sendq) {
        struct Env *s = curenv->env_ipc_sendq;
        curenv->env_ipc_sendq = s->env_ipc_next;
        s->env_ipc_next = NULL;
        int r = ipc_send_page(s, curenv);
        s->env_status = ENV_RUNNABLE;
        s->env_tf.tf_regs.reg_eax = r;
        if (r < 0) { // 映射失败继续睡
            curenv->env_ipc_recving = 1;
            curenv->env_status = ENV_NOT_RUNNABLE;
            sched_yield();
            return 0;
        }
        curenv->env_ipc_recving = 0;
        curenv->env_ipc_from  = s->env_id;
        curenv->env_ipc_value = s->env_ipc_snd_val;
        curenv->env_tf.tf_regs.reg_eax = 0;
        return 0;
    }

	

    // 无发送者，睡眠
    curenv->env_ipc_recving = 1;
    curenv->env_status = ENV_NOT_RUNNABLE;
    sched_yield();
    return 0;
}

static int
sys_ipc_try_send(envid_t envid, uint32_t value, void *srcva, unsigned perm)
{
	cnt_ipc_try_send++;
    int r;
    struct Env *dst;
    if ((r = envid2env(envid, &dst, 0)) < 0)
        return r;
    if (!(dst->env_ipc_recving && dst->env_status == ENV_NOT_RUNNABLE))
        return -E_IPC_NOT_RECV;

    // 发送页（仅在双方都请求时）
    dst->env_ipc_perm = 0;
    if (srcva < (void*)UTOP && dst->env_ipc_dstva < (void*)UTOP) {
        if ((uintptr_t)srcva & (PGSIZE - 1)) return -E_INVAL;
        if (perm & ~PTE_SYSCALL) return -E_INVAL;
        if (!(perm & PTE_U) || !(perm & PTE_P)) return -E_INVAL;
        pte_t *pte;
        struct PageInfo *pp = page_lookup(curenv->env_pgdir, srcva, &pte);
        if (!pp) return -E_INVAL;
        if ((perm & PTE_W) && !(*pte & PTE_W)) return -E_INVAL;
        if ((r = page_insert(dst->env_pgdir, pp, dst->env_ipc_dstva, perm)) < 0)
            return r;
        dst->env_ipc_perm = perm;
    }

    dst->env_ipc_recving = 0;
    dst->env_ipc_from  = curenv->env_id;
    dst->env_ipc_value = value;
    dst->env_status    = ENV_RUNNABLE;
    dst->env_tf.tf_regs.reg_eax = 0;
    return 0;
}

static int
sys_ipc_send(envid_t envid, uint32_t value, void *srcva, unsigned perm)
{	
	cnt_ipc_send++;
    int r;
    struct Env *dst;
    if ((r = envid2env(envid, &dst, 0)) < 0)
        return r;

    // 直接交付
    if (dst->env_ipc_recving && dst->env_status == ENV_NOT_RUNNABLE) {
        curenv->env_ipc_snd_val  = value;
        curenv->env_ipc_snd_va   = srcva;
        curenv->env_ipc_snd_perm = perm;
        r = ipc_send_page(curenv, dst);
        if (r < 0) return r;
        dst->env_ipc_recving = 0;
        dst->env_ipc_from  = curenv->env_id;
        dst->env_ipc_value = value;
        dst->env_status    = ENV_RUNNABLE;
        dst->env_tf.tf_regs.reg_eax = 0;
        return 0;
    }

    // 队列阻塞
    curenv->env_ipc_snd_val  = value;
    curenv->env_ipc_snd_va   = srcva;
    curenv->env_ipc_snd_perm = perm;
    curenv->env_ipc_next = dst->env_ipc_sendq;
    dst->env_ipc_sendq  = curenv;
    curenv->env_status  = ENV_NOT_RUNNABLE;
    sched_yield();
    return 0;
}

static int
ipc_send_page(struct Env *src, struct Env *dst)
{
    void *srcva = src->env_ipc_snd_va;
    unsigned perm = src->env_ipc_snd_perm;
    dst->env_ipc_perm = 0;
    if (srcva < (void*)UTOP && dst->env_ipc_dstva < (void*)UTOP) {
        if ((uintptr_t)srcva & (PGSIZE - 1)) return -E_INVAL;
        if (perm & ~PTE_SYSCALL) return -E_INVAL;
        if (!(perm & PTE_U) || !(perm & PTE_P)) return -E_INVAL;
        pte_t *pte;
        struct PageInfo *pp = page_lookup(src->env_pgdir, srcva, &pte);
        if (!pp) return -E_INVAL;
        if ((perm & PTE_W) && !(*pte & PTE_W)) return -E_INVAL;
        int r = page_insert(dst->env_pgdir, pp, dst->env_ipc_dstva, perm);
        if (r < 0) return r;
        dst->env_ipc_perm = perm;
    }
    return 0;
}

// Dispatches to the correct kernel function, passing the arguments.
int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
    switch (syscallno) {
    case SYS_cputs:
        sys_cputs((const char*)a1, (size_t)a2);
        return 0;
    case SYS_cgetc:
        return sys_cgetc();
    case SYS_getenvid:
        return sys_getenvid();
    case SYS_env_destroy:
        return sys_env_destroy((envid_t)a1);
    case SYS_yield:
        sys_yield();
        return 0;
    case SYS_exofork:
        return sys_exofork();
    case SYS_env_set_status:
        return sys_env_set_status((envid_t)a1, (int)a2);
    case SYS_page_alloc:
        return sys_page_alloc((envid_t)a1, (void*)a2, (int)a3);
    case SYS_page_map:
        return sys_page_map((envid_t)a1, (void*)a2,
                            (envid_t)a3, (void*)a4, (int)a5);
    case SYS_page_unmap:
        return sys_page_unmap((envid_t)a1, (void*)a2);
	case SYS_env_set_pgfault_upcall:
	return sys_env_set_pgfault_upcall((envid_t)a1, (void*)a2);
	case SYS_ipc_try_send:
	return sys_ipc_try_send((envid_t)a1, a2, (void*)a3, (unsigned)a4);
    case SYS_ipc_recv:
        return sys_ipc_recv((void*)a1);
	case SYS_ipc_send:
        return sys_ipc_send((envid_t)a1, a2, (void*)a3, (unsigned)a4);
	case 255:
    	cprintf("cnt_ipc_send=%d cnt_ipc_try_send=%d cnt_ipc_recv=%d\n", cnt_ipc_send, cnt_ipc_try_send, cnt_ipc_recv);
    return 0;

    default:
        return -E_INVAL;
    }
}

