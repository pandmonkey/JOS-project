// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>
#include <inc/memlayout.h>
// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

extern void _pgfault_upcall(void);
//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
    void *addr = (void*) ROUNDDOWN(utf->utf_fault_va, PGSIZE);
    uint32_t err = utf->utf_err;
    int r;

    // 必须是写缺页 + 该页是 COW
    if (!( (err & FEC_WR) &&
           (uvpd[PDX(addr)] & PTE_P) &&
           (uvpt[PGNUM(addr)] & PTE_P) &&
           (uvpt[PGNUM(addr)] & PTE_U) &&
           (uvpt[PGNUM(addr)] & PTE_COW) )) {
        panic("pgfault: not a COW write fault va=%08x err=%x", utf->utf_fault_va, err);
    }

    // 分配临时页，复制，再替换
    if ((r = sys_page_alloc(0, (void*)PFTEMP, PTE_U|PTE_P|PTE_W)) < 0)
        panic("pgfault alloc: %e", r);
    memmove((void*)PFTEMP, addr, PGSIZE);
    if ((r = sys_page_map(0, (void*)PFTEMP, 0, addr, PTE_U|PTE_P|PTE_W)) < 0)
        panic("pgfault map: %e", r);
    if ((r = sys_page_unmap(0, (void*)PFTEMP)) < 0)
        panic("pgfault unmap temp: %e", r);
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
    int r;
    void *va = (void*)(pn * PGSIZE);
    pte_t pte = uvpt[pn];

    // 共享页直接保持原权限
    if (pte & PTE_SHARE) {
        return sys_page_map(0, va, envid, va, pte & PTE_SYSCALL);
    }

    if ((pte & PTE_W) || (pte & PTE_COW)) {
        // 设为 COW（去掉写位，双方都 COW）
        pte_t perm = PTE_U | PTE_P | PTE_COW;
        if ((r = sys_page_map(0, va, envid, va, perm)) < 0)
            return r;
        if ((r = sys_page_map(0, va, 0, va, perm)) < 0)
            return r;
    } else {
        // 只读页直接映射
        pte_t perm = PTE_U | PTE_P;
        if ((r = sys_page_map(0, va, envid, va, perm)) < 0)
            return r;
    }
    return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
    envid_t child;
    int r;

    set_pgfault_handler(pgfault);

    child = sys_exofork();
    if (child < 0)
        panic("fork: %e", child);

    if (child == 0) {
        // 子进程路径
        thisenv = &envs[ENVX(sys_getenvid())];
        return 0;
    }

    // 父进程：复制所有低于 UTOP 的用户页，跳过用户异常栈页
    for (uintptr_t va = 0; va < UTOP; va += PGSIZE) {
        // 跳过异常栈页
        if (va >= (UXSTACKTOP - PGSIZE) && va < UXSTACKTOP)
            continue;
        // PDE 不在或 PTE 不在
        if (!(uvpd[PDX(va)] & PTE_P))
            continue;
        pte_t pte = uvpt[PGNUM(va)];
        if (!(pte & PTE_P) || !(pte & PTE_U))
            continue;
        if ((r = duppage(child, PGNUM(va))) < 0)
            panic("fork duppage va=%08x: %e", va, r);
    }

    // 分配子进程的异常栈
    if ((r = sys_page_alloc(child, (void*)(UXSTACKTOP - PGSIZE), PTE_U|PTE_P|PTE_W)) < 0)
        panic("fork uxstack alloc: %e", r);

    // 注册 upcall
    if ((r = sys_env_set_pgfault_upcall(child, _pgfault_upcall)) < 0)
        panic("fork set upcall: %e", r);

    // 置为可运行
    if ((r = sys_env_set_status(child, ENV_RUNNABLE)) < 0)
        panic("fork set status: %e", r);

    return child;
}
// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
