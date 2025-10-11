// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{"backtrace", "Backtrace the details of called functions", mon_backtrace},
	{"showmap", "Show VA -> PA and its permissions", mon_showmap},
	{"setperm", "Set the VA -> PA's permissions", mon_setperm},
	{"dumpva", "dump the contents of a specified virtual address", mon_dumpva}, 
	{"dumppa", "dump the contents of a specified physical address", mon_dumppa}
};

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(commands); i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	// Your code here.
	// 读出 ebp 的指针
	// ebp 以上还有 eip, 未知数量个 args
	uint32_t *ebp = (uint32_t *)read_ebp(); // 得到当前的 rbp pointer
	while (ebp) {
		struct Eipdebuginfo info;
		cprintf("ebp %08x  eip %08x  args %08x %08x %08x %08x %08x\n", ebp, ebp[1], ebp[2], ebp[3], ebp[4], ebp[5], ebp[6]);
		int status = debuginfo_eip(ebp[1], &info);
		// const  char* filename=(&info)->eip_file;
	    // int line = (&info)->eip_line;
	    // const char * not_null_ter_fname=(&info)->eip_fn_name;
	    // int offset = (int)(ebp[1])-(int)((&info)->eip_fn_addr);
	    // cprintf("        %s:%d:  %.*s+%d\n",filename,line,info.eip_fn_namelen,not_null_ter_fname,offset);
		const char *file = info.eip_file;
		const int file_linenum = info.eip_line;

		const int fn_length = info.eip_fn_namelen;
		const char *fn_name = info.eip_fn_name;
		const int fn_linenum = (uintptr_t)ebp[1] - info.eip_fn_addr;
			cprintf("     %s:%d:  %.*s+%d\n", file, file_linenum, fn_length, fn_name, fn_linenum);
		ebp = (uint32_t *)(*ebp);
	}
	return 0;
}

int mon_showmap(int argc, char **argv, struct Trapframe *tf) {
	// 先判断 showmap 的相关参数是否合法
	if (argc < 2 || argc > 3) {
		showmap_usage();
		return 0;
	}
	
	char *endp = NULL;
	uintptr_t va_start = (uintptr_t)strtol(argv[1], &endp, 0);

		if (endp == argv[1]) {
		cprintf("showmap: invalid va_start\n");
		return 0;
    	}

		if (argc == 2) {
			// 单地址查询
			struct map_entry me;
			memset(&me, 0, sizeof(me));
			int r = pmap_lookup_mapping(kern_pgdir, va_start, &me);
			if (r != -3) {
				
				showmap_print_single_entry(&me); // 打印一条
			} else {
				// -3 --> -E_INVAL
				cprintf("pgdir or map_entry is null"); // 发生错误
				return 0;
			}
		} else {
			// for 轮询
			uintptr_t va_end = (uintptr_t) strtol(argv[2], &endp, 0);
			if (endp == argv[2] || va_end <= va_start) {
			cprintf("showmap: invalid range\n");
			return 0;
			}
			for (size_t i = va_start; i < va_end; i+= PGSIZE) {
				struct map_entry me;
				memset(&me, 0, sizeof(me));
				int r = pmap_lookup_mapping(kern_pgdir, i, &me);
				if (r != -3) {
					showmap_print_single_entry(&me);
				} else {
					cprintf("pgdir or map entry is null");
					return 0;
				}
			}
		}


	return 0;
}

int mon_setperm(int argc, char **argv, struct Trapframe *tf) {
	static const char *msg = 
	"Usage: setperm <virtualaddress> <permission>\n"; // 输入不合法时
	if (argc != 3) {
		cprintf(msg);
		return 0;
	}

	void *va = (void *)strtol(argv[1], NULL, 0);
	uint32_t perm = (uint32_t)strtol(argv[2], NULL, 0);
	pte_t *pte = pgdir_walk(kern_pgdir, va, 0);

	if (pte && (*pte)&PTE_P) {
		*pte = (*pte & (~0xfff)) | PTE_P | (perm & 0xfff);
	} else {
		cprintf("There is no such mapping\n");
	}
	return 0;
}

int mon_dumpva(int argc, char **argv, struct Trapframe *tf) {
	static const char *msg = 
	"Usage: dumpva <start_va> <length>\n";
	if (argc !=3) {
		cprintf(msg);
		return 0;
	}
	uintptr_t start = (uintptr_t)strtol(argv[1], NULL, 0);
	size_t len = (size_t)strtol(argv[2], NULL, 0);
	uintptr_t end = start + len;

	uintptr_t cur = start;
	while(cur < end) {
		// 注意区分颗粒度, 每次是考虑一个页, 对于一个页的内容, 显然是适用一个 pte的

		// 找到页末
		uintptr_t page_end = MIN(ROUNDUP(cur + 1, PGSIZE), end); // 
		// pgdir_walk 得到 pte_t *
		pte_t * pte = pgdir_walk(kern_pgdir, (void *)cur, 0);
		// 判定: 如果 unmapped 直接跳过
		if (!pte || !(*pte && PTE_P)) {
			cprintf( "VA 0x%08x-0x%08x: unmapped\n",
				(uint32_t)ROUNDDOWN(cur, PGSIZE), (uint32_t)(page_end - 1)
			);
			cur = page_end;
			continue;;
		}
		// 从 cur ~ page_end 进行 输出
		while(cur < page_end) {
			uint8_t v = *(uint8_t*)cur;
			cprintf("VA 0x%08x -- %02x\n", (uint32_t)cur, v);
			cur++;
		}
	}
	return 0;
}
int mon_dumppa(int argc, char **argv, struct Trapframe *tf) {
		static const char *msg = 
	"Usage: dumppa <start_pa> <length>\n";
	if (argc !=3) {
		cprintf(msg);
		return 0;
	}
	return 0;
}



/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");


	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}


// Helper Functions:
	// helper function of showmap
	// showmap 参数不合法的使用说明
static void showmap_usage() {
	cprintf("Usage: showmap vastart [va_end]\n");
	cprintf("- If only vastart is given, show mapping for that page. \n");
	cprintf("- address may not be alligned because they will be ROUND_DOWNd. \n");
}


static int showmap_print_single_entry(const struct map_entry *me) {
	if (me ->pte & PTE_P) {
		const char *perm = get_perm(me->pte);
				cprintf("VA %08lx -> PA %08lx  PTE=%08lx  Perm=%s\n",
				(unsigned long)me->va,
				(unsigned long)me->pa,
				(unsigned long)me->pte,
				perm);
	} else {
		cprintf("VA %08lx -> unmapped\n", (unsigned long)me->va);
	}
	return 0; 	
}

static inline char* get_perm(pte_t pte) {
	static char buf[8];
	int i = 0;
	buf[i++] = (pte & PTE_P) ? 'P' : '-';
	buf[i++] = (pte & PTE_W) ? 'W' : '-';
	buf[i++] = (pte & PTE_U) ? 'U' : '-';
	buf[i] = 0;
	return buf;
}