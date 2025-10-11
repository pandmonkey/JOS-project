#ifndef JOS_KERN_MONITOR_H
#define JOS_KERN_MONITOR_H
#ifndef JOS_KERNEL
# error "This is a JOS kernel header; user programs should not #include it"
#endif
#include <kern/pmap.h>
struct Trapframe;

// Activate the kernel monitor,
// optionally providing a trap frame indicating the current state
// (NULL if none).
void monitor(struct Trapframe *tf);

// Functions implementing monitor commands.
int mon_help(int argc, char **argv, struct Trapframe *tf);
int mon_kerninfo(int argc, char **argv, struct Trapframe *tf);
int mon_backtrace(int argc, char **argv, struct Trapframe *tf);
int mon_showmap(int argc, char **argv, struct Trapframe *tf);
int mon_setperm(int argc, char **argv, struct Trapframe *tf);
int mon_dumpva(int argc, char **argv, struct Trapframe *tf);
int mon_dumppa(int argc, char **argv, struct Trapframe *tf);

// Helper Functions
    // helper function of showmap:
static void showmap_usage();
static int showmap_print_single_entry(const struct map_entry *me);
static inline char* get_perm(pte_t pte);
// Make sure the definition in the corresponding .c file matches this declaration.
#endif	// !JOS_KERN_MONITOR_H
