/* golden */
/* 1/2/2018 */

#ifndef _RESOLVE_H
#define _RESOLVE_H

#include "ps4ren.h"

// this is really a dependency, called from crt

// data
void *M_TEMP;


// freebsd/common
int (*printf)(const char *fmt, ...);
int (*vprintf)(const char *fmt, va_list arg);
void *(*malloc)(unsigned long size, void *type, int flags);
void (*free)(void *addr, void *type);
void (*memcpy)(void *dst, const void *src, size_t len);
void *(*memset)(void *ptr, int value, size_t num);
int (*memcmp)(const void *ptr1, const void *ptr2, size_t num);
size_t (*strlen)(const char *str);
void (*pause)(const char *wmesg, int timo);
int (*kthread_add)(void (*func)(void *), void *arg, struct proc *procp, struct thread **newtdpp, int flags, int pages, const char *fmt, ...);
void (*kthread_exit)(void);
void (*kthread_suspend_check)(void);
void (*kthread_set_affinity)(const char *tdname, uint64_t prio, uint64_t cpuset, uint64_t unknown); // custom name
int (*kproc_create)(void (*func)(void *), void *arg, struct proc **newpp, int flags, int pages, const char *fmt, ...);
int (*kproc_kthread_add)(void (*func)(void *), void *arg, struct proc **procptr, struct thread **tdptr, int flags, int pages, char * procname, const char *fmt, ...);
void (*sched_prio)(struct thread *td, uint16_t prio);
void (*sched_add)(struct thread *td, uint64_t cpuset);
void (*kern_yield)(uint64_t p);
int (*create_thread)(struct thread * td, uint64_t ctx, void (*start_func)(void *), void *arg, char *stack_base, size_t stack_size, char *tls_base, long * child_tid, long * parent_tid, uint64_t flags, uint64_t rtp);
int (*proc_rwmem)(struct proc *p, struct uio *uio);
void (*sx_init_flags)(struct sx *sx, const char *description, int opts);
void (*sx_xlock)(struct sx *sx);
void (*sx_xunlock)(struct sx *sx);
void (*mtx_init)(struct mtx *mutex, const char *name, const char *type, int opts);
void (*mtx_lock_spin_flags)(struct mtx *mutex, int flags);
void (*mtx_unlock_spin_flags)(struct mtx *mutex, int flags);
void (*mtx_lock_sleep)(struct mtx *mutex, int flags);
void (*mtx_unlock_sleep)(struct mtx *mutex, int flags);
int (*fpu_kern_enter)(struct thread *td, void *ctx, unsigned int flags);
int (*fpu_kern_leave)(struct thread *td, void *ctx);
void (*kern_reboot)(int magic);
int	(*fill_regs)(struct thread *td, struct reg *rg);
int	(*set_regs)(struct thread *td, struct reg *rg);

// virtual memory
struct vmspace *(*vmspace_acquire_ref)(struct proc *p);
void (*vmspace_free)(struct vmspace *vm);
void (*vm_map_lock_read)(struct vm_map *map);
void (*vm_map_unlock_read)(struct vm_map *map);
int (*vm_map_lookup_entry)(struct vm_map *map, uint64_t address, struct vm_map_entry **entries);
int (*vm_map_findspace)(struct vm_map * map, uint64_t start, uint64_t length, uint64_t *addr);
int (*vm_map_insert)(struct vm_map * map, uint64_t object, uint64_t offset, uint64_t start, uint64_t end, int prot, int max, int cow);
void (*vm_map_lock)(struct vm_map * map);
void (*vm_map_unlock)(struct vm_map * map);
int (*vm_map_delete)(struct vm_map * map, uint64_t start, uint64_t end);
int (*vm_map_protect)(struct vm_map * map, uint64_t start, uint64_t end, int new_prot, uint64_t set_max);
void (*eventhandler_register)(void *list, const char *name, void *func, void *arg, int priority);

void resolve(uint64_t kernbase);

#endif
