/* golden + SiSTRo */
/* 05/03/2018 */

#include "ps4ren.h"
#include "install.h"

extern uint8_t kpayload[];
extern int32_t kpayload_size;

void ascii_art(void *_printf) {
	printf("\n\n");
	printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
	printf("             _ _                _       _     \n");
	printf("            (_) | ___ __   __ _| |_ ___| |__  \n");
	printf("            | | |/ / '_ \\ / _` | __/ __| '_ \\ \n");
	printf("            | |   <| |_) | (_| | || (__| | | |\n");
	printf("           _/ |_|\\_\\ .__/ \\__,_|\\__\\___|_| |_|\n");
	printf("          |__/     |_|                        \n");
	printf("\n");
	printf("                        Powered by\n");
	printf("   _________.__  ____________________________ ________   \n");
	printf("  /   _____/|__|/   _________    _________   \\\\_____  \\  \n");
	printf("  \\_____  \\ |  |\\_____  \\   |    |  |       _/ /   |   \\ \n");
	printf("  /        \\|  |/        \\  |    |  |    |   \\/    |    \\\n");
	printf(" /_______  /|__/_______  /  |____|  |____|_  /\\_________/\n");
	printf("         \\/            \\/                  \\/\n\n");
	printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");
}

void jailbreak(struct thread *td, uint64_t kernbase) {
	void **prison0 =   (void **)(kernbase + __prison0);
	void **rootvnode = (void **)(kernbase + __rootvnode);

	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;
	cred->cr_prison = *prison0;
	fd->fd_rdir = fd->fd_jdir = *rootvnode;
}

void debug_patches(struct thread *td, uint64_t kernbase) {
	// disable sysdump_perform_dump_on_fatal_trap
	// will continue execution and give more information on crash, such as rip
	*(uint8_t *)(kernbase + 0x7673E0) = 0xC3;

	// patch vm_map_protect check
	memcpy((void *)(kernbase + 0x1A3C08), "\x90\x90\x90\x90\x90\x90", 6);
}

void scesbl_patches(struct thread *td, uint64_t kernbase) {
	char *td_ucred = (char *)td->td_ucred;

	*(uint64_t *)(td_ucred + 0x58) = 0x3801000000000013; // gives access to everything

	*(uint64_t *)(td_ucred + 0x60) = 0xFFFFFFFFFFFFFFFF;

	*(uint64_t *)(td_ucred + 0x68) = 0xFFFFFFFFFFFFFFFF;

	// sceSblACMgrIsAllowedSystemLevelDebugging
	//*(uint8_t *)(kernbase + 0x36057B) = 0;
}

int jkpatch(struct thread *td) {
	uint64_t kernbase = getkernbase();
	resolve(kernbase);

	// disable write protect
	uint64_t CR0 = __readcr0();
	__writecr0(CR0 & ~CR0_WP);

	// enable uart
	uint8_t *disable_console_output = (uint8_t *)(kernbase + __disable_console_output);
	*disable_console_output = FALSE;

	// real quick jailbreak ;)
	jailbreak(td, kernbase);

	// quick debug patches
	debug_patches(td, kernbase);

	// sceSblMgr patches
	scesbl_patches(td, kernbase);

	// restore CR0
	__writecr0(CR0);

	// print some stuff
	ascii_art(printf);

	printf("[ps4ren] installer loaded\n");
	printf("[ps4ren] kernelbase: 0x%llX\n", kernbase);

	printf("[ps4ren] loading payload...\n");

	// install wizardry
	if (install_payload(td, kernbase, kpayload, kpayload_size)) {
		printf("[ps4ren] install_payload failed!\n");
		return 1;
	}

	printf("[ps4ren] all done! have fun with remote play!\n");

	return 0;
}

int _main(void) {
	initKernel();
	initLibc();

	syscall(11, jkpatch);

	initSysUtil();
	notify("Welcome to PS4REN v"VERSION"\nCoded by SiSTRo");

	return 0;
}
