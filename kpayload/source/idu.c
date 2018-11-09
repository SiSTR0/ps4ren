/* SiSTRo */
/* 11/7/2018 */

#include "idu.h"

int fake_sceRegMgrGetInt(uint64_t regId, long *intVal) {
	int (*_regMgrComGetReg)(uint64_t regId, void *regVal, long regSize, long dunno) = (void *)(getkernbase() + __regMgrComGetReg);

	int result = _regMgrComGetReg(regId, intVal, 4LL, 0LL);

	if (regId == 0x2860100) {
		*intVal = 1;
		uprintf("[ps4ren] fake_sceRegMgrGetInt called - regId: %d - intVal: %d - result: %d", regId, *intVal, result);
	}

	return result;
}

void install_sceRegMgrGetInt_hook() {
	// disable write protect
	uint64_t CR0 = __readcr0();
	__writecr0(CR0 & ~CR0_WP);

	uint64_t kernbase = getkernbase();

	write_jmp(kernbase + __sceRegMgrGetInt, (uint64_t)fake_sceRegMgrGetInt);

	// restore CR0
	__writecr0(CR0);

	uprintf("[ps4ren] installed fake_sceRegMgrGetInt hook - 0x%llX", (uint64_t)fake_sceRegMgrGetInt);
}

int shellui_idu_patch() {

	uint8_t *text_seg_base = NULL;

	struct proc_vm_map_entry *entries = NULL;
	size_t num_entries;
	size_t n;

	int ret = 0;

	uint32_t ofs_to_ret_0[] = {
			0x27A0, // sceUserServiceLogin
			0x2970, // sceUserServiceLogout
			0x2C90, // sceUserServiceCreateUser
			0x2EB0, // sceUserServiceDestroyUser
	};

	struct proc *ssu = proc_find_by_name("SceShellUI");

	if (!ssu) {
		ret = 1;
		goto error;
	}

	if (proc_get_vm_map(ssu, &entries, &num_entries)) {
		ret = 1;
		goto error;
	}

	for (int i = 0; i < num_entries; i++) {
		if (!memcmp(entries[i].name, "libSceUserService.sprx", 22) && (entries[i].prot == (PROT_READ | PROT_EXEC))) {
			uprintf("[ps4ren] libSceUserService module found - 0x%llX [%d]", (uint8_t *)entries[i].start, entries[i].prot);
			text_seg_base = (uint8_t *)entries[i].start;
			break;
		}
	}

	if (!text_seg_base) {
		ret = 1;
		goto error;
	}

	for (int i = 0; i < COUNT_OF(ofs_to_ret_0); i++) {
		ret = proc_write_mem(ssu, (void *)(text_seg_base + ofs_to_ret_0[i]), 4, "\x48\x31\xC0\xC3", &n);
		if (ret) {
			goto error;
		}
	}

	error:
	if (entries) {
		dealloc(entries);
	}

	return ret;
}
