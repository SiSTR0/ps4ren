/* SiSTRo */
/* 3/13/2020 */

#include "patch.h"

int shellui_patch() {

    uint8_t *ssu_text_seg_base = NULL,
            *ssu_app_text_seg_base = NULL;

    struct proc_vm_map_entry *entries = NULL;
    size_t num_entries;
    size_t n;

    int ret = 0;

    struct proc *ssui = proc_find_by_name("SceShellUI");

    if (!ssui) {
        ret = 1;
        goto error;
    }

    if (proc_get_vm_map(ssui, &entries, &num_entries)) {
        ret = 1;
        goto error;
    }

    for (int i = 0; i < num_entries; i++) {
        if (!memcmp(entries[i].name, "executable", 10) && (entries[i].prot >= (PROT_READ | PROT_EXEC))) {
            uprintf("[ps4ren] SceShellUI found - 0x%llX [%d]", (uint8_t *)entries[i].start, entries[i].prot);
            ssu_text_seg_base  = (uint8_t *)entries[i].start;
            break;
        }
    }

    if (!ssu_text_seg_base ) {
        ret = 1;
        goto error;
    }

    // disable CreateUserForIDU
    ret = proc_write_mem(ssui, (void *)(ssu_text_seg_base  + __CreateUserForIDU_patch), 4, "\x48\x31\xC0\xC3", &n);
    if (ret) {
        goto error;
    }

    for (int i = 0; i < num_entries; i++) {
        if (!memcmp(entries[i].name, "app.exe.sprx", 12) && (entries[i].prot >= (PROT_READ | PROT_EXEC))) {
            uprintf("[ps4ren] SceShellUI > app.exe.sprx found - 0x%llX [%d]", (uint8_t *)entries[i].start, entries[i].prot);
            ssu_app_text_seg_base  = (uint8_t *)entries[i].start;
            break;
        }
    }

    if (!ssu_app_text_seg_base) {
        ret = 1;
        goto error;
    }

    // enable remote play menu - credits to Aida
    ret = proc_write_mem(ssui, (void *)(ssu_app_text_seg_base  + __remote_play_menu_patch), 5, "\xE9\x82\x02\x00\x00", &n);

    uprintf("[ps4ren] SceShellUI successfully patched!");

    error:
    if (entries) {
        dealloc(entries);
    }

    return ret;
}

int remoteplay_patch() {

    uint8_t *srp_text_seg_base = NULL;

    struct proc_vm_map_entry *entries = NULL;
    size_t num_entries;
    size_t n;

    int ret = 0;

    struct proc *srp = proc_find_by_name("SceRemotePlay");

    if (!srp) {
        ret = 1;
        goto error;
    }

    if (proc_get_vm_map(srp, &entries, &num_entries)) {
        ret = 1;
        goto error;
    }

    for (int i = 0; i < num_entries; i++) {
        if (!memcmp(entries[i].name, "executable", 10) && (entries[i].prot == (PROT_READ | PROT_EXEC))) {
            uprintf("[ps4ren] SceRemotePlay found - 0x%llX [%d]", (uint8_t *)entries[i].start, entries[i].prot);
            srp_text_seg_base = (uint8_t *)entries[i].start;
            break;
        }
    }

    if (!srp_text_seg_base) {
        ret = 1;
        goto error;
    }

    // patch SceRemotePlay process
    ret = proc_write_mem(srp, (void *)(srp_text_seg_base + __SceRemotePlay_patch1), 1, "\x01", &n);
    if (ret) {
        goto error;
    }

    ret = proc_write_mem(srp, (void *)(srp_text_seg_base + __SceRemotePlay_patch2), 2, "\xEB\x1E", &n);
    if (ret) {
        goto error;
    }

    uprintf("[ps4ren] SceRemotePlay successfully patched!");

error:
    if (entries) {
        dealloc(entries);
    }

    return ret;
}

void remoteplay_patches() {
    shellui_patch();
    remoteplay_patch();
}

void install_remoteplay_patches() {
    remoteplay_patches();
    eventhandler_register(NULL, "system_resume_phase4", &remoteplay_patches, NULL, EVENTHANDLER_PRI_LAST);
}