#import "TRCCommon.h"

#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>
#import <dirent.h>
#import <errno.h>
#import <string.h>
#import <unistd.h>
#import <sys/mman.h>
#import <sys/sysctl.h>
#import <mach/mach.h>
#import <mach/vm_page_size.h>
#import <mach/vm_map.h>   // vm_protect 在 iOS SDK 只有这里声明
#import <mach-o/nlist.h>

#if defined(__arm64e__)
#import <ptrauth.h>
#define TRC_SIGN_FN(p) ((void *)ptrauth_sign_unauthenticated((void *)(p), ptrauth_key_function_pointer, 0))
#else
#define TRC_SIGN_FN(p) ((void *)(p))
#endif

typedef struct __SecTask *SecTaskRef;

enum {
    TRC_CS_OPS_STATUS = 0,
    TRC_CS_OPS_CDHASH = 5,
    TRC_CS_OPS_ENTITLEMENTS_BLOB = 7,
};

enum {
    TRC_CS_VALID = 0x00000001,
    TRC_CS_DEBUGGED = 0x10000000,
};

static uint32_t (*orig_image_count)(void);
static const char *(*orig_image_name)(uint32_t);
static const struct mach_header *(*orig_image_header)(uint32_t);
static intptr_t (*orig_image_slide)(uint32_t);

static int (*orig_access)(const char *, int);
static struct dirent *(*orig_readdir)(DIR *);
static int (*orig_readdir_r)(DIR *, struct dirent *, struct dirent **);
static ssize_t (*orig_getdirentries64)(int, void *, size_t, off_t *);

static int (*orig_csops)(pid_t, unsigned int, void *, size_t);
static CFTypeRef (*orig_sec_task_value)(SecTaskRef, CFStringRef, CFErrorRef *);
static CFStringRef (*orig_sec_task_signing_id)(SecTaskRef, CFErrorRef *);

static BOOL gSkipChainedImages = YES;
static BOOL gPatchDataConst = NO;

static BOOL TRCIsHiddenIndex(uint32_t index);
static int trc_access(const char *path, int mode);
static struct dirent *trc_readdir(DIR *dir);
static int trc_readdir_r(DIR *dir, struct dirent *entry, struct dirent **result);
static ssize_t trc_getdirentries64(int fd, void *buffer, size_t size, off_t *basep);
static int trc_csops(pid_t pid, unsigned int op, void *addr, size_t size);
static CFTypeRef trc_sec_task_value(SecTaskRef task, CFStringRef key, CFErrorRef *error);
static CFStringRef trc_sec_task_signing_id(SecTaskRef task, CFErrorRef *error);

#ifndef LC_DYLD_CHAINED_FIXUPS
#define LC_DYLD_CHAINED_FIXUPS 0x80000034
#endif

BOOL TRCPathHidden(const char *path) {
    if (!path) return NO;
    for (NSString *needle in TRCConfigArray(@"HideNeedles")) {
        const char *raw = needle.UTF8String;
        if (raw && strstr(path, raw)) return YES;
    }
    return NO;
}

static uint32_t TRCVisibleIndex(uint32_t visible) {
    uint32_t total = orig_image_count();
    uint32_t seen = 0;

    for (uint32_t i = 0; i < total; i++) {
        if (TRCIsHiddenIndex(i)) continue;
        if (seen == visible) return i;
        seen++;
    }
    return UINT32_MAX;
}

static uint32_t trc_image_count(void) {
    uint32_t total = orig_image_count();
    uint32_t visible = 0;
    for (uint32_t i = 0; i < total; i++) {
        if (!TRCIsHiddenIndex(i)) visible++;
    }
    return visible;
}

static const char *trc_image_name(uint32_t index) {
    uint32_t real = TRCVisibleIndex(index);
    return real == UINT32_MAX ? NULL : orig_image_name(real);
}

static const struct mach_header *trc_image_header(uint32_t index) {
    uint32_t real = TRCVisibleIndex(index);
    return real == UINT32_MAX ? NULL : orig_image_header(real);
}

static intptr_t trc_image_slide(uint32_t index) {
    uint32_t real = TRCVisibleIndex(index);
    return real == UINT32_MAX ? 0 : orig_image_slide(real);
}

static BOOL TRCIsHiddenIndex(uint32_t index) {
    const char *name = orig_image_name(index);
    return TRCPathHidden(name);
}

static uint64_t TRCTextVMAddr(const struct mach_header_64 *header) {
    const struct load_command *lc = (const struct load_command *)(header + 1);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *segment = (const struct segment_command_64 *)lc;
            if (strncmp(segment->segname, "__TEXT", 16) == 0) return segment->vmaddr;
        }
        lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
    }
    return 0;
}

static BOOL TRCImageUsesChainedFixups(const struct mach_header_64 *header) {
    const struct load_command *lc = (const struct load_command *)(header + 1);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (lc->cmd == LC_DYLD_CHAINED_FIXUPS) return YES;
        lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
    }
    return NO;
}

static void TRCRebindImage(const struct mach_header_64 *header,
                           intptr_t slide,
                           const char *symbol,
                           void *replacement) {
    if (!header || header->magic != MH_MAGIC_64) return;
    if (gSkipChainedImages && TRCImageUsesChainedFixups(header)) return;

    const struct load_command *lc = (const struct load_command *)(header + 1);
    const struct symtab_command *symtab = NULL;
    const struct dysymtab_command *dysymtab = NULL;

    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (lc->cmd == LC_SYMTAB) symtab = (const struct symtab_command *)lc;
        if (lc->cmd == LC_DYSYMTAB) dysymtab = (const struct dysymtab_command *)lc;
        lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
    }
    if (!symtab || !dysymtab) return;

    const struct nlist_64 *symbols = (const struct nlist_64 *)((const uint8_t *)header + symtab->symoff);
    const char *strings = (const char *)header + symtab->stroff;
    const uint32_t *indirect = (const uint32_t *)((const uint8_t *)header + dysymtab->indirectsymoff);
    const uint64_t textVMAddr = TRCTextVMAddr(header);

    lc = (const struct load_command *)(header + 1);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *segment = (const struct segment_command_64 *)lc;
            const struct section_64 *section = (const struct section_64 *)(segment + 1);

            for (uint32_t s = 0; s < segment->nsects; s++, section++) {
                uint32_t type = section->flags & SECTION_TYPE;
                if (type != S_NON_LAZY_SYMBOL_POINTERS && type != S_LAZY_SYMBOL_POINTERS) continue;
                if (!gPatchDataConst && strncmp(segment->segname, "__DATA_CONST", 16) == 0) continue;
                if (section->addr < textVMAddr) continue;

                void **slots = (void **)((uint8_t *)header + (section->addr - textVMAddr));
                for (uint32_t k = 0; k < section->size / sizeof(void *); k++) {
                    uint32_t symIndex = indirect[section->reserved1 + k];
                    if (symIndex == INDIRECT_SYMBOL_LOCAL || symIndex == INDIRECT_SYMBOL_ABS) continue;

                    const char *name = strings + symbols[symIndex].n_un.n_strx;
                    if (strcmp(name, symbol) != 0) continue;

                    vm_address_t page = (vm_address_t)&slots[k] & ~(vm_page_size - 1);
                    vm_protect(mach_task_self(), page, vm_page_size, false,
                               VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
                    slots[k] = TRC_SIGN_FN(replacement);
                }
            }
        }
        lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
    }
}

void TRCRebindAll(const char *symbol, void *replacement) {
    if (!symbol || !replacement) return;

    uint32_t count = orig_image_count ? orig_image_count() : _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *header = orig_image_header ? orig_image_header(i) : _dyld_get_image_header(i);
        intptr_t slide = orig_image_slide ? orig_image_slide(i) : _dyld_get_image_vmaddr_slide(i);
        TRCRebindImage((const struct mach_header_64 *)header, slide, symbol, replacement);
    }
}

static void TRCOnImageAdded(const struct mach_header *header, intptr_t slide) {
    if (!header || header->cputype != CPU_TYPE_ARM64) return;

    TRCRebindImage((const struct mach_header_64 *)header, slide, "__dyld_image_count", (void *)trc_image_count);
    TRCRebindImage((const struct mach_header_64 *)header, slide, "__dyld_get_image_name", (void *)trc_image_name);
    TRCRebindImage((const struct mach_header_64 *)header, slide, "__dyld_get_image_header", (void *)trc_image_header);
    TRCRebindImage((const struct mach_header_64 *)header, slide, "__dyld_get_image_vmaddr_slide", (void *)trc_image_slide);
    if (orig_access) {
        TRCRebindImage((const struct mach_header_64 *)header, slide, "_access", (void *)trc_access);
    }
    if (orig_readdir) {
        TRCRebindImage((const struct mach_header_64 *)header, slide, "_readdir", (void *)trc_readdir);
    }
    if (orig_readdir_r) {
        TRCRebindImage((const struct mach_header_64 *)header, slide, "_readdir_r", (void *)trc_readdir_r);
    }
    if (orig_getdirentries64) {
        TRCRebindImage((const struct mach_header_64 *)header, slide, "_getdirentries64", (void *)trc_getdirentries64);
    }
    if (orig_csops) {
        TRCRebindImage((const struct mach_header_64 *)header, slide, "_csops", (void *)trc_csops);
    }
    if (orig_sec_task_value) {
        TRCRebindImage((const struct mach_header_64 *)header, slide,
                       "_SecTaskCopyValueForEntitlement", (void *)trc_sec_task_value);
    }
    if (orig_sec_task_signing_id) {
        TRCRebindImage((const struct mach_header_64 *)header, slide,
                       "_SecTaskCopySigningIdentifier", (void *)trc_sec_task_signing_id);
    }
}

static int trc_access(const char *path, int mode) {
    if (TRCPathHidden(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_access(path, mode);
}

static struct dirent *trc_readdir(DIR *dir) {
    struct dirent *entry = NULL;
    do {
        entry = orig_readdir(dir);
    } while (entry && TRCPathHidden(entry->d_name));
    return entry;
}

static int trc_readdir_r(DIR *dir, struct dirent *entry, struct dirent **result) {
    int rc = 0;
    do {
        rc = orig_readdir_r(dir, entry, result);
        if (rc != 0 || !*result) return rc;
    } while (TRCPathHidden((*result)->d_name));
    return rc;
}

static ssize_t trc_getdirentries64(int fd, void *buffer, size_t size, off_t *basep) {
    ssize_t total = orig_getdirentries64(fd, buffer, size, basep);
    if (total <= 0) return total;

    uint8_t *readPtr = (uint8_t *)buffer;
    uint8_t *writePtr = (uint8_t *)buffer;
    uint8_t *end = readPtr + total;

    while (readPtr < end) {
        struct dirent *entry = (struct dirent *)readPtr;
        if (entry->d_reclen == 0) break;

        if (!TRCPathHidden(entry->d_name)) {
            if (writePtr != readPtr) memmove(writePtr, readPtr, entry->d_reclen);
            writePtr += entry->d_reclen;
        }
        readPtr += entry->d_reclen;
    }
    return writePtr - (uint8_t *)buffer;
}

static int trc_csops(pid_t pid, unsigned int op, void *addr, size_t size) {
    static const uint8_t fakeCDHash[20] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,
        0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x01,0x02,0x03,0x04
    };

    if (op == TRC_CS_OPS_STATUS && addr && size >= sizeof(uint32_t)) {
        uint32_t *flags = (uint32_t *)addr;
        *flags &= ~TRC_CS_DEBUGGED;
        *flags |= TRC_CS_VALID;
        return 0;
    }
    if (op == TRC_CS_OPS_CDHASH && addr && size >= sizeof(fakeCDHash)) {
        memcpy(addr, fakeCDHash, sizeof(fakeCDHash));
        return 0;
    }
    if (op == TRC_CS_OPS_ENTITLEMENTS_BLOB && addr && size >= 8) {
        memset(addr, 0, size);
        return 0;
    }
    return orig_csops ? orig_csops(pid, op, addr, size) : -1;
}

static CFTypeRef trc_sec_task_value(SecTaskRef task, CFStringRef key, CFErrorRef *error) {
    NSString *name = (__bridge NSString *)key;
    NSString *team = TRCConfigString(@"FakeTeamID");
    NSString *bundle = TRCConfigString(@"FakeBundleID");

    if ([name isEqualToString:@"application-identifier"]) {
        return (__bridge CFTypeRef)[NSString stringWithFormat:@"%@.%@", team, bundle];
    }
    if ([name isEqualToString:@"com.apple.developer.team-identifier"]) {
        return (__bridge CFTypeRef)team;
    }
    if ([name isEqualToString:@"get-task-allow"]) {
        return (__bridge CFTypeRef)@NO;
    }
    return orig_sec_task_value ? orig_sec_task_value(task, key, error) : NULL;
}

static CFStringRef trc_sec_task_signing_id(SecTaskRef task, CFErrorRef *error) {
    NSString *bundle = TRCConfigString(@"FakeBundleID");
    return (__bridge_retained CFStringRef)bundle;
}

void TRCInstallHideDylib(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gSkipChainedImages = TRCConfigBool(@"SkipChainedImages");
        gPatchDataConst = TRCConfigBool(@"PatchDataConst");

        orig_image_count = dlsym(RTLD_DEFAULT, "_dyld_image_count");
        orig_image_name = dlsym(RTLD_DEFAULT, "_dyld_get_image_name");
        orig_image_header = dlsym(RTLD_DEFAULT, "_dyld_get_image_header");
        orig_image_slide = dlsym(RTLD_DEFAULT, "_dyld_get_image_vmaddr_slide");

        orig_access = dlsym(RTLD_DEFAULT, "access");
        orig_readdir = dlsym(RTLD_DEFAULT, "readdir");
        orig_readdir_r = dlsym(RTLD_DEFAULT, "readdir_r");
        orig_getdirentries64 = dlsym(RTLD_DEFAULT, "getdirentries64");

        orig_csops = dlsym(RTLD_DEFAULT, "csops");
        orig_sec_task_value = dlsym(RTLD_DEFAULT, "SecTaskCopyValueForEntitlement");
        orig_sec_task_signing_id = dlsym(RTLD_DEFAULT, "SecTaskCopySigningIdentifier");

        _dyld_register_func_for_add_image(TRCOnImageAdded);

        uint32_t count = _dyld_image_count();
        for (uint32_t i = 0; i < count; i++) {
            TRCOnImageAdded(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
        }
    });
}
