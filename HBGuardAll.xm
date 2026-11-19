/**********************************************************************
 *  HBGuardAll.xm —— 单文件整合版
 *
 *  内容：
 *    1. Replica       反检测逐条复刻（34 条 hook，对齐 TrafficRules.dylib）
 *    2. Tweak         自身 + 第三方插件镜像隐藏（dyld 改名 / LC_ID_DYLIB / 文件系统过滤）
 *    3. URLHijack     URL 重定向 + appKey 替换 + sign 重算（合并自 URLHijackDetector）
 *    4. Coverage      插件之外的补漏（默认关闭）
 *    5. Support       Mach-O 工具 / 符号重绑 / 配置
 *
 *  编译：Theos（ARCHS=arm64 arm64e），或直接喂给打包工具
 *  配置：CFPreferences domain = com.local.hbguard，全部默认开启
 **********************************************************************/

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <string.h>
#import <stdlib.h>
#import <unistd.h>
#import <errno.h>
#import <dirent.h>
#import <sys/stat.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach/mach.h>
#import <mach/vm_prot.h>
#import <CommonCrypto/CommonDigest.h>

#ifndef INDIRECT_SYMBOL_LOCAL
#define INDIRECT_SYMBOL_LOCAL 0x80000000
#endif
#ifndef INDIRECT_SYMBOL_ABS
#define INDIRECT_SYMBOL_ABS   0x40000000
#endif
#ifndef SECTION_TYPE
#define SECTION_TYPE          0x000000ff
#endif

/* ==================== Support/HBGConfig.h ==================== */
//
//  HBGConfig.h
//  配置项：默认全部开启（未写入过时返回默认值）
//
#ifndef HBGCONFIG_H
#define HBGCONFIG_H


/// 总开关，默认 YES
BOOL HBGEnabled(void);

/// 隐藏目标插件（图片里那批），默认 YES
BOOL HBGHideTargetsEnabled(void);

/// 连官方 framework 一起隐藏（Unicorn / nuisdk 等），默认 NO —— 有风险
BOOL HBGHideOfficialEnabled(void);

/// 合并进来的 URL 劫持，默认 YES
BOOL HBGURLHijackEnabled(void);

/// 伪造完整性（SPAppInfo / SPCheckInfo 那 5 个方法），默认 YES
BOOL HBGIntegrityEnabled(void);

/// 按 selector 名全类扫描补漏（apf_/dogger_/elm_/eps_/hbf_ 那几套），默认 YES
BOOL HBGCoverageEnabled(void);

/// execFileMd5 要固定返回的哈希（重打包后必须伪造）
/// 默认就是样本里解出来的常量，可通过 prefs 覆盖成别的版本
NSString *HBGExecMd5(void);

/// 官方原版的 Team ID / application-identifier（有就伪造，没有返回 nil）
NSString *HBGOriginTeamId(void);
NSString *HBGOriginAppIdentifier(void);

/// 模拟器 / 定位来源抹除（installHideSimHooks 等价实现），默认 YES
BOOL HBGSimHideEnabled(void);

/// 跨镜像重绑 readdir/access（改 __DATA 里的间接符号指针），默认 NO
BOOL HBGRebindEnabled(void);

/// 写配置（也可以用 defaults 命令从外部改）
void HBGSetBool(NSString *key, BOOL value);

/// 打印当前配置（调试用）
void HBGDumpConfig(void);

#endif /* HBGCONFIG_H */

/* ==================== Support/HBGConfig.m ==================== */
//
//  HBGConfig.m
//

static CFStringRef HBGDomain(void) {
    return CFSTR("com.local.hbguard");
}

static BOOL HBGBool(CFStringRef key, BOOL def) {
    CFPreferencesAppSynchronize(HBGDomain());
    Boolean ok = false;
    Boolean v  = CFPreferencesGetAppBooleanValue(key, HBGDomain(), &ok);
    return ok ? (v ? YES : NO) : def;      // 没写过就用默认值
}

BOOL HBGEnabled(void)              { return HBGBool(CFSTR("enabled"),        YES); }
BOOL HBGHideTargetsEnabled(void)   { return HBGBool(CFSTR("hideTargets"),    YES); }
BOOL HBGHideOfficialEnabled(void)  { return HBGBool(CFSTR("hideOfficial"),   NO);  }
BOOL HBGURLHijackEnabled(void)     { return HBGBool(CFSTR("urlHijack"),      YES); }
BOOL HBGIntegrityEnabled(void)     { return HBGBool(CFSTR("integrity"),     YES); }
// 默认关：Replica.xm 已经逐条对齐插件本体，
// Coverage 是「插件没覆盖到的那批」的额外补漏，会改变插件原本的行为面。
BOOL HBGCoverageEnabled(void)      { return HBGBool(CFSTR("coverage"),      NO); }
BOOL HBGSimHideEnabled(void)       { return HBGBool(CFSTR("simHide"),      YES); }
// 默认关：跨镜像改 __DATA 里的间接符号指针风险最高（写错一个地址就启动崩），
// 而文件访问面已经有 NSFileManager / NSData 的 ObjC hook 覆盖。
// 确认环境稳定后可用 defaults write com.local.hbguard rebind -bool YES 打开。
BOOL HBGRebindEnabled(void)        { return HBGBool(CFSTR("rebind"),       NO); }

// 重打包后主程序哈希必变，这个值必须固定。
// 默认取样本里现场解密出来的常量：e4d330c15021d53a959aca760dbb845e
// 换包（不同 App 版本）时用
//   defaults write com.local.hbguard execMd5 -string <新哈希>
// 覆盖即可，不用重编译。
static NSString *const kHBGDefaultExecMd5 = @"e4d330c15021d53a959aca760dbb845e";

NSString *HBGExecMd5(void) {
    CFPreferencesAppSynchronize(HBGDomain());
    CFStringRef v = (CFStringRef)CFPreferencesCopyAppValue(CFSTR("execMd5"), HBGDomain());
    if (v) {
        NSString *s = [(__bridge NSString *)v copy];
        CFRelease(v);
        if (s.length >= 32) return s;
    }
    return kHBGDefaultExecMd5;
}

// 官方原版的 Team ID / application-identifier。
// 没配就返回 nil —— 样本的做法本来也是 getTeamInfo→"null"、bundleTeamIdentifier→nil。
static NSString *HBGStringPref(CFStringRef key) {
    CFPreferencesAppSynchronize(HBGDomain());
    CFStringRef v = (CFStringRef)CFPreferencesCopyAppValue(key, HBGDomain());
    if (!v) return nil;
    NSString *s = [(__bridge NSString *)v copy];
    CFRelease(v);
    return s.length ? s : nil;
}

NSString *HBGOriginTeamId(void) {
    return HBGStringPref(CFSTR("teamId"));
}

NSString *HBGOriginAppIdentifier(void) {
    return HBGStringPref(CFSTR("appIdentifier"));
}

void HBGSetBool(NSString *key, BOOL value) {
    if (!key) return;
    CFPreferencesSetAppValue((__bridge CFStringRef)key,
                             (value ? kCFBooleanTrue : kCFBooleanFalse),
                             HBGDomain());
    CFPreferencesAppSynchronize(HBGDomain());
}

void HBGDumpConfig(void) {
    NSLog(@"[HBGuard] enabled=%d hideTargets=%d hideOfficial=%d urlHijack=%d integrity=%d",
          HBGEnabled(), HBGHideTargetsEnabled(), HBGHideOfficialEnabled(),
          HBGURLHijackEnabled(), HBGIntegrityEnabled());
}

/* ==================== Support/HBGMachO.h ==================== */
//
//  HBGMachO.h
//  内存中 Mach-O 的只读工具 + dyld 镜像改名
//
#ifndef HBGMACHO_H
#define HBGMACHO_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

int  hbg_image_count(void);
const char *hbg_image_path(uint32_t idx);
const struct mach_header_64 *hbg_image_header(uint32_t idx);
intptr_t hbg_image_slide(uint32_t idx);

/// 把某段内存改成可写（页对齐 + VM_PROT_COPY）
int  hbg_make_writable(void *addr, size_t len);

/// 把第 idx 个镜像在 dyld 里的**整条路径**改写成 fakePath（长度必须 <= 原路径）
/// dyld_image_info.imageFilePath 指向同一块内存，改完立即对枚举方生效
int  hbg_rename_image_path(uint32_t idx, const char *fakePath);

/// 只改 basename（整条路径放不下时的退路）
int  hbg_rename_image_basename(uint32_t idx, const char *fakeBase);

/// 改自身 mach_header 里的 LC_ID_DYLIB 名字
int  hbg_rename_id_dylib(uint32_t idx, const char *fakePath);

/// path 的 basename 是否严格等于 name（不吃子串，避免 "i.dylib" 误伤 "xiaosaobi.dylib"）
bool hbg_basename_is(const char *path, const char *name);

/// path 里是否含有 "/dir/" 这样的目录段（用于 xxx.framework）
bool hbg_path_has_dir(const char *path, const char *dir);

/// 隐藏一个目标：命中就整条路径改名，失败退化为 basename
/// 返回被改写的镜像数量
int  hbg_hide_target(const char *key, const char *fakePath);

#ifdef __cplusplus
}
#endif

#endif /* HBGMACHO_H */

/* ==================== Support/HBGMachO.c ==================== */
//
//  HBGMachO.c
//

#include <stdio.h>
#include <sys/mman.h>

int hbg_image_count(void) {
    return (int)_dyld_image_count();
}

const char *hbg_image_path(uint32_t idx) {
    return _dyld_get_image_name(idx);
}

const struct mach_header_64 *hbg_image_header(uint32_t idx) {
    const struct mach_header *h = _dyld_get_image_header(idx);
    if (!h) return NULL;
    if (h->magic != MH_MAGIC_64) return NULL;      // 只处理 arm64
    return (const struct mach_header_64 *)h;
}

intptr_t hbg_image_slide(uint32_t idx) {
    return _dyld_get_image_vmaddr_slide(idx);
}

int hbg_make_writable(void *addr, size_t len) {
    if (!addr || len == 0) return -1;
    long pg = sysconf(_SC_PAGESIZE);
    if (pg <= 0) pg = 0x4000;
    uintptr_t start = (uintptr_t)addr & ~((uintptr_t)pg - 1);
    uintptr_t end   = ((uintptr_t)addr + len + (uintptr_t)pg - 1) & ~((uintptr_t)pg - 1);
    kern_return_t kr = vm_protect(mach_task_self(),
                                  (vm_address_t)start,
                                  (vm_size_t)(end - start),
                                  false,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    return (kr == KERN_SUCCESS) ? 0 : -1;
}

int hbg_rename_image_path(uint32_t idx, const char *fakePath) {
    const char *p = _dyld_get_image_name(idx);
    if (!p || !fakePath) return -1;

    char *w = (char *)p;
    size_t cap = strlen(w);
    size_t fl  = strlen(fakePath);
    if (cap == 0) return -1;
    if (fl > cap) return -2;                  // 放不下，交由调用方退化

    if (hbg_make_writable(w, cap + 1) != 0) return -3;

    memcpy(w, fakePath, fl);
    memset(w + fl, 0, cap - fl);              // 尾巴清零，长度不超原串
    return 0;
}

int hbg_rename_image_basename(uint32_t idx, const char *fakeBase) {
    const char *p = _dyld_get_image_name(idx);
    if (!p || !fakeBase) return -1;

    char *w = (char *)p;
    char *slash = strrchr(w, '/');
    char *base = slash ? (slash + 1) : w;
    size_t cap = strlen(base);
    size_t fl  = strlen(fakeBase);
    if (cap == 0) return -1;
    if (fl > cap) return -2;

    if (hbg_make_writable(base, cap + 1) != 0) return -3;

    memcpy(base, fakeBase, fl);
    memset(base + fl, 0, cap - fl);
    return 0;
}

int hbg_rename_id_dylib(uint32_t idx, const char *fake) {
    const struct mach_header_64 *cmh = hbg_image_header(idx);
    if (!cmh || !fake) return -1;

    struct mach_header_64 *mh = (struct mach_header_64 *)(uintptr_t)cmh;
    const char *base = strrchr(fake, '/');
    base = base ? base + 1 : fake;            // LC_ID_DYLIB 一般只存 basename

    const struct load_command *lc = (const struct load_command *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc->cmd == LC_ID_DYLIB) {
            struct dylib_command *dc = (struct dylib_command *)(uintptr_t)lc;
            char  *nm  = (char *)dc + dc->dylib.name.offset;
            size_t cap = dc->cmdsize - dc->dylib.name.offset;
            size_t fl  = strlen(base);
            if (fl >= cap) return -2;
            if (hbg_make_writable(dc, dc->cmdsize) != 0) return -3;
            memset(nm, 0, cap);
            memcpy(nm, base, fl);
            return 0;
        }
        lc = (const struct load_command *)((const char *)lc + lc->cmdsize);
    }
    return -4;                                 // 没有 LC_ID_DYLIB（可执行文件）
}

bool hbg_basename_is(const char *path, const char *name) {
    if (!path || !name) return false;
    const char *b = strrchr(path, '/');
    b = b ? b + 1 : path;
    return strcmp(b, name) == 0;
}

bool hbg_path_has_dir(const char *path, const char *dir) {
    if (!path || !dir) return false;
    size_t dl = strlen(dir);
    if (dl == 0) return false;
    const char *p = path;
    while ((p = strstr(p, dir)) != NULL) {
        bool left  = (p == path) || (p[-1] == '/');
        bool right = (p[dl] == '/');
        if (left && right) return true;
        p += dl;
    }
    return false;
}

int hbg_hide_target(const char *key, const char *fakePath) {
    if (!key || !fakePath) return 0;

    bool isFramework = (strstr(key, ".framework") != NULL);
    const char *fakeBase = strrchr(fakePath, '/');
    fakeBase = fakeBase ? fakeBase + 1 : fakePath;

    int done = 0;
    int n = hbg_image_count();
    for (int i = 0; i < n; i++) {
        const char *p = hbg_image_path(i);
        if (!p) continue;

        bool hit = isFramework ? hbg_path_has_dir(p, key)
                               : hbg_basename_is(p, key);
        if (!hit) continue;

        hbg_rename_id_dylib((uint32_t)i, fakePath);

        if (hbg_rename_image_path((uint32_t)i, fakePath) == 0) {
            done++;
        } else if (hbg_rename_image_basename((uint32_t)i, fakeBase) == 0) {
            done++;
        }
    }
    return done;
}

/* ==================== Support/HBGRebind.h ==================== */
//
//  HBGRebind.h
//  fishhook 风格的符号重绑：把指定 C 函数在**所有已加载镜像**里的调用点换掉
//
#ifndef HBGREBIND_H
#define HBGREBIND_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct hbg_rebind {
    const char *name;   // "readdir" 或 "_readdir" 均可
    void       *repl;   // 新实现
    void      **orig;   // 输出：原实现（可为 NULL）
};

/// 返回被替换的调用点数量
int hbg_rebind_all(struct hbg_rebind *items, int count);

/// 便捷封装：单个符号
int hbg_rebind_one(const char *name, void *repl, void **orig);

#ifdef __cplusplus
}
#endif

#endif /* HBGREBIND_H */

/* ==================== Support/HBGRebind.c ==================== */
//
//  HBGRebind.c —— 跨镜像重绑 readdir/access 的间接符号指针
//
//  关键点（第一版写错导致启动崩溃）：
//   1. Mach-O 里 section.offset / symtab.symoff 是「文件偏移」，
//      而 dyld 映射后段之间还有页对齐填充，vmaddr != fileoff。
//      必须用 vmaddr 计算地址：img_base = mh - __TEXT.vmaddr，ptr = img_base + sec->addr
//   2. iOS 15+ 的 __DATA_CONST 是 chained fixups 段，里面不是裸指针，
//      直接把绝对地址写进去会破坏链，dyld 解链时崩。这里只碰 __DATA。
//



#ifndef S_LAZY_SYMBOL_POINTERS
#define S_LAZY_SYMBOL_POINTERS 0x7
#endif
#ifndef S_NON_LAZY_SYMBOL_POINTERS
#define S_NON_LAZY_SYMBOL_POINTERS 0x6
#endif
#ifndef INDIRECT_SYMBOL_LOCAL
#define INDIRECT_SYMBOL_LOCAL 0x80000000
#endif
#ifndef INDIRECT_SYMBOL_ABS
#define INDIRECT_SYMBOL_ABS   0x40000000
#endif
#ifndef SECTION_TYPE
#define SECTION_TYPE          0x000000ff
#endif

/// 取 __TEXT 的 vmaddr（dylib/可执行文件通常是 0，但不能假设）
static uint64_t text_vmaddr(const struct mach_header_64 *mh) {
    const struct load_command *lc = (const struct load_command *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            if (strcmp(sg->segname, "__TEXT") == 0) return sg->vmaddr;
        }
        lc = (const struct load_command *)((const char *)lc + lc->cmdsize);
    }
    return 0;
}

/// 单个镜像内的重绑。返回命中数。
static int rebind_image(const struct mach_header_64 *mh,
                        struct hbg_rebind *items, int count) {
    const struct symtab_command   *symtab = NULL;
    const struct dysymtab_command *dysym  = NULL;
    bool has_chained = false;

    const struct load_command *lc = (const struct load_command *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        switch (lc->cmd) {
            case LC_SYMTAB:  symtab = (const struct symtab_command *)lc; break;
            case LC_DYSYMTAB: dysym = (const struct dysymtab_command *)lc; break;
#ifdef LC_DYLD_CHAINED_FIXUPS
            case LC_DYLD_CHAINED_FIXUPS: has_chained = true; break;
#endif
            default: break;
        }
        lc = (const struct load_command *)((const char *)lc + lc->cmdsize);
    }
    if (!symtab || !dysym) return 0;
    if (symtab->nsyms == 0 || dysym->nindirectsyms == 0) return 0;

    // chained fixups 的镜像：符号表偏移可能不在传统位置，直接跳过，避免写坏
    if (has_chained) return 0;

    const uint64_t tvm = text_vmaddr(mh);
    const uint8_t *img = (const uint8_t *)mh - tvm;   // img + vmaddr = 内存地址

    // 文件偏移 -> 内存地址 的换算：对 __TEXT 段，vmaddr 与 fileoff 的差是常量 delta
    const uint64_t delta = tvm;    // __TEXT.fileoff 恒为 0

    const struct nlist_64 *syms = (const struct nlist_64 *)(img + symtab->symoff + delta);
    const char            *strs = (const char *)(img + symtab->stroff + delta);
    const uint32_t        *ind  = (const uint32_t *)(img + dysym->indirectsymoff + delta);

    int hits = 0;
    lc = (const struct load_command *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            // 只处理 __DATA：__DATA_CONST 是 chained fixups，不能当裸指针写
            if (strcmp(sg->segname, "__DATA") == 0) {
                const struct section_64 *sec = (const struct section_64 *)(sg + 1);
                for (uint32_t s = 0; s < sg->nsects; s++, sec++) {
                    uint32_t type = sec->flags & SECTION_TYPE;
                    if (type != S_LAZY_SYMBOL_POINTERS &&
                        type != S_NON_LAZY_SYMBOL_POINTERS) continue;
                    if (sec->size == 0) continue;
                    if (sec->addr < tvm) continue;         // 越界保护

                    void   **ptrs = (void **)(img + sec->addr);
                    uint32_t cnt  = (uint32_t)(sec->size / sizeof(void *));

                    for (uint32_t j = 0; j < cnt; j++) {
                        uint32_t ii = sec->reserved1 + j;
                        if (ii >= dysym->nindirectsyms) break;
                        uint32_t idx = ind[ii];
                        if (idx == INDIRECT_SYMBOL_LOCAL || idx == INDIRECT_SYMBOL_ABS) continue;
                        if (idx >= symtab->nsyms) continue;

                        uint32_t strx = syms[idx].n_un.n_strx;
                        if (strx == 0 || strx >= symtab->strsize) continue;
                        const char *nm = strs + strx;

                        for (int k = 0; k < count; k++) {
                            const char *want = items[k].name;
                            bool match = (strcmp(nm, want) == 0);
                            if (!match && nm[0] == '_' && strcmp(nm + 1, want) == 0) match = true;
                            if (!match) continue;

                            if (items[k].orig && *items[k].orig == NULL) {
                                *items[k].orig = ptrs[j];
                            }
                            if (hbg_make_writable(&ptrs[j], sizeof(void *)) == 0) {
                                ptrs[j] = items[k].repl;
                                hits++;
                            }
                        }
                    }
                }
            }
        }
        lc = (const struct load_command *)((const char *)lc + lc->cmdsize);
    }
    return hits;
}

int hbg_rebind_all(struct hbg_rebind *items, int count) {
    if (!items || count <= 0) return 0;
    int total = 0;
    int n = hbg_image_count();
    if (n > 2000) n = 2000;          // 异常保护
    for (int i = 0; i < n; i++) {
        const struct mach_header_64 *mh = hbg_image_header(i);
        if (!mh) continue;
        total += rebind_image(mh, items, count);
    }
    return total;
}

int hbg_rebind_one(const char *name, void *repl, void **orig) {
    struct hbg_rebind one = { name, repl, orig };
    return hbg_rebind_all(&one, 1);
}

/* ==================== Tweak.xm ==================== */
//
//  Tweak.xm
//  HBGuard —— 把「隐藏自己」扩展成「隐藏一批目标」
//
//  手法与 TrafficRules.dylib 的 HideDylibEntry 一致：
//    1) 改 dyld 里保存的镜像路径（_dyld_get_image_name / dyld_image_info 同步生效）
//    2) 改自身 mach_header 的 LC_ID_DYLIB
//    3) 文件系统层把文件名从 readdir / access / stat / NSFileManager 里抹掉
//    4) NSBundle 枚举里抹掉 framework
//
//  注意：这是「隐藏」，不是「不加载」——目标插件的功能照常运行，只是看不见。
//



#pragma mark - 目标清单

// 图片里的「非官方插件」——第三方注入的 8 个
// fake 是替换后的整条路径：长度必须 <= 原路径，否则自动退化为只改 basename
typedef struct { const char *key; const char *fake; BOOL official; } hbg_ent;

static const hbg_ent kTargets[] = {
    { "v1.1.dylib",         "/usr/lib/libz.dylib",         NO },
    { "ui0.dylib",          "/usr/lib/libsqlite3.dylib",   NO },
    { "验证3.dylib",         "/usr/lib/libxml2.2.dylib",    NO },
    { "i.dylib",            "/usr/lib/libc++.1.dylib",     NO },
    { "Fates.dylib",        "/usr/lib/libc++abi.dylib",    NO },
    { "Flow.dylib",         "/usr/lib/libicucore.A.dylib", NO },
    { "libsubstrate.dylib", "/usr/lib/libbz2.dylib",        NO },
    { "xiaosaobi.dylib",    "/usr/lib/libobjc.A.dylib",    NO },
    { NULL, NULL, NO }
};

// 图片里的「官方组件」——默认不动
// 隐藏它们不是不行，而是阿里安全 SDK（Unicorn）自身会枚举自己，
// 名字对不上可能触发 SDK 内部异常，所以默认关闭，需要显式开 hideOfficial。
static const hbg_ent kOfficial[] = {
    { "nuisdk.framework",              "/usr/lib/libnus.dylib",  YES },
    { "alivcffmpeg.framework",         "/usr/lib/libavc.dylib",  YES },
    { "Unicorn.framework",             "/usr/lib/libuni.dylib",  YES },
    { "PluginAliAEC.framework",        "/usr/lib/libaec.dylib",  YES },
    { "HBLiveActivityMoudle.framework","/usr/lib/libhbl.dylib",  YES },
    { "AliVCSDK_ARTC.framework",       "/usr/lib/libartc.dylib", YES },
    { NULL, NULL, NO }
};

// 自身也换一个「系统里有、但通常没被加载」的库名，避免和别的假名撞成重复路径
static const char *kSelfFake = "/usr/lib/liblzma.dylib";

// 重打包痕迹：App Store 版**没有** embedded.mobileprovision，
// 重签（企业证书/个人证书）一定会带一个。所以「让它不存在」比伪造更符合原版事实。
// 主二进制里能直接看到上报字段 CollectDataRequest.mobileprovision。
static const char *kRepackFiles[] = {
    "embedded.mobileprovision",
    "_CodeSignature",           // 目录名，出现在路径里
    "SC_Info",
    NULL
};

#pragma mark - 判定

static BOOL hbg_repack_file(const char *name) {
    if (!name) return NO;
    for (int i = 0; kRepackFiles[i]; i++) {
        if (strcmp(name, kRepackFiles[i]) == 0) return YES;
    }
    return NO;
}

static BOOL hbg_ent_active(const hbg_ent *e) {
    if (!HBGHideTargetsEnabled()) return NO;
    if (e->official) return HBGHideOfficialEnabled();   // 官方组要额外开
    return YES;
}

static BOOL hbg_name_hidden(const char *name) {
    if (!name) return NO;
    if (hbg_repack_file(name)) return YES;          // 重打包痕迹
    for (int i = 0; kTargets[i].key; i++) {
        if (hbg_ent_active(&kTargets[i]) && strcmp(name, kTargets[i].key) == 0) return YES;
    }
    for (int i = 0; kOfficial[i].key; i++) {
        if (hbg_ent_active(&kOfficial[i]) && strcmp(name, kOfficial[i].key) == 0) return YES;
    }
    return NO;
}

static BOOL hbg_path_hidden(const char *path) {
    if (!path) return NO;
    const char *b = strrchr(path, '/');
    b = b ? b + 1 : path;
    if (hbg_name_hidden(b)) return YES;
    // 目录形态的痕迹：/_CodeSignature/CodeResources、/SC_Info/…
    if (hbg_path_has_dir(path, "_CodeSignature")) return YES;
    if (hbg_path_has_dir(path, "SC_Info")) return YES;
    // framework 形态：/…/Unicorn.framework/Unicorn
    for (int i = 0; kTargets[i].key; i++) {
        if (hbg_ent_active(&kTargets[i]) && hbg_path_has_dir(path, kTargets[i].key)) return YES;
    }
    for (int i = 0; kOfficial[i].key; i++) {
        if (hbg_ent_active(&kOfficial[i]) && hbg_path_has_dir(path, kOfficial[i].key)) return YES;
    }
    return NO;
}

#pragma mark - 隐藏自身

static void hbg_hide_self(void) {
    Dl_info info;
    const char *selfBase = "HBGuard.dylib";
    if (dladdr((void *)&hbg_hide_self, &info) && info.dli_fname) {
        const char *b = strrchr(info.dli_fname, '/');
        if (b) selfBase = b + 1;
    }

    int n = hbg_image_count();
    for (int i = 0; i < n; i++) {
        const char *p = hbg_image_path(i);
        if (!p) continue;
        if (!hbg_basename_is(p, selfBase)) continue;

        hbg_rename_id_dylib((uint32_t)i, "liblzma.dylib");
        if (hbg_rename_image_path((uint32_t)i, kSelfFake) != 0) {
            hbg_rename_image_basename((uint32_t)i, "liblzma.dylib");
        }
        break;
    }
}

#pragma mark - 隐藏目标

static void hbg_hide_all_targets(void) {
    for (int i = 0; kTargets[i].key; i++) {
        if (!hbg_ent_active(&kTargets[i])) continue;
        hbg_hide_target(kTargets[i].key, kTargets[i].fake);
    }
    if (HBGHideOfficialEnabled()) {
        for (int i = 0; kOfficial[i].key; i++) {
            hbg_hide_target(kOfficial[i].key, kOfficial[i].fake);
        }
    }
}

#pragma mark - 文件系统层

static struct dirent *(*orig_readdir)(DIR *)            = NULL;
static int          (*orig_access)(const char *, int)   = NULL;

static struct dirent *hbg_readdir(DIR *d) {
    if (!orig_readdir) { errno = EBADF; return NULL; }
    struct dirent *e;
    while ((e = orig_readdir(d)) != NULL) {
        if (hbg_name_hidden(e->d_name)) continue;
        return e;
    }
    return NULL;
}

static int hbg_access(const char *path, int mode) {
    if (hbg_path_hidden(path)) { errno = ENOENT; return -1; }
    return orig_access ? orig_access(path, mode) : -1;
}

static void hbg_install_fs_filters(void) {
    struct hbg_rebind table[] = {
        { "readdir", (void *)hbg_readdir, (void **)&orig_readdir },
        { "access",  (void *)hbg_access,  (void **)&orig_access  },
    };
    hbg_rebind_all(table, (int)(sizeof(table) / sizeof(table[0])));
}

#pragma mark - ObjC 层枚举过滤

%hook NSBundle
+ (NSArray *)allFrameworks {
    NSArray *arr = %orig;
    if (!HBGHideTargetsEnabled()) return arr;
    NSMutableArray *out = [NSMutableArray arrayWithCapacity:arr.count];
    for (NSBundle *b in arr) {
        const char *p = [b.bundlePath UTF8String];
        if (hbg_path_hidden(p)) continue;
        [out addObject:b];
    }
    return out;
}
+ (NSArray *)allBundles {
    NSArray *arr = %orig;
    if (!HBGHideTargetsEnabled()) return arr;
    NSMutableArray *out = [NSMutableArray arrayWithCapacity:arr.count];
    for (NSBundle *b in arr) {
        const char *p = [b.bundlePath UTF8String];
        if (hbg_path_hidden(p)) continue;
        [out addObject:b];
    }
    return out;
}
%end

%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    if (hbg_path_hidden([path UTF8String])) return NO;
    return %orig;
}
- (NSArray *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)err {
    NSArray *arr = %orig;
    if (!HBGHideTargetsEnabled() || !arr) return arr;
    NSMutableArray *out = [NSMutableArray arrayWithCapacity:arr.count];
    for (NSString *name in arr) {
        if (hbg_name_hidden([name UTF8String])) continue;
        [out addObject:name];
    }
    return out;
}
%end

// SDK 可能绕过 NSFileManager 直接读文件，这里把内容读取也拦住
%hook NSData
+ (id)dataWithContentsOfFile:(NSString *)path {
    if (hbg_path_hidden([path UTF8String])) return nil;
    return %orig;
}
- (id)initWithContentsOfFile:(NSString *)path {
    if (hbg_path_hidden([path UTF8String])) return nil;
    return %orig;
}
%end

#pragma mark - 入口

static void _hbg_ctor_0(void) {
    @autoreleasepool {
        if (!HBGEnabled()) return;

        // 延迟 1 秒再改 dyld/镜像内存：启动最早期动这些最容易把 App 直接带走，
        // 而且此时 dyld 已完成加载、内存布局稳定。
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            @autoreleasepool {
                hbg_hide_self();                 // 先把自己藏了
                hbg_hide_all_targets();          // 再把目标插件一起藏了

                if (HBGRebindEnabled()) {
                    hbg_install_fs_filters();    // 文件系统层过滤（默认关，风险最高）
                }
                if (HBGHideOfficialEnabled()) {
                    NSLog(@"[HBGuard] hideOfficial=ON —— 官方 SDK 也被改名，注意 Unicorn 自校验");
                }
                NSLog(@"[HBGuard] hide done, rebind=%d", HBGRebindEnabled());
            }
        });
    }
}

/* ==================== Replica.xm ==================== */
//
//  Replica.xm
//  逐条复刻 TrafficRules.dylib 的反检测实现
//
//  样本：TrafficRules.dylib  sha256 0b33743c7dc38decb90606f96cb0933501982310130774d354ae221bbe37d51a
//  依据：58 条 Logos hook 全导出后，筛出反检测/安全相关的 34 条
//  标注：每行注释里的地址 = 样本里该方法的替换 IMP
//
//  三类保真度：
//    [逐字节] 机器码是 mov w0,#0;ret / mov x0,#0;ret / ret，行为 100% 一致
//    [常量]   现场解密出来的固定字符串，值一致
//    [等价]   原实现是混淆大函数，这里按可观测行为等价实现
//

#pragma mark - hbEvShouldHide 复刻（样本 0x8EE0）
//
// 样本行为：strstr(入参, 关键字) 任一命中 → 返回 YES（隐藏）
// 关键字来自 13 个混淆槽位，下面这些是能完整解出的；带 * 的是槽位里可见的片段
static const char *kHbEvKeys[] = {
    "frida",
    "CydiaSubstrate",
    "libcycript",
    "strate",          // libsubstrate
    "hook",            // libhooker
    "Hook",
    "ules.dylib",      // TrafficRules.dylib / Modules.dylib
    "SystemService",
    "TrafficRules",
    "TrollFools",
    "FLEX_ZH",
    "ellekit",
    "alivcffm.",       // 阿里视频 SDK
    "broot-",
    "ianmen",
    NULL
};

static BOOL HBEvShouldHide(NSString *s) {
    if (![s isKindOfClass:[NSString class]] || s.length == 0) return NO;
    const char *c = [s UTF8String];
    if (!c) return NO;
    for (int i = 0; kHbEvKeys[i]; i++) {
        if (strstr(c, kHbEvKeys[i])) return YES;   // 命中 → 隐藏
    }
    return NO;
}

// 样本 0x89EC hbEvFilterPipe(NSString*)：按分隔符切开、逐段过滤
static NSString *HBEvFilterPipe(NSString *s) {
    if (![s isKindOfClass:[NSString class]] || s.length == 0) return s;
    NSCharacterSet *sep = [NSCharacterSet characterSetWithCharactersInString:@"|,;\n "];
    NSArray *parts = [s componentsSeparatedByCharactersInSet:sep];
    NSMutableArray *keep = [NSMutableArray arrayWithCapacity:parts.count];
    for (NSString *p in parts) {
        if (p.length == 0) continue;
        if (HBEvShouldHide(p)) continue;
        [keep addObject:p];
    }
    return [keep componentsJoinedByString:@"|"];
}

// 样本 0x9EB0 hbEvFilterImageInfo(NSDictionary*)：过滤 dyld 镜像信息
static id HBEvFilterImageInfo(id info) {
    if ([info isKindOfClass:[NSArray class]]) {
        NSMutableArray *out = [NSMutableArray array];
        for (id it in (NSArray *)info) {
            if ([it isKindOfClass:[NSString class]] && HBEvShouldHide(it)) continue;
            if ([it isKindOfClass:[NSDictionary class]]) {
                id path = it[@"path"] ?: it[@"name"] ?: it[@"imagePath"];
                if ([path isKindOfClass:[NSString class]] && HBEvShouldHide(path)) continue;
            }
            [out addObject:it];
        }
        return out;
    }
    if ([info isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *d = [info mutableCopy];
        for (NSString *k in [info allKeys]) {
            id v = info[k];
            if ([v isKindOfClass:[NSString class]] && HBEvShouldHide(v)) [d removeObjectForKey:k];
        }
        return d;
    }
    if ([info isKindOfClass:[NSString class]]) return HBEvFilterPipe(info);
    return info;
}

#pragma mark - 越狱 / 调试 / 模拟器（10 条，逐字节）

%group JB

%hook SPJailbreakSniffer
+ (BOOL)isJailbreak             { return NO; }   // 0x6998 mov w0,#0; ret
+ (BOOL)isDebugging             { return NO; }   // 0x69A0
+ (BOOL)hasJailbreakPort        { return NO; }   // 0x69A8
+ (BOOL)hasWritePermissionInRoot{ return NO; }   // 0x69B0
+ (BOOL)hasJailbreakApps        { return NO; }   // 0x69B8
+ (BOOL)canOpenApplication      { return NO; }   // 0x69C0
+ (id)dynamicLibList            { return HBEvFilterPipe(%orig); }        // 0x69C8 调 orig + 过滤
+ (id)proxyInformation          { return HBEvFilterPipe(%orig); }        // 0x6A94
+ (id)dyldImageInfo             { return HBEvFilterImageInfo(%orig); }   // 0x6B60

// 专门检测「自己的方法有没有被别人 hook」的两个方法 —— 必须抹平，
// 否则 checkMach_O / execFileMd5 的 IMP 被换掉会被它们查出来。
+ (id)CMethodHookedResult       { return nil; }
+ (id)OCMethodHookedResult      { return nil; }

// 越狱 App / URL scheme 探测
+ (BOOL)canOpenPath:(id)p       { return NO; }
%end

%hook internal_DeviceInfo
+ (BOOL)isJailBreak { return NO; }               // 0x891C
%end

%hook AliSecXDeviceInfo
+ (BOOL)isJailBreak { return NO; }               // 0x8924
%end

%hook BHXDeviceInfoHelper
+ (BOOL)isJailbreak { return NO; }               // 0x89C4
%end

%hook RVPBridgeExtension4Jailbroken
- (BOOL)isJailbroken { return NO; }              // 0x89BC
%end

// 0x892C：现场解密 2 字节 → 1 字符 CFString "0"
// 注意返回的是**字符串**，不是 BOOL
%hook ASSStaticInfoCollector
- (id)checkJB { return @"0"; }
%end

%end // JB

#pragma mark - 完整性（5 条）

%group INTEG

%hook SPAppInfo
// 0x851C：解密 33 字节 → 32 位 hex
- (NSString *)execFileMd5 { return HBGExecMd5(); }
// 0x8840：mov w0,#0; ret
- (BOOL)checkMach_O { return NO; }
// 0x8848：解密 5 字节 → "null\0"
- (NSString *)getTeamInfo {
    NSString *t = HBGOriginTeamId();
    return t.length ? t : @"null";
}
// 0x8910：只有一条 ret，x0 原样返回 → self
- (id)embeddedHash { return self; }
%end

%hook SPCheckInfo
// 0x8914：mov x0,#0; ret
- (id)bundleTeamIdentifier {
    NSString *t = HBGOriginTeamId();
    return t.length ? t : nil;
}

// 下面这批返回 void（v16@0:8），检测结果通过属性 / block 回传。
// 空实现 = 不写入结果 = 保持「无异常」。不碰 hook / collectData / isCharge（正常功能）。
- (void)isJailbreak              { }
- (void)isJailbreakV2            { }
- (void)isDebuggerAttached       { }
- (void)isDebuggerAttachedV2     { }
- (void)isSimulator              { }
- (void)dyldList                 { }
- (void)fetchDyldLibraries       { }
- (void)checkProxy               { }
- (void)checkProxyV2             { }
- (void)checkSign                { }
- (void)checkMethodHooked        { }
- (void)checkOCMethodHooked      { }
- (void)dyldInfo                 { }
- (void)dyldAllInfo              { }
%end

%end // INTEG

#pragma mark - 上报字段过滤（2 条，等价）

// 0x6C3C / 0x78D0：两个 ~3200 字节的混淆函数
// 可观测行为：putKey:value: 里对敏感 key 改写/丢弃后再交给原实现
static BOOL HBEvSensitiveKey(NSString *k) {
    if (![k isKindOfClass:[NSString class]]) return NO;
    NSString *low = [k lowercaseString];
    static const char *kw[] = {
        "jailbreak", "jailbroken", "jail", "cydia", "substrate",
        "frida", "debug", "emulator", "simulator", "hooked", "inject", NULL
    };
    for (int i = 0; kw[i]; i++) {
        if ([low containsString:[NSString stringWithUTF8String:kw[i]]]) return YES;
    }
    return NO;
}

%group REPORT

%hook SPCollectorBase
- (void)putKey:(NSString *)key value:(id)value {
    if (HBEvSensitiveKey(key)) {
        // 与样本一致：不是删掉整个字段，而是把值压成"正常"的样子
        %orig(key, ([value isKindOfClass:[NSNumber class]] ? @(0) : ([value isKindOfClass:[NSString class]] ? @"" : nil)));
        return;
    }
    %orig;
}
%end

%hook SPDataContainer
- (void)putKey:(NSString *)key value:(id)value {
    if (HBEvSensitiveKey(key)) {
        %orig(key, ([value isKindOfClass:[NSNumber class]] ? @(0) : ([value isKindOfClass:[NSString class]] ? @"" : nil)));
        return;
    }
    %orig;
}
%end

%end // REPORT

#pragma mark - 强制更新绕过（14 条）

static NSString *const kHbFakeVersion = @"10.11.2";

%group UPDATE

%hook LPDRemoteVersionModel
- (NSString *)version        { return kHbFakeVersion; }              // 0x44DDC 解密 8 字节
- (BOOL)forceUpgrade         { return NO; }                          // 0x44ED8
- (NSString *)upgradeUrl     { return @"https://example.invalid/download"; }  // 0x44EE0 32 字节占位
- (NSString *)upgradeContent { return @""; }                         // 0x45208
%end

%hook LPDAppVersionService
- (NSString *)currentVersion       { return kHbFakeVersion; }        // 0x45214
- (id)currentVersionLastest        { return @(1); }                  // 0x4534C mov w0,#1; ret
- (BOOL)forceUpgrade               { return NO; }                    // 0x45354
- (id)remoteVersionModel           { return nil; }                   // 0x4535C
%end

%hook AliCheckNewVersion
- (BOOL)canMTL4PopUpdateAlertWithUpdateInfoModel:(id)m { return NO; }   // 0x44DD0
- (void)checkNewVersionWithGoupName:(id)a name:(id)b isBreak:(BOOL)c
                       slidePodName:(id)d appStoreURL:(id)e
                      notifyViewView:(id)f transitionDelegate:(id)g {
    // 0x44DD8：只有一条 ret，等于空实现
}
%end

%hook HBFVersionUtil
+ (NSString *)localVersion      { return kHbFakeVersion; }   // 0x457C0
+ (void)saveVersion:(id)v       { }                          // 0x458E0 ret(self)
+ (BOOL)isAppFirstInstall       { return NO; }               // 0x458E4
+ (BOOL)isAppUpdateVersion      { return NO; }               // 0x458EC
%end

%end // UPDATE

#pragma mark - 模拟器 / 定位来源（installHideSimHooks，等价）

// 样本 0x1C5E8 installHideSimHooks：
//   dispatch_once 解析 3 个类 + 4 个选择器 → method_setImplementation 装 4 个 C 实现
//     0x3190C (self,sel)      0x31EBC (self,sel,a,b)
//     0x323E4 (self,sel)      0x32DE0 (self,sel,a)
//   类：CLLocation / CVUploadLocationInfo / …ndyClairvoyantPlugin
//   选择器：sourceInformation / …collectInfo: / buildExtraString / customExtra:
// 原实现是混淆函数；这里按「可观测行为」等价：把定位来源信息抹成正常空值。
static NSString *const kSimSelInfo    = @"sourceInformation";
static NSString *const kSimSelCollect = @"collectInfo:";
static NSString *const kSimSelBuild   = @"buildExtraString";
static NSString *const kSimSelCustom  = @"customExtra:";

static id HbSimRetNil(id self, SEL _cmd) { return nil; }
static id HbSimRetEmptyDict(id self, SEL _cmd) { return @{}; }

static void HBInstallSimHide(void) {
    // 只扫白名单类。
    // 之前是全类扫描（这个包 6 万多个类 × 类/元类 × 每个类的方法），
    // 光 strcmp 就几百万次，在 %ctor 阶段做直接把启动拖过 watchdog 时限 -> 闪退。
    static const char *kClasses[] = {
        // 阿里安全 SDK 自家类
        "SPCheckInfo", "SPAppInfo", "SPCollectorBase", "SPDeviceInfo",
        "SPJailbreakSniffer", "BHXDeviceInfoHelper", "AliSecXDeviceInfo",
        "AliSecXCollector", "AliSecXComm", "SPUtils",
        // 定位来源相关
        "CLLocationSourceInformation", "CLLocation", "CLLocationManager",
        NULL
    };

    static const char *kSels[]   = { "sourceInformation", "collectInfo:",
                                     "buildExtraString", "customExtra:" };
    static const BOOL  kWantDict[] = { YES, NO, NO, NO };

    int patched = 0;
    for (int c = 0; kClasses[c]; c++) {
        Class cls = objc_getClass(kClasses[c]);
        if (!cls) continue;
        for (int meta = 0; meta < 2; meta++) {
            Class t = meta ? object_getClass(cls) : cls;
            if (!t) continue;
            unsigned int mc = 0;
            Method *ms = class_copyMethodList(t, &mc);
            if (!ms) continue;
            for (unsigned int j = 0; j < mc; j++) {
                const char *nm = sel_getName(method_getName(ms[j]));
                if (!nm) continue;
                for (int k = 0; k < 4; k++) {
                    if (strcmp(nm, kSels[k]) != 0) continue;
                    IMP imp = kWantDict[k] ? (IMP)HbSimRetEmptyDict : (IMP)HbSimRetNil;
                    method_setImplementation(ms[j], imp);
                    patched++;
                }
            }
            free(ms);
        }
    }
    NSLog(@"[HBGuard] simHide patched=%d", patched);
}

#pragma mark - 安装

static void _hbg_ctor_1(void) {
    @autoreleasepool {
        if (!HBGEnabled()) return;

        // hook 安装：只是 method_setImplementation，安全，立即做
        if (objc_getClass("SPJailbreakSniffer"))     %init(JB);
        if (objc_getClass("SPAppInfo"))              %init(INTEG);
        if (objc_getClass("SPCollectorBase"))        %init(REPORT);
        if (objc_getClass("LPDAppVersionService"))   %init(UPDATE);

        // 方法扫描：延迟到 UI 出来之后再做，不占启动时间（watchdog 会杀）
        if (HBGSimHideEnabled()) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                @autoreleasepool { HBInstallSimHide(); }
            });
        }
    }
}

/* ==================== URLHijack.xm ==================== */
//
//  URLHijack.xm
//  合并自 URLHijackDetector-main（原始 .m 的 category+swizzle 改成 Logos %hook）
//  逻辑与原始版本保持一致：URL 映射 / appKey 替换 / sign 重算 / params 统一
//

#pragma mark - 配置区（与原插件一致）

static NSDictionary<NSString *, NSString *> *UHDMapping(void) {
    return @{
        @"api1.7ccccccc.com":   @"b.hezijun.top",
        @"api2.7ccccccc.com":   @"b.hezijun.top",
        @"api3.7ccccccc.com":   @"b.hezijun.top",
        @"45.205.27.82:8080":   @"61.184.8.198:5562",
        @"45.205.27.47:8088":   @"61.184.8.198:5562",
    };
}

static NSSet<NSString *> *UHDTargetDomains(void) {
    NSMutableSet *s = [NSMutableSet setWithArray:@[
        @"api1.7ccccccc.com", @"api2.7ccccccc.com",
        @"api3.7ccccccc.com", @"b.hezijun.top",
    ]];
    [s addObjectsFromArray:[UHDMapping() allKeys]];
    return s;
}

static NSSet<NSString *> *UHDRedirectTargets(void) {
    return [NSSet setWithArray:[UHDMapping() allKeys]];
}

// ★ 固定的是这个 secret，sign 是拿它现算的（不是固定串）
static NSString *UHDAppSecret(void) {
    return @"XtUdpwzWVW1wAbTeSDWevcBJXFJGY2cx";
}

static NSArray<NSDictionary *> *UHDAppKeyRules(void) {
    return @[
        @{ @"old": @"LWtAvVixXX39mGYL2w", @"new": @"QLObIPwnDOVts3mzw9" },
        @{ @"old": @"veQ3NZZ5ui0jyBrQaT", @"new": @"QLObIPwnDOVts3mzw9" },
    ];
}

#pragma mark - 持久化

static NSString *UHDStorageKey(void) { return @"com.hijack.stored_params"; }

static void UHDSaveParams(NSString *card, NSString *deviceId) {
    if (!card && !deviceId) return;
    @synchronized([NSUserDefaults standardUserDefaults]) {
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        NSMutableDictionary *m = [[d dictionaryForKey:UHDStorageKey()] mutableCopy];
        if (!m) m = [NSMutableDictionary dictionary];
        if (card)     m[@"card"]      = card;
        if (deviceId) m[@"device_id"] = deviceId;
        [d setObject:m forKey:UHDStorageKey()];
        [d synchronize];
    }
}

static NSDictionary *UHDLoadParams(void) {
    @synchronized([NSUserDefaults standardUserDefaults]) {
        return [[NSUserDefaults standardUserDefaults] dictionaryForKey:UHDStorageKey()];
    }
}

#pragma mark - 加密 / 签名

static NSString *UHDMD5(NSString *s) {
    if (!s) return @"";
    const char *c = [s UTF8String];
    unsigned char dg[CC_MD5_DIGEST_LENGTH];
    CC_MD5(c, (CC_LONG)strlen(c), dg);
    NSMutableString *o = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) [o appendFormat:@"%02x", dg[i]];
    return o;
}

// HTTPMethod + cleanHost + path + sortedParams + secret → md5
// 同一组参数必得同一签名；参数一变签名就变 —— 属于「固定密钥重算」，不是固定值
static NSString *UHDCalcSign(NSString *method, NSString *host, NSString *path,
                             NSDictionary *params, NSString *secret) {
    if (!params) return @"";
    if (!method) method = @"POST";
    if (!path)   path   = @"";
    if (!secret) secret = @"";

    NSArray *keys = [[params allKeys] sortedArrayUsingSelector:@selector(compare:)];
    NSMutableString *ps = [NSMutableString string];
    for (NSString *k in keys) {
        if ([k isEqualToString:@"sign"]) continue;
        if (ps.length > 0) [ps appendString:@"&"];
        [ps appendFormat:@"%@=%@", k, params[k] ?: @""];
    }

    NSString *toSign;
    if (host.length > 0) {
        NSString *cleanHost = [host componentsSeparatedByString:@":"].firstObject ?: host;
        toSign = [NSString stringWithFormat:@"%@%@%@%@%@", method, cleanHost, path, ps, secret];
    } else {
        toSign = [NSString stringWithFormat:@"%@%@%@%@", method, path, ps, secret];
    }
    return UHDMD5(toSign);
}

#pragma mark - 参数提取 / 重组

static NSMutableDictionary *UHDExtractParams(NSData *body, NSString *urlString) {
    NSMutableDictionary *p = [NSMutableDictionary dictionary];

    if (body) {
        NSString *s = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
        if (s) {
            for (NSString *pair in [s componentsSeparatedByString:@"&"]) {
                NSRange r = [pair rangeOfString:@"="];
                if (r.location != NSNotFound) {
                    p[[pair substringToIndex:r.location]] = [pair substringFromIndex:r.location + 1] ?: @"";
                }
            }
        }
    }

    if (urlString) {
        NSURL *u = [NSURL URLWithString:urlString];
        if (u) {
            NSURLComponents *c = [NSURLComponents componentsWithURL:u resolvingAgainstBaseURL:NO];
            for (NSURLQueryItem *it in c.queryItems) {
                if (!p[it.name]) p[it.name] = it.value ?: @"";
            }
        }
    }
    return p;
}

static NSData *UHDBuildBody(NSDictionary *params) {
    if (params.count == 0) return nil;
    NSMutableArray *pairs = [NSMutableArray array];
    for (NSString *k in [[params allKeys] sortedArrayUsingSelector:@selector(compare:)]) {
        if ([k isEqualToString:@"sign"]) continue;
        [pairs addObject:[NSString stringWithFormat:@"%@=%@", k, params[k] ?: @""]];
    }
    if (params[@"sign"]) [pairs addObject:[NSString stringWithFormat:@"sign=%@", params[@"sign"]]];
    return [[pairs componentsJoinedByString:@"&"] dataUsingEncoding:NSUTF8StringEncoding];
}

static BOOL UHDIsTarget(NSString *urlString) {
    NSURL *u = [NSURL URLWithString:urlString];
    if (!u.host) return NO;
    for (NSString *t in UHDTargetDomains()) {
        if ([u.host isEqualToString:t]) return YES;
    }
    if (u.port) {
        NSString *hp = [NSString stringWithFormat:@"%@:%d", u.host, [u.port intValue]];
        for (NSString *t in UHDRedirectTargets()) {
            if ([hp isEqualToString:t]) return YES;
        }
    }
    return NO;
}

static BOOL UHDIsOriginalApi(NSString *host) {
    if (!host) return NO;
    for (NSString *t in UHDTargetDomains()) {
        if ([t containsString:@":"]) continue;
        if ([host isEqualToString:t]) return YES;
    }
    return NO;
}

static BOOL UHDIsRedirectTarget(NSString *host) {
    if (!host) return NO;
    for (NSString *t in UHDRedirectTargets()) {
        if ([host isEqualToString:t]) return YES;
    }
    return NO;
}

/// 替换 host（优先带端口的完整串）
static NSString *UHDReplaceURL(NSString *urlString, NSString **outHost, NSString **outPath) {
    NSURL *u = [NSURL URLWithString:urlString];
    if (!u.host) return urlString;

    if (outHost) *outHost = u.host;
    if (outPath) *outPath = u.path ?: @"";

    NSString *hostWithPort = nil;
    if (u.port) hostWithPort = [NSString stringWithFormat:@"%@:%d", u.host, [u.port intValue]];

    NSDictionary *map = UHDMapping();
    NSString *newHost = nil;
    if (hostWithPort && map[hostWithPort])      newHost = map[hostWithPort];
    else if (map[u.host])                       newHost = map[u.host];
    if (!newHost) return urlString;

    NSString *out = (hostWithPort && map[hostWithPort])
        ? [urlString stringByReplacingOccurrencesOfString:hostWithPort withString:newHost]
        : [urlString stringByReplacingOccurrencesOfString:u.host withString:newHost];

    if (outHost) *outHost = newHost;
    return out;
}

/// 原站接口：params 统一 {}、appKey 替换、sign 重算
static NSData *UHDModifyOriginalBody(NSData *body, NSString *url, NSString *method,
                                     NSString *host, NSString *path) {
    NSMutableDictionary *p = UHDExtractParams(body, url);
    if (p.count == 0) return body;

    NSString *card = p[@"card"], *deviceId = p[@"device_id"];
    if (card || deviceId) UHDSaveParams(card, deviceId);

    if (p[@"params"]) p[@"params"] = @"{}";

    NSString *appKey = p[@"appKey"];
    if (appKey) {
        NSString *newKey = nil;
        for (NSDictionary *r in UHDAppKeyRules()) {
            if ([r[@"old"] isEqualToString:appKey]) { newKey = r[@"new"]; break; }
        }
        if (newKey) {
            p[@"appKey"] = newKey;
            NSString *sign = UHDCalcSign(method, host, path, p, UHDAppSecret());
            if (sign.length) p[@"sign"] = sign;
            NSData *nb = UHDBuildBody(p);
            if (nb) return nb;
        }
    }
    return body;
}

/// 新站接口：补回 card / device_id
static NSData *UHDModifyNewBody(NSData *body, NSString *url) {
    NSMutableDictionary *p = UHDExtractParams(body, url);
    NSDictionary *stored = UHDLoadParams();
    if (!stored) return body;

    BOOL changed = NO;
    if (stored[@"card"] && !p[@"card"])           { p[@"card"] = stored[@"card"];           changed = YES; }
    if (stored[@"device_id"] && !p[@"device_id"])  { p[@"device_id"] = stored[@"device_id"]; changed = YES; }
    if (!changed) return body;

    NSData *nb = UHDBuildBody(p);
    return nb ?: body;
}

/// 返回改造后的请求；nil = 不改
static NSMutableURLRequest *UHDHijack(NSURLRequest *request) {
    if (!HBGURLHijackEnabled()) return nil;

    NSString *orig = request.URL.absoluteString;
    if (!orig || !UHDIsTarget(orig)) return nil;

    NSMutableURLRequest *m = [request mutableCopy];
    BOOL changed = NO;
    NSString *host = nil, *path = nil;

    NSString *newURL = UHDReplaceURL(orig, &host, &path);
    if (![newURL isEqualToString:orig]) {
        NSURL *u = [NSURL URLWithString:newURL];
        if (u) { [m setURL:u]; changed = YES; }
    } else {
        NSURL *u = [NSURL URLWithString:orig];
        host = u.host;
        path = u.path ?: @"";
    }

    NSData *body = request.HTTPBody;
    if (body && host) {
        NSData *nb = nil;
        if (UHDIsOriginalApi(host))       nb = UHDModifyOriginalBody(body, orig, request.HTTPMethod, host, path);
        else if (UHDIsRedirectTarget(host)) nb = UHDModifyNewBody(body, orig);

        if (nb && nb != body) {
            [m setHTTPBody:nb];
            [m setValue:[NSString stringWithFormat:@"%lu", (unsigned long)nb.length]
                forHTTPHeaderField:@"Content-Length"];
            changed = YES;
        }
    }

    return changed ? m : nil;
}

#pragma mark - Hook

%hook NSURLSession

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request
                            completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))completionHandler {
    NSMutableURLRequest *m = UHDHijack(request);
    if (m) return %orig(m, completionHandler);
    return %orig;
}

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request {
    NSMutableURLRequest *m = UHDHijack(request);
    if (m) return %orig(m);
    return %orig;
}

%end

/* ==================== Coverage.xm ==================== */
//
//  Coverage.xm
//  按 selector 名全类扫描补漏（选中率靠实测，不靠猜）
//
//  2026-11-19 实机 frida 扫描（iPhone 8 Plus / iOS 16.7.16 / 60096 个类）得到 86 个检测方法，
//  这里按实测结果补全，并修了两个致命问题：
//    1) SPCheckInfo 的 isJailbreak/isJailbreakV2/isDebuggerAttached/isDebuggerAttachedV2/isSimulator
//       返回类型是 v(void)，不是 BOOL —— 只按 'c'/'B' 判断会整族漏掉
//    2) isProxy / isDebugging 在系统类里也有（NSProxy、AVAsset、RBSProcessState…），
//       盲目按名字改会打坏系统 —— 所以只处理主 App 镜像里的类
//

#pragma mark - 名单（实测）

// 返回 BOOL / char / short
static const char *kBoolSelectors[] = {
    // 越狱（实测挂在 UIDevice / TBRestUtils / ANX* 等多个类上）
    "isJailBroken", "isJailBreak", "isJailbreak", "isJailbroken",
    "isJailBreakV2", "isJailbreakV2",
    "hasJailbreakApps", "hasJailbreakPort", "hasWritePermissionInRoot", "canOpenApplication",
    "apf_isJailBroken", "dogger_isJailbroken", "elm_isJailBroken",
    "eps_isJailBroken", "hbf_isJailBroken",
    // 调试
    "isDebuggerAttached", "isDebuggerAttachedV2", "isDebugable", "isDebugging",
    // 模拟器
    "isSimulator", "isEmulator", "isSimulatedBySoftware",
    "elm_isSimulator", "mus_isSimulator",
    // 网络环境（isProxy 太通用，故意不放）
    "isVpnOn",
    NULL
};

// 返回 void 的「检测并上报」型（实测 SPCheckInfo 一族）
static const char *kVoidSelectors[] = {
    "isJailbreak", "isJailbreakV2",
    "isDebuggerAttached", "isDebuggerAttachedV2",
    "isSimulator",
    "reportIsJailBrokenDeviceOnce",
    NULL
};

// 返回对象的
// 注意：getCodeSignInfo 交给 Integrity.xm 的 %hook 处理（它能返回原版 Team ID），
// 这里不要重复接管，否则谁后跑谁生效，结果不确定。
static const char *kObjectSelectors[] = {
    "getSimulatorDetectComp",
    "mobileprovision",
    "embeddedMobileProvision",
    NULL
};

// checkJB 单独处理：样本返回的是字符串 "0"，不是 nil
static const char *kZeroStringSelectors[] = { "checkJB", NULL };

#pragma mark - 替换实现

static BOOL hbg_ret_no(id self, SEL _cmd)   { return NO; }
static void hbg_ret_void(id self, SEL _cmd) { }
static id   hbg_ret_nil(id self, SEL _cmd)  { return nil; }
static id   hbg_ret_zero(id self, SEL _cmd) { return @"0"; }

static BOOL hbg_in_list(const char *name, const char **list) {
    for (int i = 0; list[i]; i++) {
        if (strcmp(name, list[i]) == 0) return YES;
    }
    return NO;
}

// 只处理主 App 镜像里的类：系统类里的 isProxy / isDebugging 绝对不能碰
static BOOL hbg_is_app_class(Class cls) {
    const char *img = class_getImageName(cls);
    const char *mainImg = _dyld_get_image_name(0);
    if (!img || !mainImg) return NO;
    return strcmp(img, mainImg) == 0;
}

#pragma mark - 扫描

static int hbg_scan_and_patch(void) {
    int count = objc_getClassList(NULL, 0);
    if (count <= 0) return 0;

    Class *classes = (Class *)malloc(sizeof(Class) * count);
    if (!classes) return 0;
    count = objc_getClassList(classes, count);

    int patched = 0, skippedSys = 0;
    for (int i = 0; i < count; i++) {
        Class cls = classes[i];
        if (!hbg_is_app_class(cls)) { skippedSys++; continue; }

        for (int meta = 0; meta < 2; meta++) {
            Class target = meta ? object_getClass(cls) : cls;
            if (!target) continue;

            unsigned int mcount = 0;
            Method *methods = class_copyMethodList(target, &mcount);
            if (!methods) continue;

            for (unsigned int j = 0; j < mcount; j++) {
                const char *name  = sel_getName(method_getName(methods[j]));
                const char *types = method_getTypeEncoding(methods[j]);
                if (!name || !types) continue;

                char ret = types[0];

                if (hbg_in_list(name, kZeroStringSelectors)) {
                    method_setImplementation(methods[j], (IMP)hbg_ret_zero);
                    patched++;
                } else if (ret == 'v' && hbg_in_list(name, kVoidSelectors)) {
                    method_setImplementation(methods[j], (IMP)hbg_ret_void);
                    patched++;
                } else if ((ret == 'c' || ret == 'B' || ret == 'S') &&
                           hbg_in_list(name, kBoolSelectors)) {
                    method_setImplementation(methods[j], (IMP)hbg_ret_no);
                    patched++;
                } else if (ret == '@' && hbg_in_list(name, kObjectSelectors)) {
                    method_setImplementation(methods[j], (IMP)hbg_ret_nil);
                    patched++;
                }
            }
            free(methods);
        }
    }
    free(classes);
    NSLog(@"[HBGuard] coverage patched=%d skippedSystemClasses=%d", patched, skippedSys);
    return patched;
}

#pragma mark - UA 兜底：IsJailbroken/1 → /0

static NSString *hbg_fix_ua(NSString *ua) {
    if (![ua isKindOfClass:[NSString class]]) return ua;
    if ([ua rangeOfString:@"IsJailbroken/"].location == NSNotFound) return ua;
    NSMutableString *m = [ua mutableCopy];
    [m replaceOccurrencesOfString:@"IsJailbroken/1"
                       withString:@"IsJailbroken/0"
                          options:0
                            range:NSMakeRange(0, m.length)];
    return m;
}

%hook NSMutableURLRequest
- (void)setValue:(NSString *)value forHTTPHeaderField:(NSString *)field {
    if (field && value && [field caseInsensitiveCompare:@"User-Agent"] == NSOrderedSame) {
        value = hbg_fix_ua(value);
    }
    %orig;
}
- (void)setAllHTTPHeaderFields:(NSDictionary<NSString *, NSString *> *)map {
    if (map[@"User-Agent"]) {
        NSMutableDictionary *d = [map mutableCopy];
        d[@"User-Agent"] = hbg_fix_ua(map[@"User-Agent"]);
        %orig(d);
        return;
    }
    %orig;
}
%end

%hook NSURLSessionConfiguration
- (void)setHTTPAdditionalHeaders:(NSDictionary *)headers {
    if (headers[@"User-Agent"]) {
        NSMutableDictionary *d = [headers mutableCopy];
        d[@"User-Agent"] = hbg_fix_ua(headers[@"User-Agent"]);
        %orig(d);
        return;
    }
    %orig;
}
%end

#pragma mark - 入口

static void _hbg_ctor_2(void) {
    @autoreleasepool {
        if (!HBGEnabled() || !HBGCoverageEnabled()) return;
        hbg_scan_and_patch();
    }
}


/* ---- 单入口：按 隐藏 -> hook -> 补漏 的顺序执行 ---- */
%ctor {
    @autoreleasepool {
        %init(_ungrouped);
        _hbg_ctor_0();
        _hbg_ctor_1();
        _hbg_ctor_2();
    }
}
