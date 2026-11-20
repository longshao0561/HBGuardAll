#import "TRCCommon.h"

#import <dlfcn.h>
#import <string.h>
#import <unistd.h>
#import <sys/sysctl.h>
#import <sys/proc.h>
#import <sys/ptrace.h>

static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static char *(*orig_getenv)(const char *);
static int (*orig_ptrace)(int, pid_t, caddr_t, int);

static void TRCZeroClassBool(const char *className, const char *selector) {
    if (!TRCClassExists(className)) return;
    TRCSwizzleClass(className, selector, TRCImpBool(^BOOL(id self) {
        return NO;
    }));
}

static void TRCZeroInstanceBool(const char *className, const char *selector) {
    if (!TRCClassExists(className)) return;
    TRCSwizzleInstance(className, selector, TRCImpBool(^BOOL(id self) {
        return NO;
    }));
}

static NSArray *TRCFilterStringArray(NSArray *input) {
    if (![input isKindOfClass:NSArray.class]) return input;

    NSMutableArray *output = [NSMutableArray array];
    for (id item in input) {
        NSString *text = [item description];
        const char *raw = text.UTF8String;
        if (raw && TRCPathHidden(raw)) continue;
        if ([text containsString:@"Substrate"] || [text containsString:@"Substitute"] ||
            [text containsString:@"ellekit"] || [text containsString:@"frida"]) continue;
        [output addObject:item];
    }
    return output;
}

static NSDictionary *TRCFilterDictionary(NSDictionary *input) {
    if (![input isKindOfClass:NSDictionary.class]) return input;

    NSMutableDictionary *output = [NSMutableDictionary dictionary];
    [input enumerateKeysAndObjectsUsingBlock:^(id key, id value, BOOL *stop) {
        if ([value isKindOfClass:NSArray.class]) {
            output[key] = TRCFilterStringArray(value);
        } else if ([value isKindOfClass:NSDictionary.class]) {
            output[key] = TRCFilterDictionary(value);
        } else if ([value isKindOfClass:NSString.class]) {
            const char *raw = [value UTF8String];
            if (raw && TRCPathHidden(raw)) return;
            output[key] = value;
        } else {
            output[key] = value;
        }
    }];
    return output;
}

static int TRCSysctlHook(int *name, u_int namelen, void *oldp, size_t *oldlenp,
                         void *newp, size_t newlen) {
    if (namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC &&
        name[2] == KERN_PROC_PID && oldp && oldlenp) {
        int rc = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
        struct kinfo_proc *proc = (struct kinfo_proc *)oldp;
        if (rc == 0 && *oldlenp >= sizeof(*proc)) {
            proc->kp_proc.p_flag &= ~P_TRACED;
        }
        return rc;
    }

    if (namelen == 2 && name[0] == CTL_HW && name[1] == HW_MACHINE &&
        oldp && oldlenp) {
        NSString *model = TRCConfigString(@"FakeDeviceModel");
        const char *raw = model.UTF8String;
        size_t length = strlen(raw) + 1;
        if (*oldlenp >= length) {
            memcpy(oldp, raw, length);
            *oldlenp = length;
            return 0;
        }
    }
    return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}

static char *TRCGetenvHook(const char *key) {
    if (key && (!strncmp(key, "SIMULATOR_", 10) ||
                strcmp(key, "DYLD_INSERT_LIBRARIES") == 0)) {
        return NULL;
    }
    return orig_getenv(key);
}

static int TRCPtraceHook(int request, pid_t pid, caddr_t addr, int data) {
    if (request == PT_DENY_ATTACH) return 0;
    return orig_ptrace(request, pid, addr, data);
}

static void TRCInstallSysctlHook(void) {
    orig_sysctl = dlsym(RTLD_DEFAULT, "sysctl");
    if (orig_sysctl) TRCRebindAll("_sysctl", (void *)TRCSysctlHook);
}

static void TRCInstallGetenvHook(void) {
    orig_getenv = dlsym(RTLD_DEFAULT, "getenv");
    if (orig_getenv) TRCRebindAll("_getenv", (void *)TRCGetenvHook);
}

static void TRCInstallPtraceHook(void) {
    orig_ptrace = dlsym(RTLD_DEFAULT, "ptrace");
    if (orig_ptrace) TRCRebindAll("_ptrace", (void *)TRCPtraceHook);
}

static void TRCInstallEnvironmentHook(void) {
    __block IMP old = NULL;
    old = TRCSwizzleInstance("NSProcessInfo", "environment", TRCImpId(^id(id self) {
        NSDictionary *environment = ((id (*)(id, SEL))old)(self, @selector(environment));
        if (![environment isKindOfClass:NSDictionary.class]) return environment;

        NSMutableDictionary *filtered = [environment mutableCopy];
        for (NSString *key in environment.allKeys) {
            if ([key hasPrefix:@"SIMULATOR_"] || [key isEqualToString:@"DYLD_INSERT_LIBRARIES"]) {
                [filtered removeObjectForKey:key];
            }
        }
        return filtered;
    }));
}

static void TRCInstallDeviceModelHook(void) {
    __block IMP old = NULL;
    old = TRCSwizzleInstance("UIDevice", "model", TRCImpId(^id(id self) {
        NSString *model = TRCConfigString(@"FakeDeviceModel");
        return model.length ? model : ((id (*)(id, SEL))old)(self, @selector(model));
    }));
}

void TRCInstallDetectionHooks(void) {
    TRCZeroClassBool("SPJailbreakSniffer", "isJailbreak");
    TRCZeroClassBool("SPJailbreakSniffer", "isDebugging");
    TRCZeroClassBool("SPJailbreakSniffer", "hasJailbreakPort");
    TRCZeroClassBool("SPJailbreakSniffer", "hasWritePermissionInRoot");
    TRCZeroClassBool("SPJailbreakSniffer", "hasJailbreakApps");
    TRCZeroClassBool("SPJailbreakSniffer", "canOpenApplication");
    TRCZeroClassBool("internal_DeviceInfo", "isJailBreak");
    TRCZeroClassBool("AliSecXDeviceInfo", "isJailBreak");
    TRCZeroClassBool("BHXDeviceInfoHelper", "isJailbreak");

    TRCZeroInstanceBool("RVPBridgeExtension4Jailbroken", "isJailbroken");

    if (TRCClassExists("SPJailbreakSniffer")) {
        __block IMP oldList = NULL;
        oldList = TRCSwizzleClass("SPJailbreakSniffer", "dynamicLibList", TRCImpId(^id(id self) {
            id value = ((id (*)(id, SEL))oldList)(self, @selector(dynamicLibList));
            return TRCFilterStringArray(value);
        }));

        __block IMP oldProxy = NULL;
        oldProxy = TRCSwizzleClass("SPJailbreakSniffer", "proxyInformation", TRCImpId(^id(id self) {
            id value = ((id (*)(id, SEL))oldProxy)(self, @selector(proxyInformation));
            return TRCFilterDictionary(value);
        }));

        __block IMP oldImages = NULL;
        oldImages = TRCSwizzleClass("SPJailbreakSniffer", "dyldImageInfo", TRCImpId(^id(id self) {
            id value = ((id (*)(id, SEL))oldImages)(self, @selector(dyldImageInfo));
            return TRCFilterDictionary(value);
        }));
    }

    TRCInstallSysctlHook();
    TRCInstallGetenvHook();
    TRCInstallPtraceHook();
    TRCInstallEnvironmentHook();
    TRCInstallDeviceModelHook();
}
