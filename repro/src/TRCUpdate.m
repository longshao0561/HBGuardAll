#import "TRCCommon.h"

static NSString *TRCFakeVersion(void) {
    return TRCConfigString(@"FakeVersion");
}

static void TRCInstallAliHooks(void) {
    if (TRCClassExists("AliCheckNewVersion")) {
        TRCSwizzleClass("AliCheckNewVersion",
            "canMTL4PopUpdateAlertWithUpdateInfoModel:",
            TRCImpBool1(^BOOL(id self, id model) {
                return NO;
            }));

        TRCSwizzleInstance("AliCheckNewVersion",
            "checkNewVersionWithGoupName:name:isBreak:slidePodName:appStoreURL:notifyViewView:transitionDelegate:",
            imp_implementationWithBlock(^void(id self, id group, id name, BOOL isBreak,
                                              id pod, id appStoreURL, id notifyView, id delegate) {
                // 检查入口整体置空
            }));
    }
}

static void TRCInstallLPDHooks(void) {
    if (TRCClassExists("LPDRemoteVersionModel")) {
        TRCSwizzleInstance("LPDRemoteVersionModel", "forceUpgrade", TRCImpBool(^BOOL(id self) {
            return NO;
        }));
        TRCSwizzleInstance("LPDRemoteVersionModel", "upgradeUrl", TRCImpId(^id(id self) {
            return TRCConfigString(@"FakeUpgradeURL");
        }));
        TRCSwizzleInstance("LPDRemoteVersionModel", "upgradeContent", TRCImpId(^id(id self) {
            return @"";
        }));
        TRCSwizzleInstance("LPDRemoteVersionModel", "version", TRCImpId(^id(id self) {
            return TRCFakeVersion();
        }));
    }

    if (TRCClassExists("LPDAppVersionService")) {
        TRCSwizzleInstance("LPDAppVersionService", "forceUpgrade", TRCImpBool(^BOOL(id self) {
            return NO;
        }));
        TRCSwizzleInstance("LPDAppVersionService", "currentVersion", TRCImpId(^id(id self) {
            return TRCFakeVersion();
        }));
        TRCSwizzleInstance("LPDAppVersionService", "currentVersionLastest", TRCImpId(^id(id self) {
            return TRCFakeVersion();
        }));
    }
}

static void TRCInstallHBFHooks(void) {
    if (!TRCClassExists("HBFVersionUtil")) return;

    TRCSwizzleClass("HBFVersionUtil", "localVersion", TRCImpId(^id(id self) {
        return TRCFakeVersion();
    }));
    TRCSwizzleClass("HBFVersionUtil", "saveVersion", TRCImpVoid(^void(id self) {
        // 不落盘
    }));
    TRCSwizzleClass("HBFVersionUtil", "isAppFirstInstall", TRCImpBool(^BOOL(id self) {
        return NO;
    }));
    TRCSwizzleClass("HBFVersionUtil", "isAppUpdateVersion", TRCImpBool(^BOOL(id self) {
        return NO;
    }));
}

void TRCInstallUpdateHooks(void) {
    TRCInstallAliHooks();
    TRCInstallLPDHooks();
    TRCInstallHBFHooks();
}
