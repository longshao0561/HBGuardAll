#import "TRCCommon.h"

static void TRCInstallSuspeciousHooks(void) {
    if (TRCClassExists("TRCSuspeciousContent")) {
        TRCSwizzleInstance("TRCSuspeciousContent", "enableSuspeciousLocation",
            TRCImpBool(^BOOL(id self) {
                return NO;
            }));
        TRCSwizzleInstance("TRCSuspeciousContent", "suspeciousLocationContent",
            TRCImpId(^id(id self) {
                return @"";
            }));
    }

    if (TRCClassExists("TRCLocationGuard")) {
        TRCSwizzleInstance("TRCLocationGuard", "registerLocationNotification",
            TRCImpVoid(^void(id self) {
                // 不注册
            }));
        TRCSwizzleInstance("TRCLocationGuard", "locationDidUpdate:",
            TRCImpVoid1(^void(id self, id location) {
                // 不回传
            }));
    }
}

static void TRCInstallDriverHooks(void) {
    if (!TRCClassExists("TrafficDriver")) return;

    // 真实速度只用于内部限速，不再向上层暴露异常加速度
    TRCSwizzleInstance("TrafficDriver", "realSpeedForAntiOverspeed",
        imp_implementationWithBlock(^double(id self) {
            return 0.0;
        }));
}

void TRCInstallRiskHooks(void) {
    TRCInstallSuspeciousHooks();
    TRCInstallDriverHooks();
}
