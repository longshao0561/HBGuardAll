#import "TRCCommon.h"

%ctor {
    @autoreleasepool {
        if (!TRCIsTargetApp()) return;

        TRCInstallHideDylib();
        TRCInstallDetectionHooks();
        TRCInstallIntegrityHooks();
        TRCInstallEventHooks();
        TRCInstallUpdateHooks();
        TRCInstallRiskHooks();
    }
}
