#import "TRCCommon.h"

static NSDictionary<NSString *, id> *TRCDefaults(void) {
    static NSDictionary<NSString *, id> *defaults;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        defaults = @{
            @"Enabled": @YES,
            @"AllowAnyBundle": @NO,
            @"TargetBundleID": @"me.ele.ios.LPDCrowdsourceAppStore",
            @"HideNeedles": @[
                @"signinject", @"TrafficRules", @"Substrate", @"Substitute",
                @"ellekit", @"libhooker", @"TweakInject", @"cynject",
                @"frida", @"cycript", @"objection", @"/var/jb"
            ],
            @"DropEvents": @NO,
            @"FakeVersion": @"10.11.2",
            @"FakeUpgradeURL": @"https://example.com/app/download",
            @"FakeMD5": @"e4d330c15021d53a959aca760dbb845e",
            @"SkipChainedImages": @YES,
            @"PatchDataConst": @NO,
            @"FakeTeamID": @"HOSTTEAMID",
            @"FakeBundleID": @"me.ele.ios.LPDCrowdsourceAppStore",
            @"FakeDeviceModel": @"iPhone15,3",
            @"RiskScoreCap": @0
        };
    });
    return defaults;
}

static NSUserDefaults *TRCPrefs(void) {
    static NSUserDefaults *prefs;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        prefs = [[NSUserDefaults alloc] initWithSuiteName:@"com.trc.repro"];
    });
    return prefs;
}

id TRCConfigValue(NSString *key) {
    id value = [TRCPrefs() objectForKey:key];
    return value ?: TRCDefaults()[key];
}

BOOL TRCConfigBool(NSString *key) {
    id value = TRCConfigValue(key);
    return [value respondsToSelector:@selector(boolValue)] ? [value boolValue] : NO;
}

NSString *TRCConfigString(NSString *key) {
    id value = TRCConfigValue(key);
    return [value isKindOfClass:NSString.class] ? value : @"";
}

NSArray<NSString *> *TRCConfigArray(NSString *key) {
    id value = TRCConfigValue(key);
    return [value isKindOfClass:NSArray.class] ? value : @[];
}

BOOL TRCIsTargetApp(void) {
    if (!TRCConfigBool(@"Enabled")) return NO;
    if (TRCConfigBool(@"AllowAnyBundle")) return YES;

    NSString *target = TRCConfigString(@"TargetBundleID");
    NSString *current = NSBundle.mainBundle.bundleIdentifier;
    if (target.length == 0 || current.length == 0) return NO;
    return [current isEqualToString:target];
}
