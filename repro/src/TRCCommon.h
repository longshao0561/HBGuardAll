#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>

NS_ASSUME_NONNULL_BEGIN

BOOL TRCIsTargetApp(void);

id TRCConfigValue(NSString *key);
BOOL TRCConfigBool(NSString *key);
NSString *TRCConfigString(NSString *key);
NSArray<NSString *> *TRCConfigArray(NSString *key);

BOOL TRCPathHidden(const char *path);
void TRCInstallHideDylib(void);
void TRCRebindAll(const char *symbol, void *replacement);

BOOL TRCClassExists(const char *name);
IMP TRCSwizzleClass(const char *cls, const char *sel, IMP imp);
IMP TRCSwizzleInstance(const char *cls, const char *sel, IMP imp);

IMP TRCImpBool(BOOL (^block)(id));
IMP TRCImpBool1(BOOL (^block)(id, id));
IMP TRCImpId(id (^block)(id));
IMP TRCImpId1(id (^block)(id, id));
IMP TRCImpVoid(void (^block)(id));
IMP TRCImpVoid1(void (^block)(id, id));

void TRCInstallDetectionHooks(void);
void TRCInstallIntegrityHooks(void);
void TRCInstallEventHooks(void);
void TRCInstallUpdateHooks(void);
void TRCInstallRiskHooks(void);

NS_ASSUME_NONNULL_END
