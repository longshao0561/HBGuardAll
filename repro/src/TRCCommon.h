#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>

NS_ASSUME_NONNULL_BEGIN

// Tweak.xm 编译成 .mm（Objective-C++），src/*.m 编译成 .m（Objective-C）。
// 不加 extern "C" 时 C++ 会对这些函数做名字修饰，链接阶段全部 undefined symbol。
#ifdef __cplusplus
extern "C" {
#endif

BOOL TRCIsTargetApp(void);

id TRCConfigValue(NSString *key);
BOOL TRCConfigBool(NSString *key);
NSString *TRCConfigString(NSString *key);
NSArray<NSString *> *TRCConfigArray(NSString *key);

BOOL TRCPathHidden(const char *path);
void TRCInstallHideDylib(void);
void TRCRebindAll(const char *symbol, void *replacement);

BOOL TRCClassExists(const char *name);
IMP _Nullable TRCSwizzleClass(const char *cls, const char *sel, IMP imp);
IMP _Nullable TRCSwizzleInstance(const char *cls, const char *sel, IMP imp);

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

#ifdef __cplusplus
}
#endif

NS_ASSUME_NONNULL_END
