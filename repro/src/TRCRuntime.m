#import "TRCCommon.h"

BOOL TRCClassExists(const char *name) {
    return name != NULL && objc_getClass(name) != Nil;
}

IMP _Nullable TRCSwizzleClass(const char *clsName, const char *selName, IMP imp) {
    Class cls = objc_getClass(clsName);
    if (!cls || !selName || !imp) return (IMP)0;

    SEL sel = sel_registerName(selName);
    Method method = class_getClassMethod(cls, sel);
    if (!method) return (IMP)0;

    IMP old = method_getImplementation(method);
    method_setImplementation(method, imp);
    return old;
}

IMP _Nullable TRCSwizzleInstance(const char *clsName, const char *selName, IMP imp) {
    Class cls = objc_getClass(clsName);
    if (!cls || !selName || !imp) return (IMP)0;

    SEL sel = sel_registerName(selName);
    Method method = class_getInstanceMethod(cls, sel);
    if (!method) return (IMP)0;

    IMP old = method_getImplementation(method);
    method_setImplementation(method, imp);
    return old;
}

IMP TRCImpBool(BOOL (^block)(id)) {
    return imp_implementationWithBlock(block);
}

IMP TRCImpBool1(BOOL (^block)(id, id)) {
    return imp_implementationWithBlock(block);
}

IMP TRCImpId(id (^block)(id)) {
    return imp_implementationWithBlock(block);
}

IMP TRCImpId1(id (^block)(id, id)) {
    return imp_implementationWithBlock(block);
}

IMP TRCImpVoid(void (^block)(id)) {
    return imp_implementationWithBlock(block);
}

IMP TRCImpVoid1(void (^block)(id, id)) {
    return imp_implementationWithBlock(block);
}
