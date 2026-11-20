#import "TRCCommon.h"

#import <string.h>

static NSSet<NSString *> *TRCBlackKeys(void) {
    static NSSet<NSString *> *keys;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        keys = [NSSet setWithArray:@[
            @"jailbreak", @"isjailbreak", @"cydia", @"substrate", @"substitute",
            @"ellekit", @"frida", @"cycript", @"debugger", @"isdebugging",
            @"simulator", @"issimulator", @"hook", @"injected", @"dylib",
            @"dyldimages", @"suspicious", @"risk", @"tamper", @"cdhash",
            @"execfilemd5", @"embeddedhash", @"proxy", @"vpn"
        ]];
    });
    return keys;
}

static NSString *TRCLowerKey(id key) {
    return [[key description] lowercaseString];
}

static id TRCSanitize(id object, BOOL rewriteUpdate) {
    if ([object isKindOfClass:NSDictionary.class]) {
        NSMutableDictionary *output = [NSMutableDictionary dictionary];
        [(NSDictionary *)object enumerateKeysAndObjectsUsingBlock:^(id key, id value, BOOL *stop) {
            NSString *lower = TRCLowerKey(key);
            if ([TRCBlackKeys() containsObject:lower]) return;

            if ([lower isEqualToString:@"riskscore"] || [lower isEqualToString:@"risklevel"]) {
                output[key] = @0;
                return;
            }

            if (rewriteUpdate) {
                if ([lower isEqualToString:@"forceupgrade"] || [lower isEqualToString:@"force_update"]) {
                    output[key] = @NO;
                    return;
                }
                if ([lower isEqualToString:@"minversion"]) {
                    output[key] = @"1.0.0";
                    return;
                }
                if ([lower isEqualToString:@"latestversion"]) {
                    output[key] = TRCConfigString(@"FakeVersion");
                    return;
                }
                if ([lower isEqualToString:@"upgradeurl"]) {
                    output[key] = TRCConfigString(@"FakeUpgradeURL");
                    return;
                }
                if ([lower isEqualToString:@"upgradecontent"]) {
                    output[key] = @"";
                    return;
                }
            }

            output[key] = TRCSanitize(value, rewriteUpdate);
        }];
        return output;
    }

    if ([object isKindOfClass:NSArray.class]) {
        NSMutableArray *output = [NSMutableArray array];
        for (id item in (NSArray *)object) {
            [output addObject:TRCSanitize(item, rewriteUpdate)];
        }
        return output;
    }

    if ([object isKindOfClass:NSString.class]) {
        const char *raw = [(NSString *)object UTF8String];
        if (raw && TRCPathHidden(raw)) return @"";
    }
    return object;
}

static NSData *TRCSanitizeJSONData(NSData *data, BOOL rewriteUpdate) {
    if (![data isKindOfClass:NSData.class] || data.length == 0) return data;

    id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (!json) return data;

    id filtered = TRCSanitize(json, rewriteUpdate);
    NSData *result = [NSJSONSerialization dataWithJSONObject:filtered options:0 error:nil];
    return result ?: data;
}

static NSURLRequest *TRCSanitizeRequest(NSURLRequest *request) {
    if (![request isKindOfClass:NSURLRequest.class]) return request;

    NSData *body = request.HTTPBody;
    if (body.length == 0) return request;

    NSData *filtered = TRCSanitizeJSONData(body, NO);
    if (filtered == body || [filtered isEqualToData:body]) return request;

    NSMutableURLRequest *copy = [request mutableCopy];
    copy.HTTPBody = filtered;
    [copy setValue:[NSString stringWithFormat:@"%lu", (unsigned long)filtered.length]
        forHTTPHeaderField:@"Content-Length"];
    return copy;
}

static void TRCInstallJSONHooks(void) {
    __block IMP oldData = NULL;
    oldData = TRCSwizzleClass("NSJSONSerialization", "dataWithJSONObject:options:error:",
        imp_implementationWithBlock(^id(id self, id object, NSUInteger options, NSError **error) {
            id filtered = TRCSanitize(object, YES);
            return ((id (*)(id, SEL, id, NSUInteger, NSError **))oldData)(
                self, @selector(dataWithJSONObject:options:error:), filtered, options, error);
        }));

    __block IMP oldObject = NULL;
    oldObject = TRCSwizzleClass("NSJSONSerialization", "JSONObjectWithData:options:error:",
        imp_implementationWithBlock(^id(id self, NSData *data, NSJSONReadingOptions options, NSError **error) {
            id object = ((id (*)(id, SEL, NSData *, NSJSONReadingOptions, NSError **))oldObject)(
                self, @selector(JSONObjectWithData:options:error:), data, options, error);
            return TRCSanitize(object, YES);
        }));
}

static void TRCInstallSessionHooks(void) {
    __block IMP oldTask = NULL;
    oldTask = TRCSwizzleInstance("NSURLSession", "dataTaskWithRequest:completionHandler:",
        imp_implementationWithBlock(^id(id self, NSURLRequest *request,
                                        void (^handler)(NSData *, NSURLResponse *, NSError *)) {
            NSURLRequest *clean = TRCSanitizeRequest(request);
            void (^wrapped)(NSData *, NSURLResponse *, NSError *) =
                ^(NSData *data, NSURLResponse *response, NSError *error) {
                    NSData *filtered = TRCSanitizeJSONData(data, NO);
                    if (handler) handler(filtered, response, error);
                };
            return ((id (*)(id, SEL, NSURLRequest *, id))oldTask)(
                self, @selector(dataTaskWithRequest:completionHandler:), clean, wrapped);
        }));

    __block IMP oldUpload = NULL;
    oldUpload = TRCSwizzleInstance("NSURLSession", "uploadTaskWithRequest:fromData:completionHandler:",
        imp_implementationWithBlock(^id(id self, NSURLRequest *request, NSData *body,
                                        void (^handler)(NSData *, NSURLResponse *, NSError *)) {
            NSURLRequest *clean = TRCSanitizeRequest(request);
            NSData *cleanBody = TRCSanitizeJSONData(body, NO);
            void (^wrapped)(NSData *, NSURLResponse *, NSError *) =
                ^(NSData *data, NSURLResponse *response, NSError *error) {
                    NSData *filtered = TRCSanitizeJSONData(data, NO);
                    if (handler) handler(filtered, response, error);
                };
            return ((id (*)(id, SEL, NSURLRequest *, NSData *, id))oldUpload)(
                self, @selector(uploadTaskWithRequest:fromData:completionHandler:), clean, cleanBody, wrapped);
        }));
}

void TRCInstallEventHooks(void) {
    TRCInstallJSONHooks();
    TRCInstallSessionHooks();
}
