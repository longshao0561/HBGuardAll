#import "TRCCommon.h"

#import <CommonCrypto/CommonDigest.h>
#import <dlfcn.h>
#import <stdio.h>
#import <string.h>

static unsigned char gFakeMD5[CC_MD5_DIGEST_LENGTH];
static unsigned char gFakeSHA256[CC_SHA256_DIGEST_LENGTH];

static unsigned char *(*orig_CC_MD5)(const void *, CC_LONG, unsigned char *);
static unsigned char *(*orig_CC_SHA256)(const void *, CC_LONG, unsigned char *);

static unsigned char *TRC_MD5Hook(const void *data, CC_LONG length, unsigned char *digest);
static unsigned char *TRC_SHA256Hook(const void *data, CC_LONG length, unsigned char *digest);

static void TRCParseHex(const char *hex, unsigned char *out, size_t length) {
    if (!hex) return;
    size_t hexLength = strlen(hex);
    for (size_t i = 0; i < length && (i * 2 + 1) < hexLength; i++) {
        unsigned int value = 0;
        sscanf(hex + i * 2, "%2x", &value);
        out[i] = (unsigned char)value;
    }
}

static BOOL TRCIsMachOBuffer(const void *data, size_t length) {
    if (!data || length < sizeof(struct mach_header_64)) return NO;
    uint32_t magic = *(const uint32_t *)data;
    return magic == MH_MAGIC_64 || magic == MH_CIGAM_64;
}

static void TRCInstallDigestHooks(void) {
    orig_CC_MD5 = dlsym(RTLD_DEFAULT, "CC_MD5");
    orig_CC_SHA256 = dlsym(RTLD_DEFAULT, "CC_SHA256");

    if (orig_CC_MD5) {
        TRCRebindAll("_CC_MD5", (void *)TRC_MD5Hook);
    }
    if (orig_CC_SHA256) {
        TRCRebindAll("_CC_SHA256", (void *)TRC_SHA256Hook);
    }
}

static unsigned char *TRC_MD5Hook(const void *data, CC_LONG length, unsigned char *digest) {
    if (TRCIsMachOBuffer(data, length)) {
        memcpy(digest, gFakeMD5, CC_MD5_DIGEST_LENGTH);
        return digest;
    }
    return orig_CC_MD5(data, length, digest);
}

static unsigned char *TRC_SHA256Hook(const void *data, CC_LONG length, unsigned char *digest) {
    if (TRCIsMachOBuffer(data, length)) {
        memcpy(digest, gFakeSHA256, CC_SHA256_DIGEST_LENGTH);
        return digest;
    }
    return orig_CC_SHA256(data, length, digest);
}

static void TRCInstallAppInfoHooks(void) {
    NSString *fakeMD5 = TRCConfigString(@"FakeMD5");
    NSString *team = TRCConfigString(@"FakeTeamID");
    NSString *bundle = TRCConfigString(@"FakeBundleID");

    if (TRCClassExists("SPAppInfo")) {
        TRCSwizzleInstance("SPAppInfo", "execFileMd5", TRCImpId(^id(id self) {
            return fakeMD5;
        }));
        TRCSwizzleInstance("SPAppInfo", "checkMach_O", TRCImpBool(^BOOL(id self) {
            return NO;
        }));
        TRCSwizzleInstance("SPAppInfo", "embeddedHash", TRCImpId(^id(id self) {
            return self;
        }));
        TRCSwizzleInstance("SPAppInfo", "getTeamInfo", TRCImpId(^id(id self) {
            return @{ @"teamID": team, @"bundleID": bundle };
        }));
    }

    if (TRCClassExists("SPCheckInfo")) {
        TRCSwizzleInstance("SPCheckInfo", "bundleTeamIdentifier", TRCImpId(^id(id self) {
            return nil;
        }));
    }
}

void TRCInstallIntegrityHooks(void) {
    NSString *hex = TRCConfigString(@"FakeMD5");
    TRCParseHex(hex.UTF8String, gFakeMD5, sizeof(gFakeMD5));
    memset(gFakeSHA256, 0xA5, sizeof(gFakeSHA256));

    TRCInstallDigestHooks();
    TRCInstallAppInfoHooks();
}
