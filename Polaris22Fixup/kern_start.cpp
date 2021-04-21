//
//  kern_start.cpp
//  Polaris22Fixup
//
//  Copyright © 2020 osy86. All rights reserved.
//

#include <Headers/plugin_start.hpp>
#include <Headers/kern_api.hpp>
#include <Headers/kern_user.hpp>

#define MODULE_SHORT "sidecar"

extern "C" void *memmem(const void *h0, size_t k, const void *n0, size_t l);

static const int kPathMaxLen = 1024;

#pragma mark - Patches

// static const uint8_t kMacModelOriginal[] = "MacPro6,1";
// static const uint8_t kMacModelPatched[] = "MacPro7,1";

static const uint8_t kMacModelOriginal[] = {0x4D, 0x61, 0x63, 0x6D, 0x69, 0x6E, 0x69, 0x37, 0x2C, 0x31, 0x00, 0x4D, 0x61, 0x63, 0x50, 0x72, 0x6F, 0x35, 0x2C, 0x31, 0x00, 0x4D, 0x61, 0x63, 0x50, 0x72, 0x6F, 0x36, 0x2C, 0x31};
static const uint8_t kMacModelPatched[]  = {0x4D, 0x61, 0x63, 0x6D, 0x69, 0x6E, 0x69, 0x37, 0x2C, 0x31, 0x00, 0x4D, 0x61, 0x63, 0x50, 0x72, 0x6F, 0x35, 0x2C, 0x31, 0x00, 0x4D, 0x61, 0x63, 0x50, 0x72, 0x6F, 0x37, 0x2C, 0x31};

static constexpr size_t kMacModelOriginalSize = sizeof(kMacModelOriginal);
static_assert(kMacModelOriginalSize == sizeof(kMacModelPatched), "patch size invalid");

static const char kSidecarCorePath[kPathMaxLen] = "/System/Library/PrivateFrameworks/SidecarCore.framework/Versions/A/SidecarCore";

static mach_vm_address_t orig_cs_func {};

#pragma mark - Kernel patching code

template <size_t patchSize>
static inline bool searchAndPatch(const void *haystack,
                                  size_t haystackSize,
                                  const char (&path)[kPathMaxLen],
                                  const uint8_t (&needle)[patchSize],
                                  const uint8_t (&patch)[patchSize]) {
    SYSLOG(MODULE_SHORT, "processing path: %s", path);
    if (UNLIKELY(strncmp(path, kSidecarCorePath, sizeof(kSidecarCorePath)) == 0) ||
        UNLIKELY(strncmp(path, UserPatcher::getSharedCachePath(), sizeof(UserPatcher::getSharedCachePath())) == 0)) {
        void *res;
        if (UNLIKELY((res = memmem(haystack, haystackSize, needle, patchSize)) != NULL)) {
            // This is redundant but we just want to print
            SYSLOG(MODULE_SHORT, "found function to patch!");
            SYSLOG(MODULE_SHORT, "path: %s", path);
            SYSLOG(MODULE_SHORT, KernelPatcher::findAndReplace(haystack, haystackSize, needle, patchSize) ? "patch succeeded" : "patch failed");
        }
    }
    return false;
}

#pragma mark - Patched functions

// pre Big Sur
static boolean_t patched_cs_validate_range(vnode_t vp,
                                           memory_object_t pager,
                                           memory_object_offset_t offset,
                                           const void *data,
                                           vm_size_t size,
                                           unsigned *result) {
    char path[kPathMaxLen];
    int pathlen = kPathMaxLen;
    boolean_t res = FunctionCast(patched_cs_validate_range, orig_cs_func)(vp, pager, offset, data, size, result);
    if (res && vn_getpath(vp, path, &pathlen) == 0) {
        searchAndPatch(data, size, path, kMacModelOriginal, kMacModelPatched);
    }
    return res;
}

// For Big Sur
static void patched_cs_validate_page(vnode_t vp,
                                          memory_object_t pager,
                                          memory_object_offset_t page_offset,
                                          const void *data,
                                          int *arg4,
                                          int *arg5,
                                          int *arg6) {
    char path[kPathMaxLen];
    int pathlen = kPathMaxLen;
    FunctionCast(patched_cs_validate_page, orig_cs_func)(vp, pager, page_offset, data, arg4, arg5, arg6);
    if (vn_getpath(vp, path, &pathlen) == 0) {
        searchAndPatch(data, PAGE_SIZE, path, kMacModelOriginal, kMacModelPatched);
    }
}

#pragma mark - Patches on start/stop

static void pluginStart() {
    LiluAPI::Error error;
    
    DBGLOG(MODULE_SHORT, "start");
    if (getKernelVersion() < KernelVersion::BigSur) {
        error = lilu.onPatcherLoad([](void *user, KernelPatcher &patcher){
            DBGLOG(MODULE_SHORT, "patching cs_validate_range");
            mach_vm_address_t kern = patcher.solveSymbol(KernelPatcher::KernelID, "_cs_validate_range");
            
            if (patcher.getError() == KernelPatcher::Error::NoError) {
                orig_cs_func = patcher.routeFunctionLong(kern, reinterpret_cast<mach_vm_address_t>(patched_cs_validate_range), true, true);
                
                if (patcher.getError() != KernelPatcher::Error::NoError) {
                    SYSLOG(MODULE_SHORT, "failed to hook _cs_validate_range");
                } else {
                    DBGLOG(MODULE_SHORT, "hooked cs_validate_range");
                }
            } else {
                SYSLOG(MODULE_SHORT, "failed to find _cs_validate_range");
            }
        });
    } else { // >= macOS 11
        error = lilu.onPatcherLoad([](void *user, KernelPatcher &patcher){
            DBGLOG(MODULE_SHORT, "patching cs_validate_page");
            mach_vm_address_t kern = patcher.solveSymbol(KernelPatcher::KernelID, "_cs_validate_page");
            
            if (patcher.getError() == KernelPatcher::Error::NoError) {
                orig_cs_func = patcher.routeFunctionLong(kern, reinterpret_cast<mach_vm_address_t>(patched_cs_validate_page), true, true);
                
                if (patcher.getError() != KernelPatcher::Error::NoError) {
                    SYSLOG(MODULE_SHORT, "failed to hook _cs_validate_page");
                } else {
                    DBGLOG(MODULE_SHORT, "hooked cs_validate_page");
                }
            } else {
                SYSLOG(MODULE_SHORT, "failed to find _cs_validate_page");
            }
        });
    }
    if (error != LiluAPI::Error::NoError) {
        SYSLOG(MODULE_SHORT, "failed to register onPatcherLoad method: %d", error);
    }
}

// Boot args.
static const char *bootargOff[] {
    "-polaris22off"
};
static const char *bootargDebug[] {
    "-polaris22dbg"
};
static const char *bootargBeta[] {
    "-polaris22beta"
};

// Plugin configuration.
PluginConfiguration ADDPR(config) {
    xStringify(PRODUCT_NAME),
    parseModuleVersion(xStringify(MODULE_VERSION)),
    LiluAPI::AllowNormal,
    bootargOff,
    arrsize(bootargOff),
    bootargDebug,
    arrsize(bootargDebug),
    bootargBeta,
    arrsize(bootargBeta),
    KernelVersion::Catalina,
    KernelVersion::BigSur,
    pluginStart
};
