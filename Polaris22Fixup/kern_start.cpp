//
//  kern_start.cpp
//  Polaris22Fixup
//
//  Copyright © 2020 osy86. All rights reserved.
//

#include <Headers/plugin_start.hpp>
#include <Headers/kern_api.hpp>

#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define MODULE_SHORT "sidecar"

extern "C" void *memmem(const void *h0, size_t k, const void *n0, size_t l);

static const int kPathMaxLen = 1024;

#pragma mark - Patches

static const uint8_t kMacModelOriginal[] = "MacPro6,1";

static const uint8_t kMacModelPatched[] = "MacPro7,1";

static constexpr size_t kMacModelOriginalSize = sizeof(kMacModelOriginal);

static_assert(kMacModelOriginalSize == sizeof(kMacModelPatched), "patch size invalid");

/* static const uint8_t kBigSurAmdBronzeMtlAddrLibGetBaseArrayModeReturnOriginal[] = {
    0xb9, 0x02, 0x00, 0x00, 0x00, 0x01, 0xc8, 0x41, 0x83, 0xf8, 0x21, 0x0f, 0x42, 0xc1, 0xeb,
};

static const uint8_t kBigSurAmdBronzeMtlAddrLibGetBaseArrayModeReturnPatched[] = {
    0xb9, 0x02, 0x00, 0x00, 0x00, 0x01, 0xc8, 0x41, 0x83, 0xf8, 0x00, 0x0f, 0x43, 0xc1, 0xeb,
};

static constexpr size_t kBigSurAmdBronzeMtlAddrLibGetBaseArrayModeReturnSize = sizeof(kBigSurAmdBronzeMtlAddrLibGetBaseArrayModeReturnOriginal);

static_assert(kBigSurAmdBronzeMtlAddrLibGetBaseArrayModeReturnSize == sizeof(kBigSurAmdBronzeMtlAddrLibGetBaseArrayModeReturnPatched), "patch size invalid"); */

static const char kSidecarCorePath[kPathMaxLen] = "/System/Library/PrivateFrameworks/SidecarCore.framework/Versions/A/SidecarCore";

static const char kDyldCachePath[kPathMaxLen] = "/private/var/db/dyld/dyld_shared_cache_x86_64h";

static const char kBigSurDyldCachePath[kPathMaxLen] = "/System/Library/dyld/dyld_shared_cache_x86_64h";

static mach_vm_address_t orig_cs_validate {};

#pragma mark - Kernel patching code

/**
 * Call block with interrupts and protections disabled
 */
static void doKernelPatch(void (^patchFunc)(void)) {
    if (MachInfo::setKernelWriting(true, KernelPatcher::kernelWriteLock) == KERN_SUCCESS) {
        DBGLOG(MODULE_SHORT, "obtained write permssions");
    } else {
        SYSLOG(MODULE_SHORT, "failed to obtain write permissions");
        return;
    }
    
    patchFunc();
    
    if (MachInfo::setKernelWriting(false, KernelPatcher::kernelWriteLock) == KERN_SUCCESS) {
        DBGLOG(MODULE_SHORT, "restored write permssions");
    } else {
        SYSLOG(MODULE_SHORT, "failed to restore write permissions");
    }
}

template <size_t patchSize>
static inline void searchAndPatch(const void *haystack,
                                  size_t haystackSize,
                                  const char (&path)[kPathMaxLen],
                                  const char (&dylibCachePath)[kPathMaxLen],
                                  const uint8_t (&needle)[patchSize],
                                  const uint8_t (&patch)[patchSize]) {
    if (UNLIKELY(strncmp(path, kSidecarCorePath, sizeof(kSidecarCorePath)) == 0) ||
        UNLIKELY(strncmp(path, dylibCachePath, sizeof(dylibCachePath)) == 0)) {
        void *res;
        if (UNLIKELY((res = memmem(haystack, haystackSize, needle, patchSize)) != NULL)) {
            SYSLOG(MODULE_SHORT, "found function to patch!");
            SYSLOG(MODULE_SHORT, "path: %s", path);
            doKernelPatch(^{
                lilu_os_memcpy(res, patch, patchSize);
            });
        }
    }
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
    boolean_t res = FunctionCast(patched_cs_validate_range, orig_cs_validate)(vp, pager, offset, data, size, result);
    if (res && vn_getpath(vp, path, &pathlen) == 0) {
        searchAndPatch(data, size, path, kDyldCachePath, kMacModelOriginal, kMacModelPatched);
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
    FunctionCast(patched_cs_validate_page, orig_cs_validate)(vp, pager, page_offset, data, arg4, arg5, arg6);
    if (vn_getpath(vp, path, &pathlen) == 0) {
        searchAndPatch(data, PAGE_SIZE, path, kDyldCachePath, kMacModelOriginal, kMacModelPatched);
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
                orig_cs_validate = patcher.routeFunctionLong(kern, reinterpret_cast<mach_vm_address_t>(patched_cs_validate_range), true, true);
                
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
                orig_cs_validate = patcher.routeFunctionLong(kern, reinterpret_cast<mach_vm_address_t>(patched_cs_validate_page), true, true);
                
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
