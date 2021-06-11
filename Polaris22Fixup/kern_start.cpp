//
//  kern_start.cpp
//  Polaris22Fixup
//
//  Copyright © 2020 osy86. All rights reserved.
//

#include <Headers/plugin_start.hpp>
#include <Headers/kern_api.hpp>
#include <Headers/kern_user.hpp>

#define MODULE_SHORT "dhinak"

static const int kPathMaxLen = 1024;

#pragma mark - Patches

static const uint8_t kDisableSnapshotPatch1[] = "/etc/bluetool/SkipBluetoothAutomaticFirmwareUpdate";

static const uint8_t kDisableSnapshotPatched[] = "/System/Library/CoreServices/boot.efi\0\0\0\0\0\0\0\0\0\0\0\0\0";

static constexpr size_t kDisableSnapshotPatch1Size = sizeof(kDisableSnapshotPatch1);

static_assert(kDisableSnapshotPatch1Size == sizeof(kDisableSnapshotPatched), "patch 1 size invalid");

static const char libSystemPath[kPathMaxLen] = "/usr/sbin/BlueTool";

static mach_vm_address_t orig_cs_func {};

#pragma mark - Kernel patching code

template <size_t patchSize>
static inline bool searchAndPatch(const void *haystack,
                                  size_t haystackSize,
                                  const char (&path)[kPathMaxLen],
                                  const uint8_t (&needle)[patchSize],
                                  const uint8_t (&patch)[patchSize]) {
    // SYSLOG(MODULE_SHORT, "processing path: %s", path);
    bool result = false;
    if (UNLIKELY(strncmp(path, libSystemPath, sizeof(libSystemPath)) == 0)) {
            result = KernelPatcher::findAndReplace(const_cast<void *>(haystack), haystackSize, needle, patchSize, patch, patchSize);
            if (result) {
                SYSLOG(MODULE_SHORT, "patch succeeded");
            } else {
                SYSLOG(MODULE_SHORT, "patch failed");
            }
    }
    return result;
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
        searchAndPatch(data, size, path, kDisableSnapshotPatch1, kDisableSnapshotPatched);
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
        searchAndPatch(data, PAGE_SIZE, path, kDisableSnapshotPatch1, kDisableSnapshotPatched);
    }
}

#pragma mark - Patches on start/stop

static void pluginStart() {
    LiluAPI::Error error;
    
    SYSLOG(MODULE_SHORT, "start");
    // if (getKernelVersion() < KernelVersion::BigSur) {
    //     error = lilu.onPatcherLoad([](void *user, KernelPatcher &patcher){
    //         SYSLOG(MODULE_SHORT, "patching cs_validate_range");
    //         mach_vm_address_t kern = patcher.solveSymbol(KernelPatcher::KernelID, "_cs_validate_range");
    //         
    //         if (patcher.getError() == KernelPatcher::Error::NoError) {
    //             orig_cs_func = patcher.routeFunctionLong(kern, reinterpret_cast<mach_vm_address_t>(patched_cs_validate_range), true, true);
    //             
    //             if (patcher.getError() != KernelPatcher::Error::NoError) {
    //                 SYSLOG(MODULE_SHORT, "failed to hook _cs_validate_range");
    //             } else {
    //                 SYSLOG(MODULE_SHORT, "hooked cs_validate_range");
    //             }
    //         } else {
    //             SYSLOG(MODULE_SHORT, "failed to find _cs_validate_range");
    //         }
    //     });
    // } else { // >= macOS 11
        error = lilu.onPatcherLoad([](void *user, KernelPatcher &patcher){
            SYSLOG(MODULE_SHORT, "patching cs_validate_page");
            mach_vm_address_t kern = patcher.solveSymbol(KernelPatcher::KernelID, "_cs_validate_page");
            
            if (patcher.getError() == KernelPatcher::Error::NoError) {
                orig_cs_func = patcher.routeFunctionLong(kern, reinterpret_cast<mach_vm_address_t>(patched_cs_validate_page), true, true);
                
                if (patcher.getError() != KernelPatcher::Error::NoError) {
                    SYSLOG(MODULE_SHORT, "failed to hook _cs_validate_page");
                } else {
                    SYSLOG(MODULE_SHORT, "hooked cs_validate_page");
                }
            } else {
                SYSLOG(MODULE_SHORT, "failed to find _cs_validate_page");
            }
        });
    // }
    if (error != LiluAPI::Error::NoError) {
        SYSLOG(MODULE_SHORT, "failed to register onPatcherLoad method: %d", error);
    }
}

// Boot args.
static const char *bootargOff[] {
    "-dhinakoff"
};
static const char *bootargDebug[] {
    "-dhinakdbg"
};
static const char *bootargBeta[] {
    "-dhinakbeta"
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
    KernelVersion::Monterey,
    KernelVersion::Monterey,
    pluginStart
};
