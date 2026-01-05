#pragma once

#include <ntddk.h>
#include "../../../Common/constants.h"
#include "../../../Common/structures.h"
#include "../../../Common/protocol.h"

//
// KernelEye Driver - Main Header
//

// Forward declarations
typedef struct _DEVICE_EXTENSION DEVICE_EXTENSION, *PDEVICE_EXTENSION;

// Device extension structure
typedef struct _DEVICE_EXTENSION {
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING SymbolicLinkName;
    BOOLEAN IsInitialized;
    KSPIN_LOCK StatisticsLock;
    KERNELEYE_STATISTICS Statistics;
    KERNELEYE_CONFIG Config;
    LARGE_INTEGER StartTime;
    UINT32 NextSequenceNumber;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

// Global variables (extern declarations)
extern PDEVICE_OBJECT g_DeviceObject;
extern BOOLEAN g_DriverUnloading;

// Driver entry and unload
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

// Device control routines
_Dispatch_type_(IRP_MJ_CREATE)
DRIVER_DISPATCH DeviceCreate;

_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH DeviceClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH DeviceControl;

// Utility functions
NTSTATUS InitializeDriver(PDEVICE_OBJECT DeviceObject);
VOID CleanupDriver(VOID);
VOID GetSystemTime(PUINT64 Timestamp);

// Debug macros
#if DBG
#define KE_DEBUG_PRINT(level, format, ...) \
    if (level <= KERNELEYE_DEBUG_LEVEL) { \
        DbgPrint("[KernelEye:%s:%d] " format "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__); \
    }
#else
#define KE_DEBUG_PRINT(level, format, ...)
#endif

#define KE_ERROR(format, ...)   KE_DEBUG_PRINT(DEBUG_LEVEL_ERROR, "[ERROR] " format, ##__VA_ARGS__)
#define KE_WARNING(format, ...) KE_DEBUG_PRINT(DEBUG_LEVEL_WARNING, "[WARN] " format, ##__VA_ARGS__)
#define KE_INFO(format, ...)    KE_DEBUG_PRINT(DEBUG_LEVEL_INFO, "[INFO] " format, ##__VA_ARGS__)
#define KE_VERBOSE(format, ...) KE_DEBUG_PRINT(DEBUG_LEVEL_VERBOSE, "[VERBOSE] " format, ##__VA_ARGS__)
