#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <cstdint>
#endif

#include "constants.h"

//
// KernelEye Anti-Cheat System - Shared Data Structures
//

#pragma pack(push, 1)

// Version structure
typedef struct _KERNELEYE_VERSION {
    UINT32 Major;
    UINT32 Minor;
    UINT32 Patch;
    UINT32 Build;
} KERNELEYE_VERSION, *PKERNELEYE_VERSION;

// Process information
typedef struct _KERNELEYE_PROCESS_INFO {
    UINT64 ProcessId;
    UINT64 ParentProcessId;
    UINT64 CreationTime;
    WCHAR ProcessName[MAX_PROCESS_NAME_LENGTH];
    WCHAR ImagePath[MAX_PATH_LENGTH];
    UINT32 ThreadCount;
    UINT32 HandleCount;
    UINT64 VirtualSize;
    UINT64 WorkingSetSize;
} KERNELEYE_PROCESS_INFO, *PKERNELEYE_PROCESS_INFO;

// Module information
typedef struct _KERNELEYE_MODULE_INFO {
    UINT64 BaseAddress;
    UINT64 Size;
    UINT64 EntryPoint;
    WCHAR ModuleName[MAX_MODULE_NAME_LENGTH];
    WCHAR ModulePath[MAX_PATH_LENGTH];
    UINT32 TimeDateStamp;
    UINT32 Checksum;
    BOOLEAN IsSigned;
} KERNELEYE_MODULE_INFO, *PKERNELEYE_MODULE_INFO;

// Memory region information
typedef struct _KERNELEYE_MEMORY_REGION {
    UINT64 BaseAddress;
    UINT64 Size;
    UINT32 Protection;
    UINT32 State;
    UINT32 Type;
    BOOLEAN IsSuspicious;
    UINT32 SuspicionFlags;
} KERNELEYE_MEMORY_REGION, *PKERNELEYE_MEMORY_REGION;

// Hook detection result
typedef struct _KERNELEYE_HOOK_DETECTION {
    UINT64 TargetAddress;
    UINT64 HookAddress;
    UINT32 HookType;          // Inline, IAT, EAT, etc.
    WCHAR TargetFunction[256];
    WCHAR TargetModule[MAX_MODULE_NAME_LENGTH];
    WCHAR HookModule[MAX_MODULE_NAME_LENGTH];
    UINT32 ThreatLevel;
} KERNELEYE_HOOK_DETECTION, *PKERNELEYE_HOOK_DETECTION;

// Driver information
typedef struct _KERNELEYE_DRIVER_INFO {
    UINT64 BaseAddress;
    UINT64 Size;
    UINT64 EntryPoint;
    WCHAR DriverName[MAX_DRIVER_NAME_LENGTH];
    WCHAR DriverPath[MAX_PATH_LENGTH];
    BOOLEAN IsSigned;
    BOOLEAN IsManuallyMapped;
    UINT32 ThreatLevel;
} KERNELEYE_DRIVER_INFO, *PKERNELEYE_DRIVER_INFO;

// Detection report
typedef struct _KERNELEYE_DETECTION_REPORT {
    UINT64 Timestamp;
    UINT32 DetectionType;
    UINT32 ThreatLevel;
    UINT64 ProcessId;
    WCHAR ProcessName[MAX_PROCESS_NAME_LENGTH];
    WCHAR Description[512];
    UINT64 Address;
    UINT64 Size;
    UINT32 AdditionalDataSize;
    BYTE AdditionalData[1];   // Variable size
} KERNELEYE_DETECTION_REPORT, *PKERNELEYE_DETECTION_REPORT;

// Scan request
typedef struct _KERNELEYE_SCAN_REQUEST {
    UINT64 ProcessId;
    UINT32 ScanFlags;
    UINT32 Timeout;
    UINT64 Context;
} KERNELEYE_SCAN_REQUEST, *PKERNELEYE_SCAN_REQUEST;

// Scan result
typedef struct _KERNELEYE_SCAN_RESULT {
    UINT64 Context;
    UINT32 Status;
    UINT32 DetectionCount;
    UINT32 ScanDuration;      // milliseconds
    UINT32 TotalChecks;
    UINT32 ResultDataSize;
    BYTE ResultData[1];       // Variable size
} KERNELEYE_SCAN_RESULT, *PKERNELEYE_SCAN_RESULT;

// Protection request
typedef struct _KERNELEYE_PROTECTION_REQUEST {
    UINT64 ProcessId;
    UINT32 ProtectionFlags;
    BOOLEAN Enable;
} KERNELEYE_PROTECTION_REQUEST, *PKERNELEYE_PROTECTION_REQUEST;

// Heartbeat message
typedef struct _KERNELEYE_HEARTBEAT {
    UINT64 Timestamp;
    UINT64 ProcessId;
    UINT32 SequenceNumber;
    UINT32 Status;
} KERNELEYE_HEARTBEAT, *PKERNELEYE_HEARTBEAT;

// Statistics
typedef struct _KERNELEYE_STATISTICS {
    UINT64 TotalScans;
    UINT64 TotalDetections;
    UINT64 TotalProcessesProtected;
    UINT64 UptimeSeconds;
    UINT32 ActiveScans;
    UINT32 QueuedRequests;
    UINT64 MemoryUsage;
    UINT32 CpuUsagePercent;
} KERNELEYE_STATISTICS, *PKERNELEYE_STATISTICS;

// Configuration
typedef struct _KERNELEYE_CONFIG {
    UINT32 ScanIntervalCritical;
    UINT32 ScanIntervalStandard;
    UINT32 ScanIntervalDeep;
    UINT32 HeartbeatInterval;
    UINT32 DebugLevel;
    BOOLEAN EnableSelfProtection;
    BOOLEAN EnableBehavioralAnalysis;
    BOOLEAN EnableMachineLearning;
    UINT32 MaxCpuUsagePercent;
    UINT32 MaxMemoryUsageMB;
} KERNELEYE_CONFIG, *PKERNELEYE_CONFIG;

#pragma pack(pop)

// Detection types
typedef enum _DETECTION_TYPE {
    DETECTION_TYPE_MEMORY_MANIPULATION = 1,
    DETECTION_TYPE_CODE_INJECTION,
    DETECTION_TYPE_HOOK_DETECTED,
    DETECTION_TYPE_DRIVER_SUSPICIOUS,
    DETECTION_TYPE_PROCESS_MANIPULATION,
    DETECTION_TYPE_THREAD_INJECTION,
    DETECTION_TYPE_KERNEL_MODIFICATION,
    DETECTION_TYPE_HARDWARE_TAMPERING,
    DETECTION_TYPE_BEHAVIORAL_ANOMALY,
    DETECTION_TYPE_DEBUGGER_DETECTED,
    DETECTION_TYPE_HYPERVISOR_DETECTED,
    DETECTION_TYPE_DMA_ATTACK,
    DETECTION_TYPE_UNKNOWN = 0xFFFF
} DETECTION_TYPE;

// Hook types
typedef enum _HOOK_TYPE {
    HOOK_TYPE_INLINE = 1,
    HOOK_TYPE_IAT,
    HOOK_TYPE_EAT,
    HOOK_TYPE_VMT,
    HOOK_TYPE_SSDT,
    HOOK_TYPE_SHADOW_SSDT,
    HOOK_TYPE_IDT,
    HOOK_TYPE_GDT,
    HOOK_TYPE_MSR,
    HOOK_TYPE_CALLBACK,
    HOOK_TYPE_HARDWARE_BREAKPOINT,
    HOOK_TYPE_UNKNOWN = 0xFFFF
} HOOK_TYPE;

// Memory suspicion flags
typedef enum _MEMORY_SUSPICION_FLAGS {
    MEM_SUSPICION_RWX_PAGES         = 0x00000001,
    MEM_SUSPICION_HIDDEN_REGION     = 0x00000002,
    MEM_SUSPICION_MODIFIED_CODE     = 0x00000004,
    MEM_SUSPICION_UNMAPPED_EXEC     = 0x00000008,
    MEM_SUSPICION_ORPHANED_SECTION  = 0x00000010,
    MEM_SUSPICION_INVALID_PE        = 0x00000020,
} MEMORY_SUSPICION_FLAGS;
