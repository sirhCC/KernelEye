#pragma once

#include <ntddk.h>
#include "../../../Common/constants.h"
#include "../../../Common/structures.h"

//
// KernelEye Driver - Process Monitor
// Monitors process/thread creation, handle operations, and image loading
//

// Protected process entry
typedef struct _PROTECTED_PROCESS_ENTRY {
    LIST_ENTRY ListEntry;
    UINT64 ProcessId;
    PEPROCESS Process;
    UINT32 ProtectionFlags;
    LARGE_INTEGER ProtectionStartTime;
    UINT32 ViolationCount;
} PROTECTED_PROCESS_ENTRY, *PPROTECTED_PROCESS_ENTRY;

// Process event entry
typedef struct _PROCESS_EVENT_ENTRY {
    LIST_ENTRY ListEntry;
    UINT64 ProcessId;
    UINT64 ParentProcessId;
    UINT64 Timestamp;
    BOOLEAN IsCreate;
    WCHAR ImageFileName[MAX_PROCESS_NAME_LENGTH];
} PROCESS_EVENT_ENTRY, *PPROCESS_EVENT_ENTRY;

// Thread event entry
typedef struct _THREAD_EVENT_ENTRY {
    LIST_ENTRY ListEntry;
    UINT64 ThreadId;
    UINT64 ProcessId;
    UINT64 Timestamp;
    BOOLEAN IsCreate;
    PVOID StartAddress;
} THREAD_EVENT_ENTRY, *PTHREAD_EVENT_ENTRY;

// Image load event
typedef struct _IMAGE_LOAD_EVENT {
    LIST_ENTRY ListEntry;
    UINT64 ProcessId;
    UINT64 ImageBase;
    SIZE_T ImageSize;
    UINT64 Timestamp;
    WCHAR ImageFileName[MAX_PATH_LENGTH];
} IMAGE_LOAD_EVENT, *PIMAGE_LOAD_EVENT;

// Handle operation event
typedef struct _HANDLE_OPERATION_EVENT {
    LIST_ENTRY ListEntry;
    UINT64 CallerProcessId;
    UINT64 TargetProcessId;
    UINT64 Timestamp;
    UINT32 DesiredAccess;
    BOOLEAN WasBlocked;
} HANDLE_OPERATION_EVENT, *PHANDLE_OPERATION_EVENT;

// Global monitor state
typedef struct _PROCESS_MONITOR_STATE {
    BOOLEAN Initialized;
    BOOLEAN CallbacksRegistered;
    
    // Protected processes
    LIST_ENTRY ProtectedProcessList;
    KSPIN_LOCK ProtectedProcessLock;
    UINT32 ProtectedProcessCount;
    
    // Event tracking
    LIST_ENTRY ProcessEventList;
    LIST_ENTRY ThreadEventList;
    LIST_ENTRY ImageLoadEventList;
    LIST_ENTRY HandleOperationList;
    KSPIN_LOCK EventLock;
    
    // Callbacks
    PVOID ProcessNotifyHandle;
    PVOID ThreadNotifyHandle;
    PVOID ImageNotifyHandle;
    PVOID ObjectCallbackHandle;
    
    // Statistics
    UINT64 ProcessCreations;
    UINT64 ProcessTerminations;
    UINT64 ThreadCreations;
    UINT64 ThreadTerminations;
    UINT64 ImageLoads;
    UINT64 HandleOperationsBlocked;
    
} PROCESS_MONITOR_STATE, *PPROCESS_MONITOR_STATE;

// Initialization and cleanup
NTSTATUS ProcessMonitorInitialize(VOID);
VOID ProcessMonitorCleanup(VOID);

// Protection management
NTSTATUS ProtectProcess(
    _In_ UINT64 ProcessId,
    _In_ UINT32 ProtectionFlags
);

NTSTATUS UnprotectProcess(
    _In_ UINT64 ProcessId
);

PPROTECTED_PROCESS_ENTRY FindProtectedProcess(
    _In_ UINT64 ProcessId
);

BOOLEAN IsProcessProtected(
    _In_ UINT64 ProcessId
);

// Callback registration
NTSTATUS RegisterProcessCallbacks(VOID);
NTSTATUS RegisterThreadCallbacks(VOID);
NTSTATUS RegisterImageCallbacks(VOID);
NTSTATUS RegisterHandleCallbacks(VOID);

VOID UnregisterAllCallbacks(VOID);

// Callback handlers
VOID ProcessNotifyCallback(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
);

VOID ThreadNotifyCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
);

VOID ImageLoadNotifyCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
);

OB_PREOP_CALLBACK_STATUS ObjectPreCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION OperationInformation
);

VOID ObjectPostCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_POST_OPERATION_INFORMATION OperationInformation
);

// Event tracking
NTSTATUS AddProcessEvent(
    _In_ UINT64 ProcessId,
    _In_ UINT64 ParentProcessId,
    _In_ BOOLEAN IsCreate,
    _In_ PCWSTR ImageFileName
);

NTSTATUS AddThreadEvent(
    _In_ UINT64 ThreadId,
    _In_ UINT64 ProcessId,
    _In_ BOOLEAN IsCreate,
    _In_ PVOID StartAddress
);

NTSTATUS AddImageLoadEvent(
    _In_ UINT64 ProcessId,
    _In_ UINT64 ImageBase,
    _In_ SIZE_T ImageSize,
    _In_ PCWSTR ImageFileName
);

NTSTATUS AddHandleOperationEvent(
    _In_ UINT64 CallerProcessId,
    _In_ UINT64 TargetProcessId,
    _In_ UINT32 DesiredAccess,
    _In_ BOOLEAN WasBlocked
);

// Event cleanup
VOID CleanupOldEvents(VOID);
VOID ClearAllEvents(VOID);

// Suspicious activity detection
BOOLEAN IsProcessCreationSuspicious(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId
);

BOOLEAN IsThreadCreationSuspicious(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ PVOID StartAddress
);

BOOLEAN IsImageLoadSuspicious(
    _In_ HANDLE ProcessId,
    _In_ PUNICODE_STRING ImageName,
    _In_ PIMAGE_INFO ImageInfo
);

BOOLEAN IsHandleOperationSuspicious(
    _In_ UINT64 CallerProcessId,
    _In_ UINT64 TargetProcessId,
    _In_ UINT32 DesiredAccess
);

// Statistics
NTSTATUS GetProcessMonitorStatistics(
    _Out_ PUINT64 ProcessCreations,
    _Out_ PUINT64 ProcessTerminations,
    _Out_ PUINT64 ThreadCreations,
    _Out_ PUINT64 ThreadTerminations,
    _Out_ PUINT64 ImageLoads,
    _Out_ PUINT64 HandleOperationsBlocked
);

// Helper functions
NTSTATUS GetProcessImageName(
    _In_ PEPROCESS Process,
    _Out_ PWCHAR ImageName,
    _In_ UINT32 ImageNameLength
);

BOOLEAN IsSystemProcess(
    _In_ UINT64 ProcessId
);

BOOLEAN IsProtectedHandleOperation(
    _In_ UINT32 DesiredAccess
);
