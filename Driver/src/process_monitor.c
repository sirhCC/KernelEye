//
// KernelEye Anti-Cheat Driver - Process Monitor
// Monitors and protects processes from tampering
//

#include "../include/driver.h"
#include "../include/process_monitor.h"

// Global state
static PROCESS_MONITOR_STATE g_MonitorState = {0};

//
// ProcessMonitorInitialize
//
NTSTATUS ProcessMonitorInitialize(VOID)
{
    NTSTATUS status;

    if (g_MonitorState.Initialized) {
        KE_WARNING("Process monitor already initialized");
        return STATUS_SUCCESS;
    }

    KE_INFO("Initializing process monitor...");

    RtlZeroMemory(&g_MonitorState, sizeof(PROCESS_MONITOR_STATE));
    
    InitializeListHead(&g_MonitorState.ProtectedProcessList);
    InitializeListHead(&g_MonitorState.ProcessEventList);
    InitializeListHead(&g_MonitorState.ThreadEventList);
    InitializeListHead(&g_MonitorState.ImageLoadEventList);
    InitializeListHead(&g_MonitorState.HandleOperationList);
    
    KeInitializeSpinLock(&g_MonitorState.ProtectedProcessLock);
    KeInitializeSpinLock(&g_MonitorState.EventLock);

    status = RegisterProcessCallbacks();
    if (!NT_SUCCESS(status)) {
        KE_ERROR("Failed to register process callbacks: 0x%08X", status);
        return status;
    }

    status = RegisterThreadCallbacks();
    if (!NT_SUCCESS(status)) {
        KE_ERROR("Failed to register thread callbacks: 0x%08X", status);
        UnregisterAllCallbacks();
        return status;
    }

    status = RegisterImageCallbacks();
    if (!NT_SUCCESS(status)) {
        KE_ERROR("Failed to register image callbacks: 0x%08X", status);
        UnregisterAllCallbacks();
        return status;
    }

    status = RegisterHandleCallbacks();
    if (!NT_SUCCESS(status)) {
        KE_WARNING("Failed to register handle callbacks: 0x%08X (continuing anyway)", status);
    }

    g_MonitorState.Initialized = TRUE;
    g_MonitorState.CallbacksRegistered = TRUE;

    KE_INFO("Process monitor initialized successfully");
    return STATUS_SUCCESS;
}

//
// ProcessMonitorCleanup
//
VOID ProcessMonitorCleanup(VOID)
{
    PLIST_ENTRY entry;
    PPROTECTED_PROCESS_ENTRY protectedEntry;

    if (!g_MonitorState.Initialized) {
        return;
    }

    KE_INFO("Cleaning up process monitor...");

    UnregisterAllCallbacks();

    while (!IsListEmpty(&g_MonitorState.ProtectedProcessList)) {
        entry = RemoveHeadList(&g_MonitorState.ProtectedProcessList);
        protectedEntry = CONTAINING_RECORD(entry, PROTECTED_PROCESS_ENTRY, ListEntry);
        
        if (protectedEntry->Process) {
            ObDereferenceObject(protectedEntry->Process);
        }
        
        ExFreePoolWithTag(protectedEntry, KERNELEYE_POOL_TAG);
    }

    ClearAllEvents();

    g_MonitorState.Initialized = FALSE;
    KE_INFO("Process monitor cleaned up");
}

//
// ProtectProcess
//
NTSTATUS ProtectProcess(
    _In_ UINT64 ProcessId,
    _In_ UINT32 ProtectionFlags
)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PPROTECTED_PROCESS_ENTRY entry;
    KIRQL oldIrql;

    KE_INFO("Protecting process PID=%llu with flags=0x%08X", ProcessId, ProtectionFlags);

    status = PsLookupProcessByProcessId((HANDLE)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        KE_ERROR("Failed to lookup process: 0x%08X", status);
        return status;
    }

    entry = (PPROTECTED_PROCESS_ENTRY)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(PROTECTED_PROCESS_ENTRY),
        KERNELEYE_POOL_TAG
    );

    if (!entry) {
        ObDereferenceObject(process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(entry, sizeof(PROTECTED_PROCESS_ENTRY));
    entry->ProcessId = ProcessId;
    entry->Process = process;
    entry->ProtectionFlags = ProtectionFlags;
    KeQuerySystemTime(&entry->ProtectionStartTime);

    KeAcquireSpinLock(&g_MonitorState.ProtectedProcessLock, &oldIrql);
    InsertTailList(&g_MonitorState.ProtectedProcessList, &entry->ListEntry);
    g_MonitorState.ProtectedProcessCount++;
    KeReleaseSpinLock(&g_MonitorState.ProtectedProcessLock, oldIrql);

    KE_INFO("Process protected successfully");
    return STATUS_SUCCESS;
}

//
// UnprotectProcess
//
NTSTATUS UnprotectProcess(
    _In_ UINT64 ProcessId
)
{
    PPROTECTED_PROCESS_ENTRY entry;
    KIRQL oldIrql;

    KE_INFO("Unprotecting process PID=%llu", ProcessId);

    KeAcquireSpinLock(&g_MonitorState.ProtectedProcessLock, &oldIrql);
    
    entry = FindProtectedProcess(ProcessId);
    if (entry) {
        RemoveEntryList(&entry->ListEntry);
        g_MonitorState.ProtectedProcessCount--;
        KeReleaseSpinLock(&g_MonitorState.ProtectedProcessLock, oldIrql);
        
        if (entry->Process) {
            ObDereferenceObject(entry->Process);
        }
        
        ExFreePoolWithTag(entry, KERNELEYE_POOL_TAG);
        
        KE_INFO("Process unprotected successfully");
        return STATUS_SUCCESS;
    }
    
    KeReleaseSpinLock(&g_MonitorState.ProtectedProcessLock, oldIrql);
    
    KE_WARNING("Process not found in protected list");
    return STATUS_NOT_FOUND;
}

//
// FindProtectedProcess
//
PPROTECTED_PROCESS_ENTRY FindProtectedProcess(
    _In_ UINT64 ProcessId
)
{
    PLIST_ENTRY entry;
    PPROTECTED_PROCESS_ENTRY protectedEntry;

    for (entry = g_MonitorState.ProtectedProcessList.Flink;
         entry != &g_MonitorState.ProtectedProcessList;
         entry = entry->Flink)
    {
        protectedEntry = CONTAINING_RECORD(entry, PROTECTED_PROCESS_ENTRY, ListEntry);
        if (protectedEntry->ProcessId == ProcessId) {
            return protectedEntry;
        }
    }

    return NULL;
}

//
// IsProcessProtected
//
BOOLEAN IsProcessProtected(
    _In_ UINT64 ProcessId
)
{
    KIRQL oldIrql;
    BOOLEAN isProtected;

    KeAcquireSpinLock(&g_MonitorState.ProtectedProcessLock, &oldIrql);
    isProtected = (FindProtectedProcess(ProcessId) != NULL);
    KeReleaseSpinLock(&g_MonitorState.ProtectedProcessLock, oldIrql);

    return isProtected;
}

//
// RegisterProcessCallbacks
//
NTSTATUS RegisterProcessCallbacks(VOID)
{
    NTSTATUS status;

    status = PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        KE_ERROR("Failed to register process notify routine: 0x%08X", status);
        return status;
    }

    g_MonitorState.ProcessNotifyHandle = (PVOID)1;
    KE_VERBOSE("Process callbacks registered");
    
    return STATUS_SUCCESS;
}

//
// RegisterThreadCallbacks
//
NTSTATUS RegisterThreadCallbacks(VOID)
{
    NTSTATUS status;

    status = PsSetCreateThreadNotifyRoutine(ThreadNotifyCallback);
    if (!NT_SUCCESS(status)) {
        KE_ERROR("Failed to register thread notify routine: 0x%08X", status);
        return status;
    }

    g_MonitorState.ThreadNotifyHandle = (PVOID)1;
    KE_VERBOSE("Thread callbacks registered");
    
    return STATUS_SUCCESS;
}

//
// RegisterImageCallbacks
//
NTSTATUS RegisterImageCallbacks(VOID)
{
    NTSTATUS status;

    status = PsSetLoadImageNotifyRoutine(ImageLoadNotifyCallback);
    if (!NT_SUCCESS(status)) {
        KE_ERROR("Failed to register image notify routine: 0x%08X", status);
        return status;
    }

    g_MonitorState.ImageNotifyHandle = (PVOID)1;
    KE_VERBOSE("Image callbacks registered");
    
    return STATUS_SUCCESS;
}

//
// RegisterHandleCallbacks
//
NTSTATUS RegisterHandleCallbacks(VOID)
{
    OB_OPERATION_REGISTRATION opReg[2];
    OB_CALLBACK_REGISTRATION callbackReg;
    UNICODE_STRING altitude;
    NTSTATUS status;

    RtlInitUnicodeString(&altitude, L"385200");

    RtlZeroMemory(&opReg, sizeof(opReg));
    
    opReg[0].ObjectType = PsProcessType;
    opReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg[0].PreOperation = ObjectPreCallback;
    opReg[0].PostOperation = ObjectPostCallback;

    opReg[1].ObjectType = PsThreadType;
    opReg[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg[1].PreOperation = ObjectPreCallback;
    opReg[1].PostOperation = ObjectPostCallback;

    callbackReg.Version = OB_FLT_REGISTRATION_VERSION;
    callbackReg.OperationRegistrationCount = 2;
    callbackReg.Altitude = altitude;
    callbackReg.RegistrationContext = NULL;
    callbackReg.OperationRegistration = opReg;

    status = ObRegisterCallbacks(&callbackReg, &g_MonitorState.ObjectCallbackHandle);
    if (!NT_SUCCESS(status)) {
        KE_ERROR("Failed to register object callbacks: 0x%08X", status);
        return status;
    }

    KE_VERBOSE("Handle callbacks registered");
    return STATUS_SUCCESS;
}

//
// UnregisterAllCallbacks
//
VOID UnregisterAllCallbacks(VOID)
{
    if (g_MonitorState.ProcessNotifyHandle) {
        PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, TRUE);
        g_MonitorState.ProcessNotifyHandle = NULL;
    }

    if (g_MonitorState.ThreadNotifyHandle) {
        PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
        g_MonitorState.ThreadNotifyHandle = NULL;
    }

    if (g_MonitorState.ImageNotifyHandle) {
        PsRemoveLoadImageNotifyRoutine(ImageLoadNotifyCallback);
        g_MonitorState.ImageNotifyHandle = NULL;
    }

    if (g_MonitorState.ObjectCallbackHandle) {
        ObUnRegisterCallbacks(g_MonitorState.ObjectCallbackHandle);
        g_MonitorState.ObjectCallbackHandle = NULL;
    }

    g_MonitorState.CallbacksRegistered = FALSE;
}

//
// ProcessNotifyCallback
//
VOID ProcessNotifyCallback(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
)
{
    if (Create) {
        g_MonitorState.ProcessCreations++;
        KE_VERBOSE("Process created: PID=%llu, Parent=%llu", 
            (UINT64)ProcessId, (UINT64)ParentId);
        
        if (IsProcessCreationSuspicious(ParentId, ProcessId)) {
            KE_WARNING("Suspicious process creation detected: PID=%llu", (UINT64)ProcessId);
        }
    } else {
        g_MonitorState.ProcessTerminations++;
        KE_VERBOSE("Process terminated: PID=%llu", (UINT64)ProcessId);
    }

    AddProcessEvent((UINT64)ProcessId, (UINT64)ParentId, Create, L"Unknown");
}

//
// ThreadNotifyCallback
//
VOID ThreadNotifyCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
)
{
    if (Create) {
        g_MonitorState.ThreadCreations++;
        KE_VERBOSE("Thread created: TID=%llu, PID=%llu", 
            (UINT64)ThreadId, (UINT64)ProcessId);
    } else {
        g_MonitorState.ThreadTerminations++;
        KE_VERBOSE("Thread terminated: TID=%llu", (UINT64)ThreadId);
    }

    AddThreadEvent((UINT64)ThreadId, (UINT64)ProcessId, Create, NULL);
}

//
// ImageLoadNotifyCallback
//
VOID ImageLoadNotifyCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
)
{
    g_MonitorState.ImageLoads++;

    if (FullImageName) {
        KE_VERBOSE("Image loaded: %wZ in PID=%llu", FullImageName, (UINT64)ProcessId);
        
        if (IsImageLoadSuspicious(ProcessId, FullImageName, ImageInfo)) {
            KE_WARNING("Suspicious image load: %wZ", FullImageName);
        }

        AddImageLoadEvent(
            (UINT64)ProcessId,
            (UINT64)ImageInfo->ImageBase,
            ImageInfo->ImageSize,
            FullImageName->Buffer
        );
    }
}

//
// ObjectPreCallback
//
OB_PREOP_CALLBACK_STATUS ObjectPreCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    UINT64 targetPid;
    UINT64 callerPid;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->ObjectType == *PsProcessType) {
        targetPid = (UINT64)PsGetProcessId((PEPROCESS)OperationInformation->Object);
        callerPid = (UINT64)PsGetCurrentProcessId();

        if (IsProcessProtected(targetPid)) {
            if (IsProtectedHandleOperation(OperationInformation->Parameters->CreateHandleInformation.DesiredAccess)) {
                KE_WARNING("Blocking handle operation on protected process: Caller=%llu, Target=%llu, Access=0x%08X",
                    callerPid, targetPid, OperationInformation->Parameters->CreateHandleInformation.DesiredAccess);

                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
                g_MonitorState.HandleOperationsBlocked++;

                AddHandleOperationEvent(
                    callerPid,
                    targetPid,
                    OperationInformation->Parameters->CreateHandleInformation.DesiredAccess,
                    TRUE
                );
            }
        }
    }

    return OB_PREOP_SUCCESS;
}

//
// ObjectPostCallback
//
VOID ObjectPostCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_POST_OPERATION_INFORMATION OperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    UNREFERENCED_PARAMETER(OperationInformation);
}

//
// Event tracking functions (simplified implementations)
//

NTSTATUS AddProcessEvent(
    _In_ UINT64 ProcessId,
    _In_ UINT64 ParentProcessId,
    _In_ BOOLEAN IsCreate,
    _In_ PCWSTR ImageFileName
)
{
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ParentProcessId);
    UNREFERENCED_PARAMETER(IsCreate);
    UNREFERENCED_PARAMETER(ImageFileName);
    return STATUS_SUCCESS;
}

NTSTATUS AddThreadEvent(
    _In_ UINT64 ThreadId,
    _In_ UINT64 ProcessId,
    _In_ BOOLEAN IsCreate,
    _In_ PVOID StartAddress
)
{
    UNREFERENCED_PARAMETER(ThreadId);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(IsCreate);
    UNREFERENCED_PARAMETER(StartAddress);
    return STATUS_SUCCESS;
}

NTSTATUS AddImageLoadEvent(
    _In_ UINT64 ProcessId,
    _In_ UINT64 ImageBase,
    _In_ SIZE_T ImageSize,
    _In_ PCWSTR ImageFileName
)
{
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ImageBase);
    UNREFERENCED_PARAMETER(ImageSize);
    UNREFERENCED_PARAMETER(ImageFileName);
    return STATUS_SUCCESS;
}

NTSTATUS AddHandleOperationEvent(
    _In_ UINT64 CallerProcessId,
    _In_ UINT64 TargetProcessId,
    _In_ UINT32 DesiredAccess,
    _In_ BOOLEAN WasBlocked
)
{
    UNREFERENCED_PARAMETER(CallerProcessId);
    UNREFERENCED_PARAMETER(TargetProcessId);
    UNREFERENCED_PARAMETER(DesiredAccess);
    UNREFERENCED_PARAMETER(WasBlocked);
    return STATUS_SUCCESS;
}

VOID ClearAllEvents(VOID)
{
    // TODO: Clear all event lists
}

//
// Suspicious activity detection
//

BOOLEAN IsProcessCreationSuspicious(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId
)
{
    UNREFERENCED_PARAMETER(ParentId);
    UNREFERENCED_PARAMETER(ProcessId);
    return FALSE;
}

BOOLEAN IsThreadCreationSuspicious(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ PVOID StartAddress
)
{
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ThreadId);
    UNREFERENCED_PARAMETER(StartAddress);
    return FALSE;
}

BOOLEAN IsImageLoadSuspicious(
    _In_ HANDLE ProcessId,
    _In_ PUNICODE_STRING ImageName,
    _In_ PIMAGE_INFO ImageInfo
)
{
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ImageName);
    UNREFERENCED_PARAMETER(ImageInfo);
    return FALSE;
}

BOOLEAN IsHandleOperationSuspicious(
    _In_ UINT64 CallerProcessId,
    _In_ UINT64 TargetProcessId,
    _In_ UINT32 DesiredAccess
)
{
    UNREFERENCED_PARAMETER(CallerProcessId);
    UNREFERENCED_PARAMETER(TargetProcessId);
    UNREFERENCED_PARAMETER(DesiredAccess);
    return FALSE;
}

//
// Statistics
//
NTSTATUS GetProcessMonitorStatistics(
    _Out_ PUINT64 ProcessCreations,
    _Out_ PUINT64 ProcessTerminations,
    _Out_ PUINT64 ThreadCreations,
    _Out_ PUINT64 ThreadTerminations,
    _Out_ PUINT64 ImageLoads,
    _Out_ PUINT64 HandleOperationsBlocked
)
{
    *ProcessCreations = g_MonitorState.ProcessCreations;
    *ProcessTerminations = g_MonitorState.ProcessTerminations;
    *ThreadCreations = g_MonitorState.ThreadCreations;
    *ThreadTerminations = g_MonitorState.ThreadTerminations;
    *ImageLoads = g_MonitorState.ImageLoads;
    *HandleOperationsBlocked = g_MonitorState.HandleOperationsBlocked;

    return STATUS_SUCCESS;
}

//
// Helper functions
//

BOOLEAN IsSystemProcess(
    _In_ UINT64 ProcessId
)
{
    return (ProcessId <= 4);
}

BOOLEAN IsProtectedHandleOperation(
    _In_ UINT32 DesiredAccess
)
{
    return (DesiredAccess & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | 
                             PROCESS_CREATE_THREAD | PROCESS_TERMINATE));
}
