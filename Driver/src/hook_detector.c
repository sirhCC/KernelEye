//
// KernelEye Anti-Cheat Driver - Hook Detector
// Detects inline hooks, IAT/EAT hooks, SSDT hooks, and suspicious callbacks
//

#include "../include/driver.h"
#include "../include/hook_detector.h"

// Global state
static BOOLEAN g_HookDetectorInitialized = FALSE;

// Known hook patterns
INLINE_HOOK_PATTERN g_InlineHookPatterns[] = {
    // JMP rel32: E9 xx xx xx xx
    { {0xE9, 0x00, 0x00, 0x00, 0x00}, {0xFF, 0x00, 0x00, 0x00, 0x00}, 5, HOOK_PATTERN_JMP_REL32, "JMP rel32" },
    
    // JMP [rip+offset]: FF 25 xx xx xx xx
    { {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00}, {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00}, 6, HOOK_PATTERN_JMP_ABS, "JMP [rip+offset]" },
    
    // CALL rel32: E8 xx xx xx xx
    { {0xE8, 0x00, 0x00, 0x00, 0x00}, {0xFF, 0x00, 0x00, 0x00, 0x00}, 5, HOOK_PATTERN_CALL_REL32, "CALL rel32" },
    
    // PUSH addr + RET: 68 xx xx xx xx C3
    { {0x68, 0x00, 0x00, 0x00, 0x00, 0xC3}, {0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF}, 6, HOOK_PATTERN_PUSH_RET, "PUSH+RET" },
    
    // MOV RAX, addr + JMP RAX: 48 B8 ... FF E0
    { {0x48, 0xB8}, {0xFF, 0xFF}, 2, HOOK_PATTERN_MOV_RAX_JMP, "MOV RAX+JMP" }
};

UINT32 g_InlineHookPatternCount = sizeof(g_InlineHookPatterns) / sizeof(INLINE_HOOK_PATTERN);

//
// HookDetectorInitialize
//
NTSTATUS HookDetectorInitialize(VOID)
{
    if (g_HookDetectorInitialized) {
        KE_WARNING("Hook detector already initialized");
        return STATUS_SUCCESS;
    }

    KE_INFO("Initializing hook detector...");

    // TODO: Build function database
    // TODO: Load known good function signatures
    
    g_HookDetectorInitialized = TRUE;
    KE_INFO("Hook detector initialized successfully");

    return STATUS_SUCCESS;
}

//
// HookDetectorCleanup
//
VOID HookDetectorCleanup(VOID)
{
    if (!g_HookDetectorInitialized) {
        return;
    }

    KE_INFO("Cleaning up hook detector...");

    // TODO: Free function database
    
    g_HookDetectorInitialized = FALSE;
    KE_INFO("Hook detector cleaned up");
}

//
// ScanProcessHooks
//
NTSTATUS ScanProcessHooks(
    _In_ UINT64 ProcessId,
    _In_ UINT32 ScanFlags,
    _Out_ PHOOK_SCAN_CONTEXT* ScanContext
)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PHOOK_SCAN_CONTEXT context = NULL;

    KE_INFO("Scanning process hooks: PID=%llu, Flags=0x%08X", ProcessId, ScanFlags);

    if (!g_HookDetectorInitialized) {
        KE_ERROR("Hook detector not initialized");
        return STATUS_UNSUCCESSFUL;
    }

    status = PsLookupProcessByProcessId((HANDLE)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        KE_ERROR("Failed to lookup process %llu: 0x%08X", ProcessId, status);
        return status;
    }

    context = (PHOOK_SCAN_CONTEXT)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(HOOK_SCAN_CONTEXT),
        SCAN_BUFFER_TAG
    );

    if (!context) {
        KE_ERROR("Failed to allocate hook scan context");
        ObDereferenceObject(process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(context, sizeof(HOOK_SCAN_CONTEXT));
    context->TargetProcess = process;
    context->ProcessId = ProcessId;
    context->ScanFlags = ScanFlags;
    InitializeListHead(&context->HookList);
    KeInitializeSpinLock(&context->HookLock);

    // TODO: Get module list and scan each module
    // For now, just scan kernel hooks if requested
    
    if (ScanFlags & SCAN_FLAG_HOOKS) {
        // Scan SSDT hooks
        ScanSSDTHooks(context);
        
        // Enumerate callbacks
        EnumerateCallbacks(context);
    }

    KE_INFO("Hook scan complete: %u functions checked, %u hooks found",
        context->FunctionsChecked, context->HookCount);

    *ScanContext = context;
    return STATUS_SUCCESS;
}

//
// ScanInlineHooks
//
NTSTATUS ScanInlineHooks(
    _In_ PEPROCESS Process,
    _In_ PVOID ModuleBase,
    _In_ SIZE_T ModuleSize,
    _Inout_ PHOOK_SCAN_CONTEXT Context
)
{
    PVOID* exportAddresses = NULL;
    UINT32 exportCount = 0;
    NTSTATUS status;
    UINT32 i;

    KE_VERBOSE("Scanning inline hooks in module at 0x%p", ModuleBase);

    status = GetModuleExports(Process, ModuleBase, &exportAddresses, &exportCount);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    for (i = 0; i < exportCount; i++) {
        if (exportAddresses[i]) {
            CheckFunctionForInlineHook(
                Process,
                exportAddresses[i],
                "Unknown",
                "Unknown",
                Context
            );
        }
    }

    if (exportAddresses) {
        ExFreePoolWithTag(exportAddresses, SCAN_BUFFER_TAG);
    }

    return STATUS_SUCCESS;
}

//
// CheckFunctionForInlineHook
//
NTSTATUS CheckFunctionForInlineHook(
    _In_ PEPROCESS Process,
    _In_ PVOID FunctionAddress,
    _In_ PCSTR FunctionName,
    _In_ PCSTR ModuleName,
    _Inout_ PHOOK_SCAN_CONTEXT Context
)
{
    UCHAR functionBytes[32];
    SIZE_T bytesRead;
    NTSTATUS status;
    UINT64 hookTarget;
    UINT32 hookType;
    CHAR hookModuleName[MAX_MODULE_NAME_LENGTH];

    Context->FunctionsChecked++;

    status = ReadProcessMemorySafe(
        Process,
        FunctionAddress,
        functionBytes,
        sizeof(functionBytes),
        &bytesRead
    );

    if (!NT_SUCCESS(status) || bytesRead < 16) {
        return status;
    }

    if (IsInlineHookPattern(functionBytes, (UINT32)bytesRead, &hookTarget, &hookType)) {
        ResolveModuleName(hookTarget, hookModuleName, sizeof(hookModuleName));
        
        AddHookDetection(
            Context,
            (UINT64)FunctionAddress,
            hookTarget,
            HOOK_TYPE_INLINE,
            THREAT_LEVEL_HIGH,
            FunctionName,
            ModuleName,
            NULL,
            functionBytes
        );
    }

    return STATUS_SUCCESS;
}

//
// IsInlineHookPattern
//
BOOLEAN IsInlineHookPattern(
    _In_ PUCHAR FunctionBytes,
    _In_ UINT32 Length,
    _Out_ PUINT64 HookTarget,
    _Out_ PUINT32 HookType
)
{
    UINT32 i;
    INT32 relativeOffset;
    UINT64 instructionAddr = 0;

    *HookTarget = 0;
    *HookType = 0;

    for (i = 0; i < g_InlineHookPatternCount; i++) {
        if (Length >= g_InlineHookPatterns[i].PatternLength) {
            if (MatchPattern(
                FunctionBytes,
                g_InlineHookPatterns[i].Pattern,
                g_InlineHookPatterns[i].Mask,
                g_InlineHookPatterns[i].PatternLength))
            {
                *HookType = g_InlineHookPatterns[i].HookType;
                
                switch (*HookType) {
                    case HOOK_PATTERN_JMP_REL32:
                    case HOOK_PATTERN_CALL_REL32:
                        relativeOffset = *(INT32*)(FunctionBytes + 1);
                        *HookTarget = CalculateRelativeTarget(instructionAddr, relativeOffset, 5);
                        return TRUE;
                        
                    case HOOK_PATTERN_JMP_ABS:
                        if (Length >= 14) {
                            *HookTarget = *(UINT64*)(FunctionBytes + 6);
                            return TRUE;
                        }
                        break;
                        
                    case HOOK_PATTERN_PUSH_RET:
                        *HookTarget = *(UINT32*)(FunctionBytes + 1);
                        return TRUE;
                        
                    case HOOK_PATTERN_MOV_RAX_JMP:
                        if (Length >= 12) {
                            *HookTarget = *(UINT64*)(FunctionBytes + 2);
                            return TRUE;
                        }
                        break;
                }
            }
        }
    }

    return FALSE;
}

//
// ScanIATHooks
//
NTSTATUS ScanIATHooks(
    _In_ PEPROCESS Process,
    _In_ PVOID ModuleBase,
    _Inout_ PHOOK_SCAN_CONTEXT Context
)
{
    PIAT_ENTRY entries = NULL;
    UINT32 entryCount = 0;
    NTSTATUS status;
    UINT32 i;
    UINT64 hookAddress;

    status = ParseImportDirectory(Process, ModuleBase, &entries, &entryCount);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    for (i = 0; i < entryCount; i++) {
        if (IsIATEntryHooked(Process, entries[i].FunctionAddress, entries[i].FunctionName, &hookAddress)) {
            AddHookDetection(
                Context,
                entries[i].FunctionAddress,
                hookAddress,
                HOOK_TYPE_IAT,
                THREAT_LEVEL_HIGH,
                entries[i].FunctionName,
                entries[i].ModuleName,
                NULL,
                NULL
            );
        }
    }

    if (entries) {
        ExFreePoolWithTag(entries, SCAN_BUFFER_TAG);
    }

    return STATUS_SUCCESS;
}

//
// ScanEATHooks
//
NTSTATUS ScanEATHooks(
    _In_ PEPROCESS Process,
    _In_ PVOID ModuleBase,
    _Inout_ PHOOK_SCAN_CONTEXT Context
)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ModuleBase);
    UNREFERENCED_PARAMETER(Context);
    
    // TODO: Implement EAT hook detection
    return STATUS_NOT_IMPLEMENTED;
}

//
// ParseImportDirectory
//
NTSTATUS ParseImportDirectory(
    _In_ PEPROCESS Process,
    _In_ PVOID ModuleBase,
    _Out_ PIAT_ENTRY* Entries,
    _Out_ PUINT32 EntryCount
)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ModuleBase);
    
    *Entries = NULL;
    *EntryCount = 0;
    
    // TODO: Parse PE import directory
    return STATUS_NOT_IMPLEMENTED;
}

//
// IsIATEntryHooked
//
BOOLEAN IsIATEntryHooked(
    _In_ PEPROCESS Process,
    _In_ UINT64 IATAddress,
    _In_ PCSTR FunctionName,
    _Out_ PUINT64 HookAddress
)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(IATAddress);
    UNREFERENCED_PARAMETER(FunctionName);
    
    *HookAddress = 0;
    
    // TODO: Verify IAT entry points to expected module
    return FALSE;
}

//
// ScanSSDTHooks
//
NTSTATUS ScanSSDTHooks(
    _Inout_ PHOOK_SCAN_CONTEXT Context
)
{
    PVOID ssdtBase = NULL;
    NTSTATUS status;

    KE_VERBOSE("Scanning SSDT hooks");

    status = GetSSDTBase(&ssdtBase);
    if (!NT_SUCCESS(status)) {
        KE_WARNING("Failed to get SSDT base: 0x%08X", status);
        return status;
    }

    // TODO: Enumerate SSDT entries and check for hooks
    
    return STATUS_SUCCESS;
}

//
// GetSSDTBase
//
NTSTATUS GetSSDTBase(
    _Out_ PVOID* SSDTBase
)
{
    *SSDTBase = NULL;
    
    // TODO: Locate KeServiceDescriptorTable
    // This requires pattern scanning or symbol lookup
    
    return STATUS_NOT_IMPLEMENTED;
}

//
// IsSSDTEntryHooked
//
BOOLEAN IsSSDTEntryHooked(
    _In_ UINT64 ServiceAddress,
    _In_ UINT32 ServiceId,
    _Out_ PUINT64 HookAddress
)
{
    UNREFERENCED_PARAMETER(ServiceAddress);
    UNREFERENCED_PARAMETER(ServiceId);
    
    *HookAddress = 0;
    
    // TODO: Check if service address is outside ntoskrnl range
    return FALSE;
}

//
// EnumerateCallbacks
//
NTSTATUS EnumerateCallbacks(
    _Inout_ PHOOK_SCAN_CONTEXT Context
)
{
    KE_VERBOSE("Enumerating kernel callbacks");

    EnumerateProcessCallbacks(Context);
    EnumerateThreadCallbacks(Context);
    EnumerateImageCallbacks(Context);

    return STATUS_SUCCESS;
}

//
// EnumerateProcessCallbacks
//
NTSTATUS EnumerateProcessCallbacks(
    _Inout_ PHOOK_SCAN_CONTEXT Context
)
{
    UNREFERENCED_PARAMETER(Context);
    
    // TODO: Walk PspCreateProcessNotifyRoutine array
    // Requires knowing offset and structure for Windows version
    
    KE_VERBOSE("Process callbacks enumerated");
    return STATUS_SUCCESS;
}

//
// EnumerateThreadCallbacks
//
NTSTATUS EnumerateThreadCallbacks(
    _Inout_ PHOOK_SCAN_CONTEXT Context
)
{
    UNREFERENCED_PARAMETER(Context);
    
    // TODO: Walk PspCreateThreadNotifyRoutine array
    
    KE_VERBOSE("Thread callbacks enumerated");
    return STATUS_SUCCESS;
}

//
// EnumerateImageCallbacks
//
NTSTATUS EnumerateImageCallbacks(
    _Inout_ PHOOK_SCAN_CONTEXT Context
)
{
    UNREFERENCED_PARAMETER(Context);
    
    // TODO: Walk PspLoadImageNotifyRoutine array
    
    KE_VERBOSE("Image callbacks enumerated");
    return STATUS_SUCCESS;
}

//
// AddHookDetection
//
NTSTATUS AddHookDetection(
    _Inout_ PHOOK_SCAN_CONTEXT Context,
    _In_ UINT64 TargetAddress,
    _In_ UINT64 HookAddress,
    _In_ UINT32 HookType,
    _In_ UINT32 ThreatLevel,
    _In_ PCSTR TargetFunction,
    _In_ PCSTR TargetModule,
    _In_opt_ PUCHAR OriginalBytes,
    _In_opt_ PUCHAR HookedBytes
)
{
    PHOOK_DETECTION_ENTRY entry;
    KIRQL oldIrql;

    entry = (PHOOK_DETECTION_ENTRY)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(HOOK_DETECTION_ENTRY),
        REPORT_BUFFER_TAG
    );

    if (!entry) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(entry, sizeof(HOOK_DETECTION_ENTRY));
    entry->TargetAddress = TargetAddress;
    entry->HookAddress = HookAddress;
    entry->HookType = HookType;
    entry->ThreatLevel = ThreatLevel;
    
    RtlStringCbCopyA(entry->TargetFunction, sizeof(entry->TargetFunction), TargetFunction);
    RtlStringCbCopyA(entry->TargetModule, sizeof(entry->TargetModule), TargetModule);
    
    if (OriginalBytes) {
        RtlCopyMemory(entry->OriginalBytes, OriginalBytes, sizeof(entry->OriginalBytes));
    }
    
    if (HookedBytes) {
        RtlCopyMemory(entry->HookedBytes, HookedBytes, sizeof(entry->HookedBytes));
    }

    KeAcquireSpinLock(&Context->HookLock, &oldIrql);
    InsertTailList(&Context->HookList, &entry->ListEntry);
    Context->HookCount++;
    KeReleaseSpinLock(&Context->HookLock, oldIrql);

    KE_WARNING("Hook detected: %s!%s at 0x%llX -> 0x%llX (Type=%u, Threat=%u)",
        TargetModule, TargetFunction, TargetAddress, HookAddress, HookType, ThreatLevel);

    return STATUS_SUCCESS;
}

//
// FreeHookScanContext
//
VOID FreeHookScanContext(
    _In_ PHOOK_SCAN_CONTEXT Context
)
{
    PLIST_ENTRY entry;
    PHOOK_DETECTION_ENTRY detection;

    if (!Context) {
        return;
    }

    while (!IsListEmpty(&Context->HookList)) {
        entry = RemoveHeadList(&Context->HookList);
        detection = CONTAINING_RECORD(entry, HOOK_DETECTION_ENTRY, ListEntry);
        ExFreePoolWithTag(detection, REPORT_BUFFER_TAG);
    }

    if (Context->TargetProcess) {
        ObDereferenceObject(Context->TargetProcess);
    }

    ExFreePoolWithTag(Context, SCAN_BUFFER_TAG);
}

//
// GetHookScanStatistics
//
NTSTATUS GetHookScanStatistics(
    _In_ PHOOK_SCAN_CONTEXT Context,
    _Out_ PUINT32 FunctionsChecked,
    _Out_ PUINT32 HooksFound
)
{
    if (!Context) {
        return STATUS_INVALID_PARAMETER;
    }

    *FunctionsChecked = Context->FunctionsChecked;
    *HooksFound = Context->HookCount;

    return STATUS_SUCCESS;
}

//
// GetModuleExports
//
NTSTATUS GetModuleExports(
    _In_ PEPROCESS Process,
    _In_ PVOID ModuleBase,
    _Out_ PVOID** ExportAddresses,
    _Out_ PUINT32 ExportCount
)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ModuleBase);
    
    *ExportAddresses = NULL;
    *ExportCount = 0;
    
    // TODO: Parse PE export directory
    return STATUS_NOT_IMPLEMENTED;
}

//
// ResolveModuleName
//
NTSTATUS ResolveModuleName(
    _In_ UINT64 Address,
    _Out_ PCHAR ModuleName,
    _In_ UINT32 ModuleNameSize
)
{
    UNREFERENCED_PARAMETER(Address);
    
    RtlStringCbCopyA(ModuleName, ModuleNameSize, "Unknown");
    
    // TODO: Resolve address to module name
    return STATUS_SUCCESS;
}

//
// IsAddressInKernelModule
//
BOOLEAN IsAddressInKernelModule(
    _In_ UINT64 Address
)
{
    // Simple heuristic: kernel addresses are in high range
    return (Address >= 0xFFFF800000000000ULL);
}

//
// CalculateRelativeTarget
//
UINT64 CalculateRelativeTarget(
    _In_ UINT64 InstructionAddress,
    _In_ INT32 RelativeOffset,
    _In_ UINT32 InstructionLength
)
{
    return InstructionAddress + InstructionLength + RelativeOffset;
}

//
// MatchPattern
//
BOOLEAN MatchPattern(
    _In_ PUCHAR Data,
    _In_ PUCHAR Pattern,
    _In_ PUCHAR Mask,
    _In_ UINT32 Length
)
{
    UINT32 i;

    for (i = 0; i < Length; i++) {
        if ((Data[i] & Mask[i]) != (Pattern[i] & Mask[i])) {
            return FALSE;
        }
    }

    return TRUE;
}
