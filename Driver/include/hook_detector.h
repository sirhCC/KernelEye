#pragma once

#include <ntddk.h>
#include "../../../Common/constants.h"
#include "../../../Common/structures.h"

//
// KernelEye Driver - Hook Detector
// Detects various types of hooks in user-mode and kernel-mode
//

// Hook detection context
typedef struct _HOOK_SCAN_CONTEXT {
    PEPROCESS TargetProcess;
    UINT64 ProcessId;
    UINT32 ScanFlags;
    UINT32 HookCount;
    UINT32 FunctionsChecked;
    LIST_ENTRY HookList;
    KSPIN_LOCK HookLock;
} HOOK_SCAN_CONTEXT, *PHOOK_SCAN_CONTEXT;

// Hook detection entry
typedef struct _HOOK_DETECTION_ENTRY {
    LIST_ENTRY ListEntry;
    UINT64 TargetAddress;
    UINT64 HookAddress;
    UINT32 HookType;
    UINT32 ThreatLevel;
    CHAR TargetFunction[256];
    CHAR TargetModule[MAX_MODULE_NAME_LENGTH];
    CHAR HookModule[MAX_MODULE_NAME_LENGTH];
    UCHAR OriginalBytes[16];
    UCHAR HookedBytes[16];
} HOOK_DETECTION_ENTRY, *PHOOK_DETECTION_ENTRY;

// Inline hook patterns
typedef struct _INLINE_HOOK_PATTERN {
    UCHAR Pattern[8];
    UCHAR Mask[8];
    UINT32 PatternLength;
    UINT32 HookType;
    CHAR Description[64];
} INLINE_HOOK_PATTERN, *PINLINE_HOOK_PATTERN;

// IAT/EAT structures
typedef struct _IAT_ENTRY {
    UINT64 FunctionAddress;
    CHAR FunctionName[256];
    CHAR ModuleName[MAX_MODULE_NAME_LENGTH];
} IAT_ENTRY, *PIAT_ENTRY;

// SSDT entry
typedef struct _SSDT_ENTRY {
    UINT64 ServiceAddress;
    UINT32 ServiceId;
    CHAR ServiceName[256];
} SSDT_ENTRY, *PSSDT_ENTRY;

// Initialization and cleanup
NTSTATUS HookDetectorInitialize(VOID);
VOID HookDetectorCleanup(VOID);

// Main scanning functions
NTSTATUS ScanProcessHooks(
    _In_ UINT64 ProcessId,
    _In_ UINT32 ScanFlags,
    _Out_ PHOOK_SCAN_CONTEXT* ScanContext
);

// Inline hook detection
NTSTATUS ScanInlineHooks(
    _In_ PEPROCESS Process,
    _In_ PVOID ModuleBase,
    _In_ SIZE_T ModuleSize,
    _Inout_ PHOOK_SCAN_CONTEXT Context
);

NTSTATUS CheckFunctionForInlineHook(
    _In_ PEPROCESS Process,
    _In_ PVOID FunctionAddress,
    _In_ PCSTR FunctionName,
    _In_ PCSTR ModuleName,
    _Inout_ PHOOK_SCAN_CONTEXT Context
);

BOOLEAN IsInlineHookPattern(
    _In_ PUCHAR FunctionBytes,
    _In_ UINT32 Length,
    _Out_ PUINT64 HookTarget,
    _Out_ PUINT32 HookType
);

// IAT/EAT hook detection
NTSTATUS ScanIATHooks(
    _In_ PEPROCESS Process,
    _In_ PVOID ModuleBase,
    _Inout_ PHOOK_SCAN_CONTEXT Context
);

NTSTATUS ScanEATHooks(
    _In_ PEPROCESS Process,
    _In_ PVOID ModuleBase,
    _Inout_ PHOOK_SCAN_CONTEXT Context
);

NTSTATUS ParseImportDirectory(
    _In_ PEPROCESS Process,
    _In_ PVOID ModuleBase,
    _Out_ PIAT_ENTRY* Entries,
    _Out_ PUINT32 EntryCount
);

BOOLEAN IsIATEntryHooked(
    _In_ PEPROCESS Process,
    _In_ UINT64 IATAddress,
    _In_ PCSTR FunctionName,
    _Out_ PUINT64 HookAddress
);

// SSDT hook detection
NTSTATUS ScanSSDTHooks(
    _Inout_ PHOOK_SCAN_CONTEXT Context
);

NTSTATUS GetSSDTBase(
    _Out_ PVOID* SSDTBase
);

BOOLEAN IsSSDTEntryHooked(
    _In_ UINT64 ServiceAddress,
    _In_ UINT32 ServiceId,
    _Out_ PUINT64 HookAddress
);

// Callback enumeration
NTSTATUS EnumerateCallbacks(
    _Inout_ PHOOK_SCAN_CONTEXT Context
);

NTSTATUS EnumerateProcessCallbacks(
    _Inout_ PHOOK_SCAN_CONTEXT Context
);

NTSTATUS EnumerateThreadCallbacks(
    _Inout_ PHOOK_SCAN_CONTEXT Context
);

NTSTATUS EnumerateImageCallbacks(
    _Inout_ PHOOK_SCAN_CONTEXT Context
);

// Detection management
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
);

VOID FreeHookScanContext(
    _In_ PHOOK_SCAN_CONTEXT Context
);

NTSTATUS GetHookScanStatistics(
    _In_ PHOOK_SCAN_CONTEXT Context,
    _Out_ PUINT32 FunctionsChecked,
    _Out_ PUINT32 HooksFound
);

// Helper functions
NTSTATUS GetModuleExports(
    _In_ PEPROCESS Process,
    _In_ PVOID ModuleBase,
    _Out_ PVOID** ExportAddresses,
    _Out_ PUINT32 ExportCount
);

NTSTATUS ResolveModuleName(
    _In_ UINT64 Address,
    _Out_ PCHAR ModuleName,
    _In_ UINT32 ModuleNameSize
);

BOOLEAN IsAddressInKernelModule(
    _In_ UINT64 Address
);

UINT64 CalculateRelativeTarget(
    _In_ UINT64 InstructionAddress,
    _In_ INT32 RelativeOffset,
    _In_ UINT32 InstructionLength
);

// Pattern matching
BOOLEAN MatchPattern(
    _In_ PUCHAR Data,
    _In_ PUCHAR Pattern,
    _In_ PUCHAR Mask,
    _In_ UINT32 Length
);

// Common hook patterns
extern INLINE_HOOK_PATTERN g_InlineHookPatterns[];
extern UINT32 g_InlineHookPatternCount;

// Hook type specific detection
#define HOOK_PATTERN_JMP_REL32      0  // E9 xx xx xx xx
#define HOOK_PATTERN_JMP_ABS        1  // FF 25 xx xx xx xx
#define HOOK_PATTERN_CALL_REL32     2  // E8 xx xx xx xx
#define HOOK_PATTERN_PUSH_RET       3  // 68 xx xx xx xx C3
#define HOOK_PATTERN_MOV_RAX_JMP    4  // 48 B8 ... FF E0
