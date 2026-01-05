#pragma once

#include <ntddk.h>
#include "../../../Common/constants.h"
#include "../../../Common/structures.h"

//
// KernelEye Driver - Memory Scanner
// Scans process memory for suspicious regions, hooks, and code modifications
//

// VAD (Virtual Address Descriptor) related structures
typedef struct _MMVAD_SHORT {
    union {
        struct {
            struct _MMVAD_SHORT* LeftChild;
            struct _MMVAD_SHORT* RightChild;
        };
        ULONG_PTR VadTreeLinks[2];
    };
    ULONG_PTR StartingVpn;
    ULONG_PTR EndingVpn;
    UCHAR StartingVpnHigh;
    UCHAR EndingVpnHigh;
    UCHAR CommitChargeHigh;
    UCHAR SpareNT64VadUChar;
    LONG ReferenceCount;
    LONG_PTR u;
} MMVAD_SHORT, *PMMVAD_SHORT;

// Memory scan context
typedef struct _MEMORY_SCAN_CONTEXT {
    PEPROCESS TargetProcess;
    UINT64 ProcessId;
    UINT32 ScanFlags;
    UINT32 DetectionCount;
    UINT32 RegionCount;
    UINT32 SuspiciousRegionCount;
    LIST_ENTRY DetectionList;
    KSPIN_LOCK DetectionLock;
} MEMORY_SCAN_CONTEXT, *PMEMORY_SCAN_CONTEXT;

// Memory detection entry
typedef struct _MEMORY_DETECTION_ENTRY {
    LIST_ENTRY ListEntry;
    UINT64 BaseAddress;
    UINT64 Size;
    UINT32 Protection;
    UINT32 SuspicionFlags;
    UINT32 ThreatLevel;
    CHAR Description[256];
} MEMORY_DETECTION_ENTRY, *PMEMORY_DETECTION_ENTRY;

// PE Header structures (simplified)
#pragma pack(push, 1)
typedef struct _IMAGE_DOS_HEADER_CUSTOM {
    UINT16 e_magic;
    UINT16 e_cblp;
    UINT16 e_cp;
    UINT16 e_crlc;
    UINT16 e_cparhdr;
    UINT16 e_minalloc;
    UINT16 e_maxalloc;
    UINT16 e_ss;
    UINT16 e_sp;
    UINT16 e_csum;
    UINT16 e_ip;
    UINT16 e_cs;
    UINT16 e_lfarlc;
    UINT16 e_ovno;
    UINT16 e_res[4];
    UINT16 e_oemid;
    UINT16 e_oeminfo;
    UINT16 e_res2[10];
    UINT32 e_lfanew;
} IMAGE_DOS_HEADER_CUSTOM, *PIMAGE_DOS_HEADER_CUSTOM;
#pragma pack(pop)

// Initialization and cleanup
NTSTATUS MemoryScannerInitialize(VOID);
VOID MemoryScannerCleanup(VOID);

// Main scanning functions
NTSTATUS ScanProcessMemory(
    _In_ UINT64 ProcessId,
    _In_ UINT32 ScanFlags,
    _Out_ PMEMORY_SCAN_CONTEXT* ScanContext
);

NTSTATUS EnumerateProcessMemory(
    _In_ PEPROCESS Process,
    _Inout_ PMEMORY_SCAN_CONTEXT ScanContext
);

// VAD enumeration
NTSTATUS WalkVadTree(
    _In_ PMMVAD_SHORT VadRoot,
    _In_ PEPROCESS Process,
    _Inout_ PMEMORY_SCAN_CONTEXT ScanContext
);

NTSTATUS ProcessVadNode(
    _In_ PMMVAD_SHORT Vad,
    _In_ PEPROCESS Process,
    _Inout_ PMEMORY_SCAN_CONTEXT ScanContext
);

// Memory region analysis
NTSTATUS AnalyzeMemoryRegion(
    _In_ PEPROCESS Process,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T Size,
    _In_ UINT32 Protection,
    _Inout_ PMEMORY_SCAN_CONTEXT ScanContext
);

BOOLEAN IsMemoryRegionSuspicious(
    _In_ PVOID BaseAddress,
    _In_ SIZE_T Size,
    _In_ UINT32 Protection,
    _Out_ PUINT32 SuspicionFlags
);

// Page protection checks
BOOLEAN IsExecutableWritable(UINT32 Protection);
BOOLEAN IsHiddenMemory(PEPROCESS Process, PVOID Address);
NTSTATUS CheckPageProtections(
    _In_ PEPROCESS Process,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T Size,
    _Out_ PBOOLEAN HasSuspiciousProtection
);

// PE header validation
NTSTATUS ValidatePEHeader(
    _In_ PEPROCESS Process,
    _In_ PVOID BaseAddress,
    _Out_ PBOOLEAN IsValid,
    _Out_ PBOOLEAN IsModified
);

NTSTATUS ReadProcessMemorySafe(
    _In_ PEPROCESS Process,
    _In_ PVOID SourceAddress,
    _Out_ PVOID DestinationAddress,
    _In_ SIZE_T Size,
    _Out_opt_ PSIZE_T BytesRead
);

// Code integrity
NTSTATUS CalculateRegionChecksum(
    _In_ PEPROCESS Process,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T Size,
    _Out_ PUINT32 Checksum
);

NTSTATUS VerifyCodeSection(
    _In_ PEPROCESS Process,
    _In_ PVOID ModuleBase,
    _Out_ PBOOLEAN IsIntact
);

// Detection management
NTSTATUS AddMemoryDetection(
    _Inout_ PMEMORY_SCAN_CONTEXT ScanContext,
    _In_ UINT64 BaseAddress,
    _In_ UINT64 Size,
    _In_ UINT32 Protection,
    _In_ UINT32 SuspicionFlags,
    _In_ UINT32 ThreatLevel,
    _In_ PCSTR Description
);

VOID FreeMemoryScanContext(
    _In_ PMEMORY_SCAN_CONTEXT ScanContext
);

// Statistics
NTSTATUS GetMemoryScanStatistics(
    _In_ PMEMORY_SCAN_CONTEXT ScanContext,
    _Out_ PUINT32 TotalRegions,
    _Out_ PUINT32 SuspiciousRegions,
    _Out_ PUINT32 DetectionCount
);

// Helper functions
PVOID GetProcessVadRoot(PEPROCESS Process);
UINT64 VpnToAddress(ULONG_PTR Vpn, UCHAR VpnHigh);
BOOLEAN IsAddressInRange(PVOID Address, PVOID Start, SIZE_T Size);

// Constants for PE validation
#define IMAGE_DOS_SIGNATURE_CUSTOM    0x5A4D     // MZ
#define IMAGE_NT_SIGNATURE_CUSTOM     0x00004550 // PE\0\0
#define MAX_PE_HEADER_SIZE            0x1000    // 4KB
