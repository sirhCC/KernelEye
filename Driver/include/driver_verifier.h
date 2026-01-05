#pragma once

#include <ntddk.h>

//
// KernelEye Driver - Driver Verifier Module
// Enumerates and validates loaded drivers for tampering
//

// Driver signature types
typedef enum _DRIVER_SIGNATURE_STATUS {
    DriverSignatureValid = 0,
    DriverSignatureInvalid,
    DriverSignatureUntrusted,
    DriverSignatureExpired,
    DriverSignatureNotPresent,
    DriverSignatureUnknown
} DRIVER_SIGNATURE_STATUS;

// Driver load type
typedef enum _DRIVER_LOAD_TYPE {
    DriverLoadNormal = 0,
    DriverLoadManualMap,
    DriverLoadModified,
    DriverLoadSuspicious
} DRIVER_LOAD_TYPE;

// Information about a loaded driver
typedef struct _DRIVER_INFO_ENTRY {
    LIST_ENTRY ListEntry;
    
    PVOID DriverBase;
    SIZE_T DriverSize;
    WCHAR DriverPath[260];
    WCHAR DriverName[64];
    
    DRIVER_SIGNATURE_STATUS SignatureStatus;
    DRIVER_LOAD_TYPE LoadType;
    
    BOOLEAN IsSystemDriver;
    BOOLEAN IsSuspicious;
    BOOLEAN IsBlacklisted;
    
    LARGE_INTEGER LoadTime;
    UINT32 Checksum;
} DRIVER_INFO_ENTRY, *PDRIVER_INFO_ENTRY;

// Driver verifier state
typedef struct _DRIVER_VERIFIER_STATE {
    BOOLEAN Initialized;
    
    LIST_ENTRY DriverList;
    KSPIN_LOCK DriverListLock;
    UINT32 DriverCount;
    
    UINT32 SuspiciousDriverCount;
    UINT32 BlacklistedDriverCount;
    
    LARGE_INTEGER LastScanTime;
} DRIVER_VERIFIER_STATE, *PDRIVER_VERIFIER_STATE;

// Blacklisted driver information
typedef struct _BLACKLISTED_DRIVER {
    const WCHAR* DriverName;
    const char* Description;
} BLACKLISTED_DRIVER, *PBLACKLISTED_DRIVER;

// Initialize/cleanup
NTSTATUS DriverVerifierInitialize(VOID);
VOID DriverVerifierCleanup(VOID);

// Driver enumeration
NTSTATUS EnumerateLoadedDrivers(VOID);
NTSTATUS ScanAllDrivers(VOID);
PDRIVER_INFO_ENTRY FindDriverByBase(_In_ PVOID DriverBase);
PDRIVER_INFO_ENTRY FindDriverByName(_In_ PCWSTR DriverName);

// Driver validation
NTSTATUS ValidateDriver(_In_ PVOID DriverBase, _In_ SIZE_T DriverSize);
DRIVER_SIGNATURE_STATUS VerifyDriverSignature(_In_ PVOID DriverBase, _In_ SIZE_T DriverSize);
DRIVER_LOAD_TYPE DetectLoadType(_In_ PVOID DriverBase, _In_ SIZE_T DriverSize);

// Suspicious driver detection
BOOLEAN IsDriverBlacklisted(_In_ PCWSTR DriverName);
BOOLEAN IsDriverSuspicious(_In_ PDRIVER_INFO_ENTRY DriverInfo);
BOOLEAN IsKnownCheatDriver(_In_ PCWSTR DriverName);

// Manual mapping detection
BOOLEAN IsDriverManuallyMapped(_In_ PVOID DriverBase);
BOOLEAN IsDriverInSystemModuleList(_In_ PVOID DriverBase);

// Statistics
NTSTATUS GetDriverVerifierStatistics(
    _Out_ PUINT32 TotalDrivers,
    _Out_ PUINT32 SuspiciousDrivers,
    _Out_ PUINT32 BlacklistedDrivers
);

// Helper functions
NTSTATUS GetDriverNameFromBase(_In_ PVOID DriverBase, _Out_ PWSTR DriverName, _In_ SIZE_T BufferSize);
BOOLEAN CompareDriverNames(_In_ PCWSTR Name1, _In_ PCWSTR Name2);
UINT32 CalculateDriverChecksum(_In_ PVOID DriverBase, _In_ SIZE_T DriverSize);
