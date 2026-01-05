//
// KernelEye Anti-Cheat Driver - Driver Verifier
// Enumerates and validates loaded drivers
//

#include "../include/driver.h"
#include "../include/driver_verifier.h"

// Global state
static DRIVER_VERIFIER_STATE g_VerifierState = {0};

// Known cheat driver blacklist (common kernel cheats)
static const BLACKLISTED_DRIVER g_BlacklistedDrivers[] = {
    { L"cheatengine", "Cheat Engine driver" },
    { L"capcom.sys", "Capcom driver exploit" },
    { L"gdrv.sys", "Gigabyte driver exploit" },
    { L"dbutil", "MSI driver exploit" },
    { L"atszio", "ASUS driver exploit" },
    { L"asrdrv", "ASUS driver exploit" },
    { L"speedfan", "SpeedFan driver exploit" },
    { L"mhyprot", "MiHoYo driver" },
    { L"vgk.sys", "Vanguard bypass" },
    { L"eac.sys", "EAC bypass" },
    { L"faceit", "FaceIT bypass" },
    { NULL, NULL }
};

//
// DriverVerifierInitialize
//
NTSTATUS DriverVerifierInitialize(VOID)
{
    NTSTATUS status;

    if (g_VerifierState.Initialized) {
        KE_WARNING("Driver verifier already initialized");
        return STATUS_SUCCESS;
    }

    KE_INFO("Initializing driver verifier...");

    RtlZeroMemory(&g_VerifierState, sizeof(DRIVER_VERIFIER_STATE));
    
    InitializeListHead(&g_VerifierState.DriverList);
    KeInitializeSpinLock(&g_VerifierState.DriverListLock);

    status = EnumerateLoadedDrivers();
    if (!NT_SUCCESS(status)) {
        KE_ERROR("Failed to enumerate loaded drivers: 0x%08X", status);
        return status;
    }

    status = ScanAllDrivers();
    if (!NT_SUCCESS(status)) {
        KE_WARNING("Failed to scan all drivers: 0x%08X", status);
    }

    g_VerifierState.Initialized = TRUE;
    KeQuerySystemTime(&g_VerifierState.LastScanTime);

    KE_INFO("Driver verifier initialized successfully (%u drivers)", g_VerifierState.DriverCount);
    return STATUS_SUCCESS;
}

//
// DriverVerifierCleanup
//
VOID DriverVerifierCleanup(VOID)
{
    PLIST_ENTRY entry;
    PDRIVER_INFO_ENTRY driverEntry;

    if (!g_VerifierState.Initialized) {
        return;
    }

    KE_INFO("Cleaning up driver verifier...");

    while (!IsListEmpty(&g_VerifierState.DriverList)) {
        entry = RemoveHeadList(&g_VerifierState.DriverList);
        driverEntry = CONTAINING_RECORD(entry, DRIVER_INFO_ENTRY, ListEntry);
        ExFreePoolWithTag(driverEntry, KERNELEYE_POOL_TAG);
    }

    g_VerifierState.Initialized = FALSE;
    KE_INFO("Driver verifier cleaned up");
}

//
// EnumerateLoadedDrivers
//
NTSTATUS EnumerateLoadedDrivers(VOID)
{
    NTSTATUS status;
    ULONG bufferSize = 0;
    PVOID buffer = NULL;
    PRTL_PROCESS_MODULES moduleInfo;
    PRTL_PROCESS_MODULE_INFORMATION moduleEntry;
    PDRIVER_INFO_ENTRY driverEntry;
    KIRQL oldIrql;
    UINT32 i;

    // Query required buffer size
    status = ZwQuerySystemInformation(
        SystemModuleInformation,
        &bufferSize,
        0,
        &bufferSize
    );

    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        KE_ERROR("Failed to query system module information size: 0x%08X", status);
        return status;
    }

    buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, KERNELEYE_POOL_TAG);
    if (!buffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQuerySystemInformation(
        SystemModuleInformation,
        buffer,
        bufferSize,
        &bufferSize
    );

    if (!NT_SUCCESS(status)) {
        KE_ERROR("Failed to query system module information: 0x%08X", status);
        ExFreePoolWithTag(buffer, KERNELEYE_POOL_TAG);
        return status;
    }

    moduleInfo = (PRTL_PROCESS_MODULES)buffer;
    
    KE_VERBOSE("Found %u system modules", moduleInfo->NumberOfModules);

    for (i = 0; i < moduleInfo->NumberOfModules; i++) {
        moduleEntry = &moduleInfo->Modules[i];
        
        driverEntry = (PDRIVER_INFO_ENTRY)ExAllocatePoolWithTag(
            NonPagedPool,
            sizeof(DRIVER_INFO_ENTRY),
            KERNELEYE_POOL_TAG
        );

        if (!driverEntry) {
            continue;
        }

        RtlZeroMemory(driverEntry, sizeof(DRIVER_INFO_ENTRY));
        
        driverEntry->DriverBase = moduleEntry->ImageBase;
        driverEntry->DriverSize = moduleEntry->ImageSize;
        
        // Convert path to wide string
        ANSI_STRING ansiPath;
        UNICODE_STRING unicodePath;
        
        RtlInitAnsiString(&ansiPath, (PCSZ)moduleEntry->FullPathName);
        RtlAnsiStringToUnicodeString(&unicodePath, &ansiPath, TRUE);
        
        if (unicodePath.Length < sizeof(driverEntry->DriverPath)) {
            RtlCopyMemory(driverEntry->DriverPath, unicodePath.Buffer, unicodePath.Length);
        }
        
        RtlFreeUnicodeString(&unicodePath);
        
        // Extract driver name from path
        GetDriverNameFromBase(driverEntry->DriverBase, driverEntry->DriverName, sizeof(driverEntry->DriverName));
        
        driverEntry->IsSystemDriver = TRUE;
        KeQuerySystemTime(&driverEntry->LoadTime);

        KeAcquireSpinLock(&g_VerifierState.DriverListLock, &oldIrql);
        InsertTailList(&g_VerifierState.DriverList, &driverEntry->ListEntry);
        g_VerifierState.DriverCount++;
        KeReleaseSpinLock(&g_VerifierState.DriverListLock, oldIrql);
    }

    ExFreePoolWithTag(buffer, KERNELEYE_POOL_TAG);
    
    KE_INFO("Enumerated %u drivers", g_VerifierState.DriverCount);
    return STATUS_SUCCESS;
}

//
// ScanAllDrivers
//
NTSTATUS ScanAllDrivers(VOID)
{
    PLIST_ENTRY entry;
    PDRIVER_INFO_ENTRY driverEntry;
    KIRQL oldIrql;

    KE_INFO("Scanning all loaded drivers...");

    KeAcquireSpinLock(&g_VerifierState.DriverListLock, &oldIrql);

    for (entry = g_VerifierState.DriverList.Flink;
         entry != &g_VerifierState.DriverList;
         entry = entry->Flink)
    {
        driverEntry = CONTAINING_RECORD(entry, DRIVER_INFO_ENTRY, ListEntry);
        
        // Validate driver
        ValidateDriver(driverEntry->DriverBase, driverEntry->DriverSize);
        
        // Check if blacklisted
        if (IsDriverBlacklisted(driverEntry->DriverName)) {
            driverEntry->IsBlacklisted = TRUE;
            g_VerifierState.BlacklistedDriverCount++;
            KE_WARNING("Blacklisted driver detected: %ws", driverEntry->DriverName);
        }
        
        // Check if suspicious
        if (IsDriverSuspicious(driverEntry)) {
            driverEntry->IsSuspicious = TRUE;
            g_VerifierState.SuspiciousDriverCount++;
            KE_WARNING("Suspicious driver detected: %ws", driverEntry->DriverName);
        }
    }

    KeReleaseSpinLock(&g_VerifierState.DriverListLock, oldIrql);

    KE_INFO("Driver scan complete: %u suspicious, %u blacklisted",
        g_VerifierState.SuspiciousDriverCount,
        g_VerifierState.BlacklistedDriverCount);

    return STATUS_SUCCESS;
}

//
// FindDriverByBase
//
PDRIVER_INFO_ENTRY FindDriverByBase(
    _In_ PVOID DriverBase
)
{
    PLIST_ENTRY entry;
    PDRIVER_INFO_ENTRY driverEntry;

    for (entry = g_VerifierState.DriverList.Flink;
         entry != &g_VerifierState.DriverList;
         entry = entry->Flink)
    {
        driverEntry = CONTAINING_RECORD(entry, DRIVER_INFO_ENTRY, ListEntry);
        if (driverEntry->DriverBase == DriverBase) {
            return driverEntry;
        }
    }

    return NULL;
}

//
// FindDriverByName
//
PDRIVER_INFO_ENTRY FindDriverByName(
    _In_ PCWSTR DriverName
)
{
    PLIST_ENTRY entry;
    PDRIVER_INFO_ENTRY driverEntry;

    for (entry = g_VerifierState.DriverList.Flink;
         entry != &g_VerifierState.DriverList;
         entry = entry->Flink)
    {
        driverEntry = CONTAINING_RECORD(entry, DRIVER_INFO_ENTRY, ListEntry);
        if (CompareDriverNames(driverEntry->DriverName, DriverName)) {
            return driverEntry;
        }
    }

    return NULL;
}

//
// ValidateDriver
//
NTSTATUS ValidateDriver(
    _In_ PVOID DriverBase,
    _In_ SIZE_T DriverSize
)
{
    PDRIVER_INFO_ENTRY driverEntry;

    driverEntry = FindDriverByBase(DriverBase);
    if (!driverEntry) {
        return STATUS_NOT_FOUND;
    }

    // Verify signature
    driverEntry->SignatureStatus = VerifyDriverSignature(DriverBase, DriverSize);
    
    // Detect load type
    driverEntry->LoadType = DetectLoadType(DriverBase, DriverSize);
    
    // Calculate checksum
    driverEntry->Checksum = CalculateDriverChecksum(DriverBase, DriverSize);

    return STATUS_SUCCESS;
}

//
// VerifyDriverSignature
//
DRIVER_SIGNATURE_STATUS VerifyDriverSignature(
    _In_ PVOID DriverBase,
    _In_ SIZE_T DriverSize
)
{
    UNREFERENCED_PARAMETER(DriverBase);
    UNREFERENCED_PARAMETER(DriverSize);

    // TODO: Implement proper signature verification
    // This requires parsing PE authenticode signatures
    return DriverSignatureUnknown;
}

//
// DetectLoadType
//
DRIVER_LOAD_TYPE DetectLoadType(
    _In_ PVOID DriverBase,
    _In_ SIZE_T DriverSize
)
{
    UNREFERENCED_PARAMETER(DriverSize);

    if (IsDriverManuallyMapped(DriverBase)) {
        return DriverLoadManualMap;
    }

    if (!IsDriverInSystemModuleList(DriverBase)) {
        return DriverLoadSuspicious;
    }

    return DriverLoadNormal;
}

//
// IsDriverBlacklisted
//
BOOLEAN IsDriverBlacklisted(
    _In_ PCWSTR DriverName
)
{
    UINT32 i;

    for (i = 0; g_BlacklistedDrivers[i].DriverName != NULL; i++) {
        if (CompareDriverNames(DriverName, g_BlacklistedDrivers[i].DriverName)) {
            return TRUE;
        }
    }

    return FALSE;
}

//
// IsDriverSuspicious
//
BOOLEAN IsDriverSuspicious(
    _In_ PDRIVER_INFO_ENTRY DriverInfo
)
{
    // Check if manually mapped
    if (DriverInfo->LoadType == DriverLoadManualMap) {
        return TRUE;
    }

    // Check if signature is invalid
    if (DriverInfo->SignatureStatus == DriverSignatureInvalid ||
        DriverInfo->SignatureStatus == DriverSignatureNotPresent) {
        return TRUE;
    }

    // Check if known cheat driver
    if (IsKnownCheatDriver(DriverInfo->DriverName)) {
        return TRUE;
    }

    return FALSE;
}

//
// IsKnownCheatDriver
//
BOOLEAN IsKnownCheatDriver(
    _In_ PCWSTR DriverName
)
{
    // Check common patterns
    if (wcsstr(DriverName, L"cheat") != NULL ||
        wcsstr(DriverName, L"hack") != NULL ||
        wcsstr(DriverName, L"bypass") != NULL) {
        return TRUE;
    }

    return FALSE;
}

//
// IsDriverManuallyMapped
//
BOOLEAN IsDriverManuallyMapped(
    _In_ PVOID DriverBase
)
{
    // Check if driver is in system module list
    return !IsDriverInSystemModuleList(DriverBase);
}

//
// IsDriverInSystemModuleList
//
BOOLEAN IsDriverInSystemModuleList(
    _In_ PVOID DriverBase
)
{
    PDRIVER_INFO_ENTRY entry;
    KIRQL oldIrql;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&g_VerifierState.DriverListLock, &oldIrql);
    entry = FindDriverByBase(DriverBase);
    if (entry && entry->IsSystemDriver) {
        found = TRUE;
    }
    KeReleaseSpinLock(&g_VerifierState.DriverListLock, oldIrql);

    return found;
}

//
// GetDriverVerifierStatistics
//
NTSTATUS GetDriverVerifierStatistics(
    _Out_ PUINT32 TotalDrivers,
    _Out_ PUINT32 SuspiciousDrivers,
    _Out_ PUINT32 BlacklistedDrivers
)
{
    *TotalDrivers = g_VerifierState.DriverCount;
    *SuspiciousDrivers = g_VerifierState.SuspiciousDriverCount;
    *BlacklistedDrivers = g_VerifierState.BlacklistedDriverCount;

    return STATUS_SUCCESS;
}

//
// GetDriverNameFromBase
//
NTSTATUS GetDriverNameFromBase(
    _In_ PVOID DriverBase,
    _Out_ PWSTR DriverName,
    _In_ SIZE_T BufferSize
)
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_EXPORT_DIRECTORY exportDir;
    const char* namePtr;
    ANSI_STRING ansiName;
    UNICODE_STRING unicodeName;

    UNREFERENCED_PARAMETER(exportDir);

    __try {
        dosHeader = (PIMAGE_DOS_HEADER)DriverBase;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)DriverBase + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        // For now, use a generic name
        namePtr = "unknown.sys";
        RtlInitAnsiString(&ansiName, namePtr);
        RtlAnsiStringToUnicodeString(&unicodeName, &ansiName, TRUE);
        
        if (unicodeName.Length < BufferSize) {
            RtlCopyMemory(DriverName, unicodeName.Buffer, unicodeName.Length);
            DriverName[unicodeName.Length / sizeof(WCHAR)] = L'\0';
        }
        
        RtlFreeUnicodeString(&unicodeName);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}

//
// CompareDriverNames
//
BOOLEAN CompareDriverNames(
    _In_ PCWSTR Name1,
    _In_ PCWSTR Name2
)
{
    return (_wcsicmp(Name1, Name2) == 0);
}

//
// CalculateDriverChecksum
//
UINT32 CalculateDriverChecksum(
    _In_ PVOID DriverBase,
    _In_ SIZE_T DriverSize
)
{
    UINT32 checksum = 0;
    BYTE* buffer = (BYTE*)DriverBase;
    SIZE_T i;

    __try {
        for (i = 0; i < DriverSize; i++) {
            checksum += buffer[i];
            checksum = (checksum << 1) | (checksum >> 31);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }

    return checksum;
}
