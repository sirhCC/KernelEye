//
// KernelEye Anti-Cheat Driver - Memory Scanner
// Scans process memory for suspicious regions and code modifications
//

#include "../include/driver.h"
#include "../include/memory_scanner.h"

// Global state
static BOOLEAN g_MemoryScannerInitialized = FALSE;

//
// MemoryScannerInitialize - Initialize memory scanner subsystem
//
NTSTATUS MemoryScannerInitialize(VOID)
{
    if (g_MemoryScannerInitialized) {
        KE_WARNING("Memory scanner already initialized");
        return STATUS_SUCCESS;
    }

    KE_INFO("Initializing memory scanner...");

    // TODO: Initialize pattern database
    // TODO: Load known good signatures

    g_MemoryScannerInitialized = TRUE;
    KE_INFO("Memory scanner initialized successfully");

    return STATUS_SUCCESS;
}

//
// MemoryScannerCleanup - Cleanup memory scanner resources
//
VOID MemoryScannerCleanup(VOID)
{
    if (!g_MemoryScannerInitialized) {
        return;
    }

    KE_INFO("Cleaning up memory scanner...");

    // TODO: Cleanup pattern database
    // TODO: Free cached signatures

    g_MemoryScannerInitialized = FALSE;
    KE_INFO("Memory scanner cleaned up");
}

//
// ScanProcessMemory - Main entry point for scanning a process
//
NTSTATUS ScanProcessMemory(
    _In_ UINT64 ProcessId,
    _In_ UINT32 ScanFlags,
    _Out_ PMEMORY_SCAN_CONTEXT* ScanContext
)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PMEMORY_SCAN_CONTEXT context = NULL;

    KE_INFO("Scanning process memory: PID=%llu, Flags=0x%08X", ProcessId, ScanFlags);

    if (!g_MemoryScannerInitialized) {
        KE_ERROR("Memory scanner not initialized");
        return STATUS_UNSUCCESSFUL;
    }

    // Get process object
    status = PsLookupProcessByProcessId((HANDLE)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        KE_ERROR("Failed to lookup process %llu: 0x%08X", ProcessId, status);
        return status;
    }

    // Allocate scan context
    context = (PMEMORY_SCAN_CONTEXT)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(MEMORY_SCAN_CONTEXT),
        SCAN_BUFFER_TAG
    );

    if (!context) {
        KE_ERROR("Failed to allocate scan context");
        ObDereferenceObject(process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Initialize context
    RtlZeroMemory(context, sizeof(MEMORY_SCAN_CONTEXT));
    context->TargetProcess = process;
    context->ProcessId = ProcessId;
    context->ScanFlags = ScanFlags;
    InitializeListHead(&context->DetectionList);
    KeInitializeSpinLock(&context->DetectionLock);

    // Enumerate memory regions
    status = EnumerateProcessMemory(process, context);
    if (!NT_SUCCESS(status)) {
        KE_ERROR("Failed to enumerate process memory: 0x%08X", status);
        FreeMemoryScanContext(context);
        ObDereferenceObject(process);
        return status;
    }

    KE_INFO("Memory scan complete: %u regions, %u suspicious, %u detections",
        context->RegionCount, context->SuspiciousRegionCount, context->DetectionCount);

    *ScanContext = context;
    return STATUS_SUCCESS;
}

//
// EnumerateProcessMemory - Enumerate all memory regions in a process
//
NTSTATUS EnumerateProcessMemory(
    _In_ PEPROCESS Process,
    _Inout_ PMEMORY_SCAN_CONTEXT ScanContext
)
{
    NTSTATUS status;
    PVOID vadRoot;
    KAPC_STATE apcState;

    KE_VERBOSE("Enumerating process memory regions");

    // Attach to target process
    KeStackAttachProcess(Process, &apcState);

    __try {
        // Get VAD root
        vadRoot = GetProcessVadRoot(Process);
        if (!vadRoot) {
            KE_WARNING("Failed to get VAD root");
            status = STATUS_UNSUCCESSFUL;
            __leave;
        }

        // Walk VAD tree
        status = WalkVadTree((PMMVAD_SHORT)vadRoot, Process, ScanContext);
        if (!NT_SUCCESS(status)) {
            KE_ERROR("Failed to walk VAD tree: 0x%08X", status);
            __leave;
        }

        status = STATUS_SUCCESS;
    }
    __finally {
        KeUnstackDetachProcess(&apcState);
    }

    return status;
}

//
// WalkVadTree - Recursively walk the VAD tree
//
NTSTATUS WalkVadTree(
    _In_ PMMVAD_SHORT VadRoot,
    _In_ PEPROCESS Process,
    _Inout_ PMEMORY_SCAN_CONTEXT ScanContext
)
{
    NTSTATUS status;

    if (!VadRoot) {
        return STATUS_SUCCESS;
    }

    // Process current node
    status = ProcessVadNode(VadRoot, Process, ScanContext);
    if (!NT_SUCCESS(status)) {
        KE_VERBOSE("Failed to process VAD node: 0x%08X", status);
        // Continue scanning even if one node fails
    }

    // Walk left subtree
    if (VadRoot->LeftChild) {
        WalkVadTree(VadRoot->LeftChild, Process, ScanContext);
    }

    // Walk right subtree
    if (VadRoot->RightChild) {
        WalkVadTree(VadRoot->RightChild, Process, ScanContext);
    }

    return STATUS_SUCCESS;
}

//
// ProcessVadNode - Process a single VAD node
//
NTSTATUS ProcessVadNode(
    _In_ PMMVAD_SHORT Vad,
    _In_ PEPROCESS Process,
    _Inout_ PMEMORY_SCAN_CONTEXT ScanContext
)
{
    UINT64 baseAddress;
    UINT64 endAddress;
    SIZE_T size;
    UINT32 protection;

    // Calculate addresses
    baseAddress = VpnToAddress(Vad->StartingVpn, Vad->StartingVpnHigh);
    endAddress = VpnToAddress(Vad->EndingVpn, Vad->EndingVpnHigh);
    size = endAddress - baseAddress + PAGE_SIZE;

    // Get protection (simplified - would need to decode VadFlags)
    protection = PAGE_READWRITE; // Placeholder

    ScanContext->RegionCount++;

    KE_VERBOSE("Processing VAD: Base=0x%llX, Size=0x%llX", baseAddress, size);

    // Analyze this memory region
    return AnalyzeMemoryRegion(
        Process,
        (PVOID)baseAddress,
        size,
        protection,
        ScanContext
    );
}

//
// AnalyzeMemoryRegion - Analyze a memory region for suspicious characteristics
//
NTSTATUS AnalyzeMemoryRegion(
    _In_ PEPROCESS Process,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T Size,
    _In_ UINT32 Protection,
    _Inout_ PMEMORY_SCAN_CONTEXT ScanContext
)
{
    UINT32 suspicionFlags = 0;
    UINT32 threatLevel = THREAT_LEVEL_NONE;
    BOOLEAN isSuspicious;
    BOOLEAN hasPageProtectionIssue = FALSE;
    BOOLEAN isPEValid = TRUE;
    BOOLEAN isPEModified = FALSE;

    // Check if region is suspicious
    isSuspicious = IsMemoryRegionSuspicious(BaseAddress, Size, Protection, &suspicionFlags);

    if (!isSuspicious) {
        return STATUS_SUCCESS;
    }

    ScanContext->SuspiciousRegionCount++;

    // Check page protections if requested
    if (ScanContext->ScanFlags & SCAN_FLAG_MEMORY) {
        CheckPageProtections(Process, BaseAddress, Size, &hasPageProtectionIssue);
        if (hasPageProtectionIssue) {
            suspicionFlags |= MEM_SUSPICION_RWX_PAGES;
            threatLevel = max(threatLevel, THREAT_LEVEL_MEDIUM);
        }
    }

    // Validate PE header for executable regions
    if (Protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) {
        if (NT_SUCCESS(ValidatePEHeader(Process, BaseAddress, &isPEValid, &isPEModified))) {
            if (!isPEValid) {
                suspicionFlags |= MEM_SUSPICION_INVALID_PE;
                threatLevel = max(threatLevel, THREAT_LEVEL_HIGH);
            }
            if (isPEModified) {
                suspicionFlags |= MEM_SUSPICION_MODIFIED_CODE;
                threatLevel = max(threatLevel, THREAT_LEVEL_CRITICAL);
            }
        }
    }

    // Add detection if threat level is significant
    if (threatLevel >= THREAT_LEVEL_MEDIUM) {
        AddMemoryDetection(
            ScanContext,
            (UINT64)BaseAddress,
            Size,
            Protection,
            suspicionFlags,
            threatLevel,
            "Suspicious memory region detected"
        );
    }

    return STATUS_SUCCESS;
}

//
// IsMemoryRegionSuspicious - Quick check if region warrants deeper analysis
//
BOOLEAN IsMemoryRegionSuspicious(
    _In_ PVOID BaseAddress,
    _In_ SIZE_T Size,
    _In_ UINT32 Protection,
    _Out_ PUINT32 SuspicionFlags
)
{
    BOOLEAN suspicious = FALSE;
    *SuspicionFlags = 0;

    // Check for RWX pages (very suspicious)
    if (IsExecutableWritable(Protection)) {
        *SuspicionFlags |= MEM_SUSPICION_RWX_PAGES;
        suspicious = TRUE;
    }

    // Check for large executable regions
    if ((Protection & PAGE_EXECUTE) && Size > 100 * 1024 * 1024) {
        *SuspicionFlags |= MEM_SUSPICION_UNMAPPED_EXEC;
        suspicious = TRUE;
    }

    // Check for unusual base addresses
    UINT64 addr = (UINT64)BaseAddress;
    if (addr < 0x10000 || addr > 0x7FFFFFFFFFFF) {
        // Outside normal user-mode range
        suspicious = TRUE;
    }

    return suspicious;
}

//
// IsExecutableWritable - Check if memory is both executable and writable
//
BOOLEAN IsExecutableWritable(UINT32 Protection)
{
    return (Protection & PAGE_EXECUTE_READWRITE) ||
           (Protection & PAGE_EXECUTE_WRITECOPY);
}

//
// CheckPageProtections - Check for suspicious page protections
//
NTSTATUS CheckPageProtections(
    _In_ PEPROCESS Process,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T Size,
    _Out_ PBOOLEAN HasSuspiciousProtection
)
{
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T returnLength;
    PVOID currentAddress = BaseAddress;
    SIZE_T remaining = Size;

    UNREFERENCED_PARAMETER(Process);

    *HasSuspiciousProtection = FALSE;

    // Check pages in this region
    while (remaining > 0) {
        // Query virtual memory (simplified - would use ZwQueryVirtualMemory)
        RtlZeroMemory(&mbi, sizeof(mbi));
        mbi.Protect = PAGE_READWRITE;
        returnLength = sizeof(mbi);

        // Check if this page has RWX protection
        if (IsExecutableWritable(mbi.Protect)) {
            *HasSuspiciousProtection = TRUE;
            return STATUS_SUCCESS;
        }

        currentAddress = (PVOID)((UINT64)currentAddress + PAGE_SIZE);
        if (remaining < PAGE_SIZE) break;
        remaining -= PAGE_SIZE;
    }

    return STATUS_SUCCESS;
}

//
// ValidatePEHeader - Validate PE header structure
//
NTSTATUS ValidatePEHeader(
    _In_ PEPROCESS Process,
    _In_ PVOID BaseAddress,
    _Out_ PBOOLEAN IsValid,
    _Out_ PBOOLEAN IsModified
)
{
    NTSTATUS status;
    IMAGE_DOS_HEADER_CUSTOM dosHeader;
    UINT32 ntSignature;
    SIZE_T bytesRead;

    *IsValid = FALSE;
    *IsModified = FALSE;

    // Read DOS header
    status = ReadProcessMemorySafe(
        Process,
        BaseAddress,
        &dosHeader,
        sizeof(IMAGE_DOS_HEADER_CUSTOM),
        &bytesRead
    );

    if (!NT_SUCCESS(status) || bytesRead != sizeof(IMAGE_DOS_HEADER_CUSTOM)) {
        return status;
    }

    // Check DOS signature
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE_CUSTOM) {
        return STATUS_SUCCESS; // Not a PE file, not necessarily invalid
    }

    // Validate e_lfanew
    if (dosHeader.e_lfanew > MAX_PE_HEADER_SIZE || dosHeader.e_lfanew < sizeof(IMAGE_DOS_HEADER_CUSTOM)) {
        *IsValid = FALSE;
        *IsModified = TRUE;
        return STATUS_SUCCESS;
    }

    // Read NT signature
    status = ReadProcessMemorySafe(
        Process,
        (PVOID)((UINT64)BaseAddress + dosHeader.e_lfanew),
        &ntSignature,
        sizeof(UINT32),
        &bytesRead
    );

    if (!NT_SUCCESS(status) || bytesRead != sizeof(UINT32)) {
        return status;
    }

    // Check NT signature
    if (ntSignature != IMAGE_NT_SIGNATURE_CUSTOM) {
        *IsValid = FALSE;
        *IsModified = TRUE;
        return STATUS_SUCCESS;
    }

    *IsValid = TRUE;

    // TODO: Deep PE validation
    // - Check section headers
    // - Validate entry point
    // - Check import table
    // - Verify checksums

    return STATUS_SUCCESS;
}

//
// ReadProcessMemorySafe - Safely read process memory
//
NTSTATUS ReadProcessMemorySafe(
    _In_ PEPROCESS Process,
    _In_ PVOID SourceAddress,
    _Out_ PVOID DestinationAddress,
    _In_ SIZE_T Size,
    _Out_opt_ PSIZE_T BytesRead
)
{
    SIZE_T bytes = 0;
    
    UNREFERENCED_PARAMETER(Process);

    __try {
        // Use ProbeForRead to validate address
        ProbeForRead(SourceAddress, Size, 1);
        
        // Copy memory
        RtlCopyMemory(DestinationAddress, SourceAddress, Size);
        bytes = Size;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        if (BytesRead) {
            *BytesRead = 0;
        }
        return STATUS_ACCESS_VIOLATION;
    }

    if (BytesRead) {
        *BytesRead = bytes;
    }

    return STATUS_SUCCESS;
}

//
// CalculateRegionChecksum - Calculate checksum for memory region
//
NTSTATUS CalculateRegionChecksum(
    _In_ PEPROCESS Process,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T Size,
    _Out_ PUINT32 Checksum
)
{
    NTSTATUS status;
    PVOID buffer = NULL;
    SIZE_T bytesRead;
    UINT32 checksum = 0;
    PUCHAR data;
    SIZE_T i;

    *Checksum = 0;

    // Allocate buffer
    buffer = ExAllocatePoolWithTag(NonPagedPool, Size, SCAN_BUFFER_TAG);
    if (!buffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Read memory
    status = ReadProcessMemorySafe(Process, BaseAddress, buffer, Size, &bytesRead);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buffer, SCAN_BUFFER_TAG);
        return status;
    }

    // Calculate simple checksum
    data = (PUCHAR)buffer;
    for (i = 0; i < bytesRead; i++) {
        checksum = (checksum << 5) + checksum + data[i];
    }

    *Checksum = checksum;
    ExFreePoolWithTag(buffer, SCAN_BUFFER_TAG);

    return STATUS_SUCCESS;
}

//
// VerifyCodeSection - Verify integrity of code section
//
NTSTATUS VerifyCodeSection(
    _In_ PEPROCESS Process,
    _In_ PVOID ModuleBase,
    _Out_ PBOOLEAN IsIntact
)
{
    // Placeholder - would compare against known good signatures
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ModuleBase);
    
    *IsIntact = TRUE; // Assume intact for now
    return STATUS_SUCCESS;
}

//
// AddMemoryDetection - Add a detection to the scan context
//
NTSTATUS AddMemoryDetection(
    _Inout_ PMEMORY_SCAN_CONTEXT ScanContext,
    _In_ UINT64 BaseAddress,
    _In_ UINT64 Size,
    _In_ UINT32 Protection,
    _In_ UINT32 SuspicionFlags,
    _In_ UINT32 ThreatLevel,
    _In_ PCSTR Description
)
{
    PMEMORY_DETECTION_ENTRY entry;
    KIRQL oldIrql;

    entry = (PMEMORY_DETECTION_ENTRY)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(MEMORY_DETECTION_ENTRY),
        REPORT_BUFFER_TAG
    );

    if (!entry) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(entry, sizeof(MEMORY_DETECTION_ENTRY));
    entry->BaseAddress = BaseAddress;
    entry->Size = Size;
    entry->Protection = Protection;
    entry->SuspicionFlags = SuspicionFlags;
    entry->ThreatLevel = ThreatLevel;
    RtlStringCbCopyA(entry->Description, sizeof(entry->Description), Description);

    KeAcquireSpinLock(&ScanContext->DetectionLock, &oldIrql);
    InsertTailList(&ScanContext->DetectionList, &entry->ListEntry);
    ScanContext->DetectionCount++;
    KeReleaseSpinLock(&ScanContext->DetectionLock, oldIrql);

    KE_WARNING("Memory detection: Addr=0x%llX, Size=0x%llX, Threat=%u, Flags=0x%08X",
        BaseAddress, Size, ThreatLevel, SuspicionFlags);

    return STATUS_SUCCESS;
}

//
// FreeMemoryScanContext - Free scan context and all detections
//
VOID FreeMemoryScanContext(
    _In_ PMEMORY_SCAN_CONTEXT ScanContext
)
{
    PLIST_ENTRY entry;
    PMEMORY_DETECTION_ENTRY detection;

    if (!ScanContext) {
        return;
    }

    // Free all detections
    while (!IsListEmpty(&ScanContext->DetectionList)) {
        entry = RemoveHeadList(&ScanContext->DetectionList);
        detection = CONTAINING_RECORD(entry, MEMORY_DETECTION_ENTRY, ListEntry);
        ExFreePoolWithTag(detection, REPORT_BUFFER_TAG);
    }

    // Dereference process
    if (ScanContext->TargetProcess) {
        ObDereferenceObject(ScanContext->TargetProcess);
    }

    // Free context
    ExFreePoolWithTag(ScanContext, SCAN_BUFFER_TAG);
}

//
// GetMemoryScanStatistics - Get scan statistics
//
NTSTATUS GetMemoryScanStatistics(
    _In_ PMEMORY_SCAN_CONTEXT ScanContext,
    _Out_ PUINT32 TotalRegions,
    _Out_ PUINT32 SuspiciousRegions,
    _Out_ PUINT32 DetectionCount
)
{
    if (!ScanContext) {
        return STATUS_INVALID_PARAMETER;
    }

    *TotalRegions = ScanContext->RegionCount;
    *SuspiciousRegions = ScanContext->SuspiciousRegionCount;
    *DetectionCount = ScanContext->DetectionCount;

    return STATUS_SUCCESS;
}

//
// GetProcessVadRoot - Get VAD root from EPROCESS
//
PVOID GetProcessVadRoot(PEPROCESS Process)
{
    // VAD root offset varies by Windows version
    // Windows 10: offset 0x658
    // Windows 11: offset might differ
    // This is a simplified version - production code should use version detection
    
    PVOID vadRoot = NULL;
    
    __try {
        // Simplified - would need proper offset for the Windows version
        vadRoot = *(PVOID*)((UINT64)Process + 0x658);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        vadRoot = NULL;
    }

    return vadRoot;
}

//
// VpnToAddress - Convert VPN to virtual address
//
UINT64 VpnToAddress(ULONG_PTR Vpn, UCHAR VpnHigh)
{
    UINT64 fullVpn = ((UINT64)VpnHigh << 32) | Vpn;
    return fullVpn << PAGE_SHIFT;
}

//
// IsAddressInRange - Check if address falls within range
//
BOOLEAN IsAddressInRange(PVOID Address, PVOID Start, SIZE_T Size)
{
    UINT64 addr = (UINT64)Address;
    UINT64 start = (UINT64)Start;
    UINT64 end = start + Size;

    return (addr >= start && addr < end);
}
