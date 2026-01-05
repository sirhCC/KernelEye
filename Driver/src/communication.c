//
// KernelEye Anti-Cheat Driver - Communication Module
// Handles IOCTL communication with user-mode service
//

#include "../include/driver.h"
#include "../include/communication.h"
#include "../include/memory_scanner.h"
#include "../include/hook_detector.h"
#include "../include/process_monitor.h"

//
// HandleIoctlRequest - Main IOCTL dispatcher
//
NTSTATUS HandleIoctlRequest(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpStack
)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG ioControlCode;
    PVOID inputBuffer;
    PVOID outputBuffer;
    ULONG inputBufferLength;
    ULONG outputBufferLength;
    ULONG bytesReturned = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    ioControlCode = IrpStack->Parameters.DeviceIoControl.IoControlCode;
    inputBufferLength = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLength = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;

    // For METHOD_BUFFERED, both input and output use the same system buffer
    inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    outputBuffer = Irp->AssociatedIrp.SystemBuffer;

    // Dispatch to appropriate handler
    switch (ioControlCode) {
        case IOCTL_KERNELEYE_GET_VERSION:
            status = HandleGetVersion(
                inputBuffer, inputBufferLength,
                outputBuffer, outputBufferLength,
                &bytesReturned
            );
            break;

        case IOCTL_KERNELEYE_INITIALIZE:
            status = HandleInitialize(
                inputBuffer, inputBufferLength,
                outputBuffer, outputBufferLength,
                &bytesReturned
            );
            break;

        case IOCTL_KERNELEYE_SHUTDOWN:
            status = HandleShutdown(
                inputBuffer, inputBufferLength,
                outputBuffer, outputBufferLength,
                &bytesReturned
            );
            break;

        case IOCTL_KERNELEYE_GET_STATISTICS:
            status = HandleGetStatistics(
                inputBuffer, inputBufferLength,
                outputBuffer, outputBufferLength,
                &bytesReturned
            );
            break;

        case IOCTL_KERNELEYE_HEARTBEAT:
            status = HandleHeartbeat(
                inputBuffer, inputBufferLength,
                outputBuffer, outputBufferLength,
                &bytesReturned
            );
            break;

        case IOCTL_KERNELEYE_CHECK_MEMORY:
            status = HandleCheckMemory(
                inputBuffer, inputBufferLength,
                outputBuffer, outputBufferLength,
                &bytesReturned
            );
            break;

        case IOCTL_KERNELEYE_CHECK_HOOKS:
            status = HandleCheckHooks(
                inputBuffer, inputBufferLength,
                outputBuffer, outputBufferLength,
                &bytesReturned
            );
            break;

        case IOCTL_KERNELEYE_START_PROTECTION:
            status = HandleStartProtection(
                inputBuffer, inputBufferLength,
                outputBuffer, outputBufferLength,
                &bytesReturned
            );
            break;

        case IOCTL_KERNELEYE_STOP_PROTECTION:
            status = HandleStopProtection(
                inputBuffer, inputBufferLength,
                outputBuffer, outputBufferLength,
                &bytesReturned
            );
            break;

        case IOCTL_KERNELEYE_SCAN_PROCESS:
        case IOCTL_KERNELEYE_SET_CONFIG:
        case IOCTL_KERNELEYE_GET_CONFIG:
        case IOCTL_KERNELEYE_GET_DETECTIONS:
        case IOCTL_KERNELEYE_ENUMERATE_DRIVERS:
        case IOCTL_KERNELEYE_ENUMERATE_MODULES:
        case IOCTL_KERNELEYE_CHECK_HOOKS:
        case IOCTL_KERNELEYE_VERIFY_DRIVER:
            KE_WARNING("IOCTL 0x%08X not yet implemented", ioControlCode);
            status = STATUS_NOT_IMPLEMENTED;
            break;

        default:
            KE_WARNING("Unknown IOCTL: 0x%08X", ioControlCode);
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    // Update IRP information
    Irp->IoStatus.Information = bytesReturned;

    return status;
}

//
// HandleGetVersion - Return driver version information
//
NTSTATUS HandleGetVersion(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
)
{
    PKERNELEYE_VERSION version;

    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferLength);

    KE_VERBOSE("HandleGetVersion called");

    if (OutputBufferLength < sizeof(KERNELEYE_VERSION)) {
        KE_ERROR("Output buffer too small for version structure");
        *BytesReturned = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    version = (PKERNELEYE_VERSION)OutputBuffer;
    version->Major = KERNELEYE_VERSION_MAJOR;
    version->Minor = KERNELEYE_VERSION_MINOR;
    version->Patch = KERNELEYE_VERSION_PATCH;
    version->Build = KERNELEYE_VERSION_BUILD;

    *BytesReturned = sizeof(KERNELEYE_VERSION);

    KE_INFO("Version requested: %d.%d.%d.%d", 
        version->Major, version->Minor, version->Patch, version->Build);

    return STATUS_SUCCESS;
}

//
// HandleInitialize - Initialize driver subsystems
//
NTSTATUS HandleInitialize(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
)
{
    NTSTATUS status;
    PDEVICE_EXTENSION deviceExtension;

    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    KE_INFO("HandleInitialize called");

    if (!g_DeviceObject) {
        KE_ERROR("Device object is NULL");
        *BytesReturned = 0;
        return STATUS_UNSUCCESSFUL;
    }

    deviceExtension = (PDEVICE_EXTENSION)g_DeviceObject->DeviceExtension;
    status = InitializeDriver(g_DeviceObject);

    *BytesReturned = 0;

    return status;
}

//
// HandleShutdown - Shutdown driver subsystems
//
NTSTATUS HandleShutdown(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
)
{
    PDEVICE_EXTENSION deviceExtension;

    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    KE_INFO("HandleShutdown called");

    if (!g_DeviceObject) {
        KE_ERROR("Device object is NULL");
        *BytesReturned = 0;
        return STATUS_UNSUCCESSFUL;
    }

    deviceExtension = (PDEVICE_EXTENSION)g_DeviceObject->DeviceExtension;
    deviceExtension->IsInitialized = FALSE;

    CleanupDriver();

    *BytesReturned = 0;

    return STATUS_SUCCESS;
}

//
// HandleGetStatistics - Return driver statistics
//
NTSTATUS HandleGetStatistics(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
)
{
    PDEVICE_EXTENSION deviceExtension;
    PKERNELEYE_STATISTICS stats;
    KIRQL oldIrql;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER uptime;

    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferLength);

    KE_VERBOSE("HandleGetStatistics called");

    if (OutputBufferLength < sizeof(KERNELEYE_STATISTICS)) {
        KE_ERROR("Output buffer too small for statistics structure");
        *BytesReturned = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (!g_DeviceObject) {
        KE_ERROR("Device object is NULL");
        *BytesReturned = 0;
        return STATUS_UNSUCCESSFUL;
    }

    deviceExtension = (PDEVICE_EXTENSION)g_DeviceObject->DeviceExtension;
    stats = (PKERNELEYE_STATISTICS)OutputBuffer;

    // Calculate uptime
    KeQuerySystemTime(&currentTime);
    uptime.QuadPart = (currentTime.QuadPart - deviceExtension->StartTime.QuadPart) / 10000000; // Convert to seconds

    // Copy statistics with lock
    KeAcquireSpinLock(&deviceExtension->StatisticsLock, &oldIrql);
    RtlCopyMemory(stats, &deviceExtension->Statistics, sizeof(KERNELEYE_STATISTICS));
    KeReleaseSpinLock(&deviceExtension->StatisticsLock, oldIrql);

    // Update uptime
    stats->UptimeSeconds = uptime.QuadPart;

    *BytesReturned = sizeof(KERNELEYE_STATISTICS);

    return STATUS_SUCCESS;
}

//
// HandleHeartbeat - Process heartbeat from user-mode service
//
NTSTATUS HandleHeartbeat(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
)
{
    PKERNELEYE_HEARTBEAT heartbeat;
    PDEVICE_EXTENSION deviceExtension;
    UINT64 currentTime;

    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (InputBufferLength < sizeof(KERNELEYE_HEARTBEAT)) {
        KE_ERROR("Input buffer too small for heartbeat structure");
        *BytesReturned = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    heartbeat = (PKERNELEYE_HEARTBEAT)InputBuffer;

    GetSystemTime(&currentTime);

    KE_VERBOSE("Heartbeat received from PID: %llu, Sequence: %u", 
        heartbeat->ProcessId, heartbeat->SequenceNumber);

    if (!g_DeviceObject) {
        KE_ERROR("Device object is NULL");
        *BytesReturned = 0;
        return STATUS_UNSUCCESSFUL;
    }

    deviceExtension = (PDEVICE_EXTENSION)g_DeviceObject->DeviceExtension;

    // TODO: Store last heartbeat time per process
    // TODO: Implement heartbeat timeout detection

    *BytesReturned = 0;

    return STATUS_SUCCESS;
}

//
// HandleCheckMemory - Check memory integrity of a process
//
NTSTATUS HandleCheckMemory(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
)
{
    NTSTATUS status;
    PKERNELEYE_SCAN_REQUEST request;
    PMEMORY_SCAN_CONTEXT scanContext = NULL;
    PKERNELEYE_SCAN_RESULT result;
    UINT32 totalRegions = 0;
    UINT32 suspiciousRegions = 0;
    UINT32 detectionCount = 0;

    KE_INFO("HandleCheckMemory called");

    if (InputBufferLength < sizeof(KERNELEYE_SCAN_REQUEST)) {
        KE_ERROR("Input buffer too small for scan request");
        *BytesReturned = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (OutputBufferLength < sizeof(KERNELEYE_SCAN_RESULT)) {
        KE_ERROR("Output buffer too small for scan result");
        *BytesReturned = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = (PKERNELEYE_SCAN_REQUEST)InputBuffer;
    result = (PKERNELEYE_SCAN_RESULT)OutputBuffer;

    KE_INFO("Scanning memory for PID=%llu, Flags=0x%08X",
        request->ProcessId, request->ScanFlags);

    // Perform memory scan
    status = ScanProcessMemory(
        request->ProcessId,
        request->ScanFlags & SCAN_FLAG_MEMORY,
        &scanContext
    );

    if (!NT_SUCCESS(status)) {
        KE_ERROR("Memory scan failed: 0x%08X", status);
        result->Status = status;
        result->Context = request->Context;
        result->DetectionCount = 0;
        result->ScanDuration = 0;
        result->TotalChecks = 0;
        result->ResultDataSize = 0;
        *BytesReturned = sizeof(KERNELEYE_SCAN_RESULT);
        return STATUS_SUCCESS; // Return success but with error in result
    }

    // Get statistics
    GetMemoryScanStatistics(scanContext, &totalRegions, &suspiciousRegions, &detectionCount);

    // Fill result
    RtlZeroMemory(result, sizeof(KERNELEYE_SCAN_RESULT));
    result->Context = request->Context;
    result->Status = KERNELEYE_STATUS_SUCCESS;
    result->DetectionCount = detectionCount;
    result->ScanDuration = 0; // TODO: Track actual duration
    result->TotalChecks = totalRegions;
    result->ResultDataSize = 0; // TODO: Serialize detections

    KE_INFO("Memory scan complete: %u regions, %u suspicious, %u detections",
        totalRegions, suspiciousRegions, detectionCount);

    // Cleanup
    FreeMemoryScanContext(scanContext);

    *BytesReturned = sizeof(KERNELEYE_SCAN_RESULT);
    return STATUS_SUCCESS;
}

//
// HandleCheckHooks - Check for hooks in a process
//
NTSTATUS HandleCheckHooks(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
)
{
    NTSTATUS status;
    PKERNELEYE_SCAN_REQUEST request;
    PHOOK_SCAN_CONTEXT scanContext = NULL;
    PKERNELEYE_SCAN_RESULT result;
    UINT32 functionsChecked = 0;
    UINT32 hooksFound = 0;

    KE_INFO("HandleCheckHooks called");

    if (InputBufferLength < sizeof(KERNELEYE_SCAN_REQUEST)) {
        KE_ERROR("Input buffer too small for scan request");
        *BytesReturned = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (OutputBufferLength < sizeof(KERNELEYE_SCAN_RESULT)) {
        KE_ERROR("Output buffer too small for scan result");
        *BytesReturned = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = (PKERNELEYE_SCAN_REQUEST)InputBuffer;
    result = (PKERNELEYE_SCAN_RESULT)OutputBuffer;

    KE_INFO("Scanning hooks for PID=%llu, Flags=0x%08X",
        request->ProcessId, request->ScanFlags);

    status = ScanProcessHooks(
        request->ProcessId,
        request->ScanFlags & SCAN_FLAG_HOOKS,
        &scanContext
    );

    if (!NT_SUCCESS(status)) {
        KE_ERROR("Hook scan failed: 0x%08X", status);
        result->Status = status;
        result->Context = request->Context;
        result->DetectionCount = 0;
        result->ScanDuration = 0;
        result->TotalChecks = 0;
        result->ResultDataSize = 0;
        *BytesReturned = sizeof(KERNELEYE_SCAN_RESULT);
        return STATUS_SUCCESS;
    }

    GetHookScanStatistics(scanContext, &functionsChecked, &hooksFound);

    RtlZeroMemory(result, sizeof(KERNELEYE_SCAN_RESULT));
    result->Context = request->Context;
    result->Status = KERNELEYE_STATUS_SUCCESS;
    result->DetectionCount = hooksFound;
    result->ScanDuration = 0;
    result->TotalChecks = functionsChecked;
    result->ResultDataSize = 0;

    KE_INFO("Hook scan complete: %u functions checked, %u hooks found",
        functionsChecked, hooksFound);

    FreeHookScanContext(scanContext);

    *BytesReturned = sizeof(KERNELEYE_SCAN_RESULT);
    return STATUS_SUCCESS;
}

//
// ValidateMessageHeader - Validate message header integrity
//
BOOLEAN ValidateMessageHeader(
    _In_ PKERNELEYE_MESSAGE_HEADER Header,
    _In_ ULONG BufferSize
)
{
    UINT32 calculatedChecksum;

    if (BufferSize < sizeof(KERNELEYE_MESSAGE_HEADER)) {
        KE_ERROR("Buffer too small for message header");
        return FALSE;
    }

    if (Header->Magic != KERNELEYE_MESSAGE_MAGIC) {
        KE_ERROR("Invalid message magic: 0x%08X", Header->Magic);
        return FALSE;
    }

    if (Header->MessageSize > BufferSize) {
        KE_ERROR("Message size exceeds buffer size: %u > %u", 
            Header->MessageSize, BufferSize);
        return FALSE;
    }

    // Validate checksum (simple for now, will be replaced with HMAC)
    calculatedChecksum = CalculateSimpleChecksum(
        (BYTE*)Header + sizeof(KERNELEYE_MESSAGE_HEADER),
        Header->MessageSize - sizeof(KERNELEYE_MESSAGE_HEADER)
    );

    if (calculatedChecksum != Header->Checksum) {
        KE_ERROR("Checksum mismatch: expected 0x%08X, got 0x%08X", 
            Header->Checksum, calculatedChecksum);
        return FALSE;
    }

    return TRUE;
}

//
// BuildResponse - Build a response message
//
NTSTATUS BuildResponse(
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _In_ UINT32 MessageType,
    _In_ PVOID ResponseData,
    _In_ ULONG ResponseDataSize,
    _Out_ PULONG BytesReturned
)
{
    PKERNELEYE_MESSAGE_HEADER header;
    ULONG totalSize;
    UINT32 checksum;
    PDEVICE_EXTENSION deviceExtension;

    totalSize = sizeof(KERNELEYE_MESSAGE_HEADER) + ResponseDataSize;

    if (OutputBufferLength < totalSize) {
        KE_ERROR("Output buffer too small: %u < %u", OutputBufferLength, totalSize);
        *BytesReturned = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    header = (PKERNELEYE_MESSAGE_HEADER)OutputBuffer;
    header->Magic = KERNELEYE_MESSAGE_MAGIC;
    header->Version = (KERNELEYE_VERSION_MAJOR << 16) | KERNELEYE_VERSION_MINOR;
    header->MessageType = MessageType;
    header->MessageSize = totalSize;
    GetSystemTime(&header->Timestamp);

    if (g_DeviceObject) {
        deviceExtension = (PDEVICE_EXTENSION)g_DeviceObject->DeviceExtension;
        header->SequenceNumber = InterlockedIncrement(&deviceExtension->NextSequenceNumber);
    } else {
        header->SequenceNumber = 0;
    }

    // Copy response data
    if (ResponseDataSize > 0 && ResponseData) {
        RtlCopyMemory(
            (BYTE*)OutputBuffer + sizeof(KERNELEYE_MESSAGE_HEADER),
            ResponseData,
            ResponseDataSize
        );
    }

    // Calculate checksum
    checksum = CalculateSimpleChecksum(
        (BYTE*)OutputBuffer + sizeof(KERNELEYE_MESSAGE_HEADER),
        ResponseDataSize
    );
    header->Checksum = checksum;

    *BytesReturned = totalSize;

    return STATUS_SUCCESS;
}

//
// HandleStartProtection - Start protecting a process
//
NTSTATUS HandleStartProtection(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
)
{
    NTSTATUS status;
    UINT64 processId;
    UINT32 protectionFlags;

    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (InputBufferLength < sizeof(UINT64) + sizeof(UINT32)) {
        KE_ERROR("Invalid input buffer size for START_PROTECTION");
        return STATUS_INVALID_PARAMETER;
    }

    processId = *((UINT64*)InputBuffer);
    protectionFlags = *((UINT32*)((BYTE*)InputBuffer + sizeof(UINT64)));

    KE_INFO("Starting protection for PID=%llu with flags=0x%08X", processId, protectionFlags);

    status = ProtectProcess(processId, protectionFlags);
    if (!NT_SUCCESS(status)) {
        KE_ERROR("Failed to protect process: 0x%08X", status);
        return status;
    }

    *BytesReturned = 0;
    return STATUS_SUCCESS;
}

//
// HandleStopProtection - Stop protecting a process
//
NTSTATUS HandleStopProtection(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
)
{
    NTSTATUS status;
    UINT64 processId;

    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (InputBufferLength < sizeof(UINT64)) {
        KE_ERROR("Invalid input buffer size for STOP_PROTECTION");
        return STATUS_INVALID_PARAMETER;
    }

    processId = *((UINT64*)InputBuffer);

    KE_INFO("Stopping protection for PID=%llu", processId);

    status = UnprotectProcess(processId);
    if (!NT_SUCCESS(status)) {
        KE_ERROR("Failed to unprotect process: 0x%08X", status);
        return status;
    }

    *BytesReturned = 0;
    return STATUS_SUCCESS;
}

