//
// KernelEye Anti-Cheat Driver - Entry Point
// Copyright (c) 2026 KernelEye Project
//

#include "../include/driver.h"
#include "../include/memory_scanner.h"

// Global variables
PDEVICE_OBJECT g_DeviceObject = NULL;
BOOLEAN g_DriverUnloading = FALSE;

//
// DriverEntry - Driver initialization entry point
//
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLinkName;
    PDEVICE_EXTENSION deviceExtension;

    UNREFERENCED_PARAMETER(RegistryPath);

    KE_INFO("KernelEye driver loading...");
    KE_INFO("Version: %d.%d.%d.%d", 
        KERNELEYE_VERSION_MAJOR, 
        KERNELEYE_VERSION_MINOR, 
        KERNELEYE_VERSION_PATCH, 
        KERNELEYE_VERSION_BUILD);

    // Initialize device name and symbolic link
    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    RtlInitUnicodeString(&symbolicLinkName, SYMBOLIC_LINK_NAME);

    // Create device object
    status = IoCreateDevice(
        DriverObject,
        sizeof(DEVICE_EXTENSION),
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject
    );

    if (!NT_SUCCESS(status)) {
        KE_ERROR("Failed to create device object: 0x%08X", status);
        return status;
    }

    KE_INFO("Device object created successfully");

    // Initialize device extension
    deviceExtension = (PDEVICE_EXTENSION)g_DeviceObject->DeviceExtension;
    RtlZeroMemory(deviceExtension, sizeof(DEVICE_EXTENSION));
    
    deviceExtension->DeviceObject = g_DeviceObject;
    deviceExtension->IsInitialized = FALSE;
    deviceExtension->NextSequenceNumber = 1;
    KeInitializeSpinLock(&deviceExtension->StatisticsLock);
    KeQuerySystemTime(&deviceExtension->StartTime);

    // Initialize default configuration
    deviceExtension->Config.ScanIntervalCritical = SCAN_INTERVAL_CRITICAL;
    deviceExtension->Config.ScanIntervalStandard = SCAN_INTERVAL_STANDARD;
    deviceExtension->Config.ScanIntervalDeep = SCAN_INTERVAL_DEEP;
    deviceExtension->Config.HeartbeatInterval = HEARTBEAT_INTERVAL;
    deviceExtension->Config.DebugLevel = KERNELEYE_DEBUG_LEVEL;
    deviceExtension->Config.EnableSelfProtection = TRUE;
    deviceExtension->Config.EnableBehavioralAnalysis = FALSE;  // Not implemented yet
    deviceExtension->Config.EnableMachineLearning = FALSE;     // Not implemented yet
    deviceExtension->Config.MaxCpuUsagePercent = 5;
    deviceExtension->Config.MaxMemoryUsageMB = 50;

    // Create symbolic link
    RtlCopyUnicodeString(&deviceExtension->SymbolicLinkName, &symbolicLinkName);
    status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);

    if (!NT_SUCCESS(status)) {
        KE_ERROR("Failed to create symbolic link: 0x%08X", status);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    KE_INFO("Symbolic link created successfully");

    // Set up dispatch routines
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    // Set device flags
    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    KE_INFO("KernelEye driver loaded successfully");

    return STATUS_SUCCESS;
}

//
// DriverUnload - Driver cleanup and unload
//
VOID DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    PDEVICE_EXTENSION deviceExtension;
    UNICODE_STRING symbolicLinkName;

    UNREFERENCED_PARAMETER(DriverObject);

    KE_INFO("KernelEye driver unloading...");

    g_DriverUnloading = TRUE;

    if (g_DeviceObject) {
        deviceExtension = (PDEVICE_EXTENSION)g_DeviceObject->DeviceExtension;

        // Cleanup driver resources
        CleanupDriver();

        // Delete symbolic link
        RtlInitUnicodeString(&symbolicLinkName, SYMBOLIC_LINK_NAME);
        IoDeleteSymbolicLink(&symbolicLinkName);
        KE_INFO("Symbolic link deleted");

        // Delete device object
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        KE_INFO("Device object deleted");
    }

    KE_INFO("KernelEye driver unloaded successfully");
}

//
// DeviceCreate - Handle IRP_MJ_CREATE
//
NTSTATUS DeviceCreate(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    KE_VERBOSE("Device opened");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

//
// DeviceClose - Handle IRP_MJ_CLOSE
//
NTSTATUS DeviceClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    KE_VERBOSE("Device closed");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

//
// DeviceControl - Handle IRP_MJ_DEVICE_CONTROL
//
NTSTATUS DeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    NTSTATUS status;
    PIO_STACK_LOCATION irpStack;
    ULONG bytesReturned = 0;

    irpStack = IoGetCurrentIrpStackLocation(Irp);

    KE_VERBOSE("IOCTL received: 0x%08X", irpStack->Parameters.DeviceIoControl.IoControlCode);

    // Handle the IOCTL request
    status = HandleIoctlRequest(DeviceObject, Irp, irpStack);

    // Complete the IRP
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

//
// InitializeDriver - Initialize driver subsystems
//
NTSTATUS InitializeDriver(
    _In_ PDEVICE_OBJECT DeviceObject
)
{
    PDEVICE_EXTENSION deviceExtension;

    deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

    if (deviceExtension->IsInitialized) {
        KE_WARNING("Driver already initialized");
        return STATUS_SUCCESS;
    }

    KE_INFO("Initializing driver subsystems...");

    // Initialize memory scanner
    status = MemoryScannerInitialize();
    if (!NT_SUCCESS(status)) {
        KE_ERROR("Failed to initialize memory scanner: 0x%08X", status);
        return status;
    }

    // TODO: Initialize process monitor
    // TODO: Initialize driver verifier
    // TODO: Initialize hook detector
    // TODO: Register callbacks

    deviceExtension->IsInitialized = TRUE;
    RtlZeroMemory(&deviceExtension->Statistics, sizeof(KERNELEYE_STATISTICS));

    KE_INFO("Driver subsystems initialized successfully");

    return STATUS_SUCCESS;
}

//
// CleanupDriver - Cleanup driver resources
//
VOID CleanupDriver(VOID)
{
    KE_INFO("Cleaning up driver resources...");

    // TODO: Unregister callbacks
    
    // Cleanup memory scanner
    MemoryScannerCleanup();
    
    // TODO: Cleanup process monitor
    // TODO: Cleanup driver verifier
    // TODO: Cleanup hook detector

    KE_INFO("Driver resources cleaned up");
}

//
// GetSystemTime - Get current system time as timestamp
//
VOID GetSystemTime(
    _Out_ PUINT64 Timestamp
)
{
    LARGE_INTEGER systemTime;
    KeQuerySystemTime(&systemTime);
    *Timestamp = systemTime.QuadPart;
}
