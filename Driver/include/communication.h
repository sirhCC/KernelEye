#pragma once

#include <ntddk.h>
#include "../../../Common/structures.h"
#include "../../../Common/protocol.h"

//
// KernelEye Driver - Communication Module
//

// IOCTL handler function
NTSTATUS HandleIoctlRequest(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpStack
);

// Individual IOCTL handlers
NTSTATUS HandleGetVersion(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
);

NTSTATUS HandleInitialize(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
);

NTSTATUS HandleShutdown(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
);

NTSTATUS HandleGetStatistics(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
);

NTSTATUS HandleHeartbeat(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
);

// Validation functions
BOOLEAN ValidateMessageHeader(
    _In_ PKERNELEYE_MESSAGE_HEADER Header,
    _In_ ULONG BufferSize
);

NTSTATUS BuildResponse(
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _In_ UINT32 MessageType,
    _In_ PVOID ResponseData,
    _In_ ULONG ResponseDataSize,
    _Out_ PULONG BytesReturned
);
