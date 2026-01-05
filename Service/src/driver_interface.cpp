//
// KernelEye Service - Driver Interface Implementation
//

#include "../include/driver_interface.h"
#include "../include/logger.h"
#include <iostream>

DriverInterface::DriverInterface()
    : m_hDevice(INVALID_HANDLE_VALUE)
    , m_lastError(ERROR_SUCCESS)
    , m_devicePath(USER_DEVICE_NAME)
{
}

DriverInterface::~DriverInterface()
{
    Disconnect();
}

//
// Connect - Open handle to the kernel driver
//
bool DriverInterface::Connect()
{
    if (IsConnected()) {
        LOG_WARNING("Already connected to driver");
        return true;
    }

    LOG_INFO("Connecting to driver: %ls", m_devicePath.c_str());

    m_hDevice = CreateFileW(
        m_devicePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (m_hDevice == INVALID_HANDLE_VALUE) {
        m_lastError = GetLastError();
        LOG_ERROR("Failed to open driver device: 0x%08X", m_lastError);
        return false;
    }

    LOG_INFO("Successfully connected to driver");
    m_lastError = ERROR_SUCCESS;
    return true;
}

//
// Disconnect - Close handle to the kernel driver
//
void DriverInterface::Disconnect()
{
    if (IsConnected()) {
        LOG_INFO("Disconnecting from driver");
        CloseHandle(m_hDevice);
        m_hDevice = INVALID_HANDLE_VALUE;
    }
}

//
// GetVersion - Retrieve driver version information
//
bool DriverInterface::GetVersion(KERNELEYE_VERSION& version)
{
    DWORD bytesReturned = 0;

    LOG_VERBOSE("Getting driver version");

    if (!SendIoctl(
        IOCTL_KERNELEYE_GET_VERSION,
        NULL,
        0,
        &version,
        sizeof(KERNELEYE_VERSION),
        &bytesReturned))
    {
        LOG_ERROR("Failed to get driver version");
        return false;
    }

    LOG_INFO("Driver version: %u.%u.%u.%u", 
        version.Major, version.Minor, version.Patch, version.Build);

    return true;
}

//
// Initialize - Initialize the driver subsystems
//
bool DriverInterface::Initialize()
{
    DWORD bytesReturned = 0;

    LOG_INFO("Initializing driver");

    if (!SendIoctl(
        IOCTL_KERNELEYE_INITIALIZE,
        NULL,
        0,
        NULL,
        0,
        &bytesReturned))
    {
        LOG_ERROR("Failed to initialize driver");
        return false;
    }

    LOG_INFO("Driver initialized successfully");
    return true;
}

//
// Shutdown - Shutdown the driver subsystems
//
bool DriverInterface::Shutdown()
{
    DWORD bytesReturned = 0;

    LOG_INFO("Shutting down driver");

    if (!SendIoctl(
        IOCTL_KERNELEYE_SHUTDOWN,
        NULL,
        0,
        NULL,
        0,
        &bytesReturned))
    {
        LOG_ERROR("Failed to shutdown driver");
        return false;
    }

    LOG_INFO("Driver shutdown successfully");
    return true;
}

//
// GetStatistics - Retrieve driver statistics
//
bool DriverInterface::GetStatistics(KERNELEYE_STATISTICS& stats)
{
    DWORD bytesReturned = 0;

    LOG_VERBOSE("Getting driver statistics");

    if (!SendIoctl(
        IOCTL_KERNELEYE_GET_STATISTICS,
        NULL,
        0,
        &stats,
        sizeof(KERNELEYE_STATISTICS),
        &bytesReturned))
    {
        LOG_ERROR("Failed to get driver statistics");
        return false;
    }

    return true;
}

//
// SendHeartbeat - Send heartbeat to driver
//
bool DriverInterface::SendHeartbeat(UINT64 processId, UINT32 sequenceNumber)
{
    KERNELEYE_HEARTBEAT heartbeat = {0};
    DWORD bytesReturned = 0;

    heartbeat.Timestamp = GetTickCount64();
    heartbeat.ProcessId = processId;
    heartbeat.SequenceNumber = sequenceNumber;
    heartbeat.Status = KERNELEYE_STATUS_SUCCESS;

    LOG_VERBOSE("Sending heartbeat: PID=%llu, Seq=%u", processId, sequenceNumber);

    if (!SendIoctl(
        IOCTL_KERNELEYE_HEARTBEAT,
        &heartbeat,
        sizeof(KERNELEYE_HEARTBEAT),
        NULL,
        0,
        &bytesReturned))
    {
        LOG_ERROR("Failed to send heartbeat");
        return false;
    }

    return true;
}

//
// SetConfig - Set driver configuration
//
bool DriverInterface::SetConfig(const KERNELEYE_CONFIG& config)
{
    DWORD bytesReturned = 0;

    LOG_INFO("Setting driver configuration");

    if (!SendIoctl(
        IOCTL_KERNELEYE_SET_CONFIG,
        (LPVOID)&config,
        sizeof(KERNELEYE_CONFIG),
        NULL,
        0,
        &bytesReturned))
    {
        LOG_ERROR("Failed to set driver configuration");
        return false;
    }

    return true;
}

//
// GetConfig - Get driver configuration
//
bool DriverInterface::GetConfig(KERNELEYE_CONFIG& config)
{
    DWORD bytesReturned = 0;

    LOG_VERBOSE("Getting driver configuration");

    if (!SendIoctl(
        IOCTL_KERNELEYE_GET_CONFIG,
        NULL,
        0,
        &config,
        sizeof(KERNELEYE_CONFIG),
        &bytesReturned))
    {
        LOG_ERROR("Failed to get driver configuration");
        return false;
    }

    return true;
}

//
// ScanProcess - Request process scan
//
bool DriverInterface::ScanProcess(const KERNELEYE_SCAN_REQUEST& request, KERNELEYE_SCAN_RESULT& result)
{
    DWORD bytesReturned = 0;

    LOG_INFO("Requesting process scan: PID=%llu, Flags=0x%08X", 
        request.ProcessId, request.ScanFlags);

    if (!SendIoctl(
        IOCTL_KERNELEYE_SCAN_PROCESS,
        (LPVOID)&request,
        sizeof(KERNELEYE_SCAN_REQUEST),
        &result,
        sizeof(KERNELEYE_SCAN_RESULT),
        &bytesReturned))
    {
        LOG_ERROR("Failed to scan process");
        return false;
    }

    return true;
}

//
// StartProtection - Start protecting a process
//
bool DriverInterface::StartProtection(UINT64 processId, UINT32 flags)
{
    KERNELEYE_PROTECTION_REQUEST request = {0};
    DWORD bytesReturned = 0;

    request.ProcessId = processId;
    request.ProtectionFlags = flags;
    request.Enable = TRUE;

    LOG_INFO("Starting protection for PID=%llu, Flags=0x%08X", processId, flags);

    if (!SendIoctl(
        IOCTL_KERNELEYE_START_PROTECTION,
        &request,
        sizeof(KERNELEYE_PROTECTION_REQUEST),
        NULL,
        0,
        &bytesReturned))
    {
        LOG_ERROR("Failed to start protection");
        return false;
    }

    return true;
}

//
// StopProtection - Stop protecting a process
//
bool DriverInterface::StopProtection(UINT64 processId)
{
    KERNELEYE_PROTECTION_REQUEST request = {0};
    DWORD bytesReturned = 0;

    request.ProcessId = processId;
    request.Enable = FALSE;

    LOG_INFO("Stopping protection for PID=%llu", processId);

    if (!SendIoctl(
        IOCTL_KERNELEYE_STOP_PROTECTION,
        &request,
        sizeof(KERNELEYE_PROTECTION_REQUEST),
        NULL,
        0,
        &bytesReturned))
    {
        LOG_ERROR("Failed to stop protection");
        return false;
    }

    return true;
}

//
// GetLastErrorMessage - Get last error as string
//
std::wstring DriverInterface::GetLastErrorMessage() const
{
    if (m_lastError == ERROR_SUCCESS) {
        return L"Success";
    }

    wchar_t* messageBuffer = nullptr;
    size_t size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        m_lastError,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&messageBuffer,
        0,
        NULL
    );

    std::wstring message(messageBuffer, size);
    LocalFree(messageBuffer);

    return message;
}

//
// SendIoctl - Send IOCTL request to driver
//
bool DriverInterface::SendIoctl(
    DWORD ioctlCode,
    LPVOID inputBuffer,
    DWORD inputSize,
    LPVOID outputBuffer,
    DWORD outputSize,
    LPDWORD bytesReturned)
{
    if (!IsConnected()) {
        LOG_ERROR("Not connected to driver");
        m_lastError = ERROR_NOT_READY;
        return false;
    }

    DWORD bytes = 0;
    BOOL result = DeviceIoControl(
        m_hDevice,
        ioctlCode,
        inputBuffer,
        inputSize,
        outputBuffer,
        outputSize,
        &bytes,
        NULL
    );

    if (bytesReturned) {
        *bytesReturned = bytes;
    }

    if (!result) {
        m_lastError = GetLastError();
        LOG_ERROR("DeviceIoControl failed: IOCTL=0x%08X, Error=0x%08X", 
            ioctlCode, m_lastError);
        return false;
    }

    m_lastError = ERROR_SUCCESS;
    return true;
}
