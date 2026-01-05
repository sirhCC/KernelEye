//
// KernelEye Anti-Cheat Client Library
// Implementation
//

#include "../include/KernelEyeClient.h"
#include "../../Common/constants.h"
#include "../../Common/structures.h"
#include "../../Common/protocol.h"

#include <windows.h>
#include <stdio.h>
#include <string>
#include <mutex>
#include <thread>
#include <atomic>

// Internal state
static struct {
    std::atomic<bool> initialized{false};
    std::atomic<bool> protected{false};
    std::atomic<bool> scanning{false};
    
    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    HANDLE heartbeatThread = nullptr;
    std::atomic<bool> stopHeartbeat{false};
    
    KERNELEYE_CONFIG config{};
    KERNELEYE_STATS stats{};
    
    KERNELEYE_DETECTION_CALLBACK detectionCallback = nullptr;
    void* detectionUserData = nullptr;
    
    KERNELEYE_HEARTBEAT_CALLBACK heartbeatCallback = nullptr;
    void* heartbeatUserData = nullptr;
    
    std::mutex mutex;
    std::string lastError;
    
    LARGE_INTEGER startTime{};
} g_State;

// Version string
static char g_VersionString[64] = {0};
static char g_DriverVersionString[64] = {0};

// Forward declarations
static DWORD WINAPI HeartbeatThreadProc(LPVOID param);
static KERNELEYE_STATUS ConnectToDriver();
static void DisconnectFromDriver();
static void SetLastError(const char* error);
static KERNELEYE_STATUS SendIoctl(ULONG ioctlCode, void* input, ULONG inputSize, void* output, ULONG outputSize);

//
// KernelEye_Initialize
//
KERNELEYE_API KERNELEYE_STATUS KernelEye_Initialize(
    const KERNELEYE_CONFIG* config
)
{
    if (g_State.initialized) {
        return KERNELEYE_ERROR_ALREADY_INITIALIZED;
    }

    std::lock_guard<std::mutex> lock(g_State.mutex);

    // Store configuration
    if (config) {
        g_State.config = *config;
    } else {
        // Default configuration
        g_State.config.HeartbeatIntervalMs = 5000;
        g_State.config.ScanIntervalMs = 60000;
        g_State.config.EnableRealtimeScanning = true;
        g_State.config.EnableBehavioralAnalysis = false;
        g_State.config.EnableHardwareChecks = false;
        g_State.config.AutoProtectProcess = true;
        g_State.config.LogLevel = 2;
    }

    // Connect to driver
    KERNELEYE_STATUS status = ConnectToDriver();
    if (status != KERNELEYE_SUCCESS) {
        SetLastError("Failed to connect to driver");
        return status;
    }

    // Initialize driver
    status = SendIoctl(IOCTL_KERNELEYE_INITIALIZE, nullptr, 0, nullptr, 0);
    if (status != KERNELEYE_SUCCESS) {
        DisconnectFromDriver();
        SetLastError("Failed to initialize driver");
        return status;
    }

    // Start protection if auto-protect enabled
    if (g_State.config.AutoProtectProcess) {
        KernelEye_StartProtection();
    }

    // Start heartbeat thread
    g_State.stopHeartbeat = false;
    g_State.heartbeatThread = CreateThread(nullptr, 0, HeartbeatThreadProc, nullptr, 0, nullptr);

    QueryPerformanceCounter(&g_State.startTime);
    g_State.initialized = true;

    return KERNELEYE_SUCCESS;
}

//
// KernelEye_Shutdown
//
KERNELEYE_API void KernelEye_Shutdown(void)
{
    if (!g_State.initialized) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_State.mutex);

    // Stop heartbeat thread
    g_State.stopHeartbeat = true;
    if (g_State.heartbeatThread) {
        WaitForSingleObject(g_State.heartbeatThread, 5000);
        CloseHandle(g_State.heartbeatThread);
        g_State.heartbeatThread = nullptr;
    }

    // Stop protection
    if (g_State.protected) {
        KernelEye_StopProtection();
    }

    // Shutdown driver
    SendIoctl(IOCTL_KERNELEYE_SHUTDOWN, nullptr, 0, nullptr, 0);

    DisconnectFromDriver();

    g_State.initialized = false;
}

//
// KernelEye_IsInitialized
//
KERNELEYE_API bool KernelEye_IsInitialized(void)
{
    return g_State.initialized;
}

//
// KernelEye_StartProtection
//
KERNELEYE_API KERNELEYE_STATUS KernelEye_StartProtection(void)
{
    if (!g_State.initialized) {
        return KERNELEYE_ERROR_NOT_INITIALIZED;
    }

    uint64_t processId = GetCurrentProcessId();
    uint32_t flags = 0xFFFFFFFF; // All protection flags

    struct {
        uint64_t processId;
        uint32_t flags;
    } input = { processId, flags };

    KERNELEYE_STATUS status = SendIoctl(
        IOCTL_KERNELEYE_START_PROTECTION,
        &input,
        sizeof(input),
        nullptr,
        0
    );

    if (status == KERNELEYE_SUCCESS) {
        g_State.protected = true;
    }

    return status;
}

//
// KernelEye_StopProtection
//
KERNELEYE_API KERNELEYE_STATUS KernelEye_StopProtection(void)
{
    if (!g_State.initialized) {
        return KERNELEYE_ERROR_NOT_INITIALIZED;
    }

    uint64_t processId = GetCurrentProcessId();

    KERNELEYE_STATUS status = SendIoctl(
        IOCTL_KERNELEYE_STOP_PROTECTION,
        &processId,
        sizeof(processId),
        nullptr,
        0
    );

    if (status == KERNELEYE_SUCCESS) {
        g_State.protected = false;
    }

    return status;
}

//
// KernelEye_IsProtected
//
KERNELEYE_API bool KernelEye_IsProtected(void)
{
    return g_State.protected;
}

//
// KernelEye_ScanMemory
//
KERNELEYE_API KERNELEYE_STATUS KernelEye_ScanMemory(void)
{
    if (!g_State.initialized) {
        return KERNELEYE_ERROR_NOT_INITIALIZED;
    }

    KERNELEYE_SCAN_REQUEST request{};
    request.ProcessId = GetCurrentProcessId();
    request.ScanFlags = SCAN_FLAG_CHECK_PROTECTION | SCAN_FLAG_VALIDATE_PE | SCAN_FLAG_CALCULATE_CHECKSUM;
    request.TimeoutMs = 5000;

    KERNELEYE_SCAN_RESULT result{};

    KERNELEYE_STATUS status = SendIoctl(
        IOCTL_KERNELEYE_CHECK_MEMORY,
        &request,
        sizeof(request),
        &result,
        sizeof(result)
    );

    if (status == KERNELEYE_SUCCESS) {
        g_State.stats.MemoryScans++;
        g_State.stats.TotalScans++;
        g_State.stats.TotalDetections += result.DetectionCount;
    }

    return status;
}

//
// KernelEye_ScanHooks
//
KERNELEYE_API KERNELEYE_STATUS KernelEye_ScanHooks(void)
{
    if (!g_State.initialized) {
        return KERNELEYE_ERROR_NOT_INITIALIZED;
    }

    KERNELEYE_SCAN_REQUEST request{};
    request.ProcessId = GetCurrentProcessId();
    request.ScanFlags = SCAN_FLAG_CHECK_INLINE_HOOKS | SCAN_FLAG_CHECK_IAT_HOOKS;
    request.TimeoutMs = 5000;

    KERNELEYE_SCAN_RESULT result{};

    KERNELEYE_STATUS status = SendIoctl(
        IOCTL_KERNELEYE_CHECK_HOOKS,
        &request,
        sizeof(request),
        &result,
        sizeof(result)
    );

    if (status == KERNELEYE_SUCCESS) {
        g_State.stats.HookScans++;
        g_State.stats.TotalScans++;
        g_State.stats.TotalDetections += result.DetectionCount;
    }

    return status;
}

//
// KernelEye_ScanFull
//
KERNELEYE_API KERNELEYE_STATUS KernelEye_ScanFull(void)
{
    KERNELEYE_STATUS status1 = KernelEye_ScanMemory();
    KERNELEYE_STATUS status2 = KernelEye_ScanHooks();

    if (status1 != KERNELEYE_SUCCESS) return status1;
    if (status2 != KERNELEYE_SUCCESS) return status2;

    return KERNELEYE_SUCCESS;
}

//
// KernelEye_SetDetectionCallback
//
KERNELEYE_API KERNELEYE_STATUS KernelEye_SetDetectionCallback(
    KERNELEYE_DETECTION_CALLBACK callback,
    void* userData
)
{
    std::lock_guard<std::mutex> lock(g_State.mutex);
    g_State.detectionCallback = callback;
    g_State.detectionUserData = userData;
    return KERNELEYE_SUCCESS;
}

//
// KernelEye_SetHeartbeatCallback
//
KERNELEYE_API KERNELEYE_STATUS KernelEye_SetHeartbeatCallback(
    KERNELEYE_HEARTBEAT_CALLBACK callback,
    void* userData
)
{
    std::lock_guard<std::mutex> lock(g_State.mutex);
    g_State.heartbeatCallback = callback;
    g_State.heartbeatUserData = userData;
    return KERNELEYE_SUCCESS;
}

//
// KernelEye_GetConfig
//
KERNELEYE_API KERNELEYE_STATUS KernelEye_GetConfig(
    KERNELEYE_CONFIG* config
)
{
    if (!config) {
        return KERNELEYE_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(g_State.mutex);
    *config = g_State.config;
    return KERNELEYE_SUCCESS;
}

//
// KernelEye_SetConfig
//
KERNELEYE_API KERNELEYE_STATUS KernelEye_SetConfig(
    const KERNELEYE_CONFIG* config
)
{
    if (!config) {
        return KERNELEYE_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(g_State.mutex);
    g_State.config = *config;
    return KERNELEYE_SUCCESS;
}

//
// KernelEye_GetStatistics
//
KERNELEYE_API KERNELEYE_STATUS KernelEye_GetStatistics(
    KERNELEYE_STATS* stats
)
{
    if (!stats || !g_State.initialized) {
        return KERNELEYE_ERROR_INVALID_PARAMETER;
    }

    KERNELEYE_STATISTICS driverStats{};
    KERNELEYE_STATUS status = SendIoctl(
        IOCTL_KERNELEYE_GET_STATISTICS,
        nullptr,
        0,
        &driverStats,
        sizeof(driverStats)
    );

    if (status == KERNELEYE_SUCCESS) {
        std::lock_guard<std::mutex> lock(g_State.mutex);
        
        stats->TotalScans = g_State.stats.TotalScans;
        stats->TotalDetections = g_State.stats.TotalDetections;
        stats->MemoryScans = g_State.stats.MemoryScans;
        stats->HookScans = g_State.stats.HookScans;
        stats->ProcessEvents = driverStats.ProcessCreations + driverStats.ThreadCreations;
        
        LARGE_INTEGER now, freq;
        QueryPerformanceCounter(&now);
        QueryPerformanceFrequency(&freq);
        stats->UptimeSeconds = (now.QuadPart - g_State.startTime.QuadPart) / freq.QuadPart;
    }

    return status;
}

//
// KernelEye_ResetStatistics
//
KERNELEYE_API KERNELEYE_STATUS KernelEye_ResetStatistics(void)
{
    std::lock_guard<std::mutex> lock(g_State.mutex);
    g_State.stats = {};
    return KERNELEYE_SUCCESS;
}

//
// KernelEye_GetVersion
//
KERNELEYE_API const char* KernelEye_GetVersion(void)
{
    snprintf(g_VersionString, sizeof(g_VersionString), "%d.%d.%d",
        KERNELEYE_CLIENT_VERSION_MAJOR,
        KERNELEYE_CLIENT_VERSION_MINOR,
        KERNELEYE_CLIENT_VERSION_PATCH);
    return g_VersionString;
}

//
// KernelEye_GetDriverVersion
//
KERNELEYE_API const char* KernelEye_GetDriverVersion(void)
{
    if (!g_State.initialized) {
        return "Not connected";
    }

    KERNELEYE_VERSION_INFO version{};
    KERNELEYE_STATUS status = SendIoctl(
        IOCTL_KERNELEYE_GET_VERSION,
        nullptr,
        0,
        &version,
        sizeof(version)
    );

    if (status == KERNELEYE_SUCCESS) {
        snprintf(g_DriverVersionString, sizeof(g_DriverVersionString), "%d.%d.%d",
            version.MajorVersion,
            version.MinorVersion,
            version.PatchVersion);
    } else {
        snprintf(g_DriverVersionString, sizeof(g_DriverVersionString), "Unknown");
    }

    return g_DriverVersionString;
}

//
// KernelEye_GetLastError
//
KERNELEYE_API const char* KernelEye_GetLastError(void)
{
    return g_State.lastError.c_str();
}

//
// KernelEye_IsDriverLoaded
//
KERNELEYE_API bool KernelEye_IsDriverLoaded(void)
{
    HANDLE handle = CreateFileW(
        DEVICE_SYMBOLIC_LINK,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (handle != INVALID_HANDLE_VALUE) {
        CloseHandle(handle);
        return true;
    }

    return false;
}

//
// KernelEye_SendHeartbeat
//
KERNELEYE_API KERNELEYE_STATUS KernelEye_SendHeartbeat(void)
{
    if (!g_State.initialized) {
        return KERNELEYE_ERROR_NOT_INITIALIZED;
    }

    return SendIoctl(IOCTL_KERNELEYE_HEARTBEAT, nullptr, 0, nullptr, 0);
}

//
// KernelEye_ReportEvent
//
KERNELEYE_API KERNELEYE_STATUS KernelEye_ReportEvent(
    const char* eventName,
    const char* eventData
)
{
    // TODO: Implement custom event reporting
    (void)eventName;
    (void)eventData;
    return KERNELEYE_SUCCESS;
}

//
// KernelEye_ValidateModule
//
KERNELEYE_API KERNELEYE_STATUS KernelEye_ValidateModule(
    const char* moduleName
)
{
    // TODO: Implement module validation
    (void)moduleName;
    return KERNELEYE_SUCCESS;
}

//
// Internal Functions
//

static DWORD WINAPI HeartbeatThreadProc(LPVOID param)
{
    (void)param;

    while (!g_State.stopHeartbeat) {
        if (g_State.initialized) {
            KERNELEYE_STATUS status = KernelEye_SendHeartbeat();
            
            if (g_State.heartbeatCallback) {
                g_State.heartbeatCallback(
                    status == KERNELEYE_SUCCESS,
                    g_State.heartbeatUserData
                );
            }
        }

        Sleep(g_State.config.HeartbeatIntervalMs);
    }

    return 0;
}

static KERNELEYE_STATUS ConnectToDriver()
{
    g_State.driverHandle = CreateFileW(
        DEVICE_SYMBOLIC_LINK,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (g_State.driverHandle == INVALID_HANDLE_VALUE) {
        return KERNELEYE_ERROR_CONNECTION_FAILED;
    }

    return KERNELEYE_SUCCESS;
}

static void DisconnectFromDriver()
{
    if (g_State.driverHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(g_State.driverHandle);
        g_State.driverHandle = INVALID_HANDLE_VALUE;
    }
}

static void SetLastError(const char* error)
{
    g_State.lastError = error;
}

static KERNELEYE_STATUS SendIoctl(
    ULONG ioctlCode,
    void* input,
    ULONG inputSize,
    void* output,
    ULONG outputSize
)
{
    if (g_State.driverHandle == INVALID_HANDLE_VALUE) {
        return KERNELEYE_ERROR_CONNECTION_FAILED;
    }

    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(
        g_State.driverHandle,
        ioctlCode,
        input,
        inputSize,
        output,
        outputSize,
        &bytesReturned,
        nullptr
    );

    if (!result) {
        DWORD error = GetLastError();
        char errorMsg[256];
        snprintf(errorMsg, sizeof(errorMsg), "IOCTL failed: 0x%08X, GetLastError: %lu", ioctlCode, error);
        SetLastError(errorMsg);
        return KERNELEYE_ERROR_UNKNOWN;
    }

    return KERNELEYE_SUCCESS;
}
