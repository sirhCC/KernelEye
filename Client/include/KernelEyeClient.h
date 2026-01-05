#pragma once

#ifdef KERNELEYE_CLIENT_EXPORTS
#define KERNELEYE_API __declspec(dllexport)
#else
#define KERNELEYE_API __declspec(dllimport)
#endif

#include <stdint.h>

//
// KernelEye Anti-Cheat Client Library
// Public API for game integration
//

#ifdef __cplusplus
extern "C" {
#endif

// Version information
#define KERNELEYE_CLIENT_VERSION_MAJOR 1
#define KERNELEYE_CLIENT_VERSION_MINOR 0
#define KERNELEYE_CLIENT_VERSION_PATCH 0

// Status codes
typedef enum _KERNELEYE_STATUS {
    KERNELEYE_SUCCESS = 0,
    KERNELEYE_ERROR_NOT_INITIALIZED = 1,
    KERNELEYE_ERROR_ALREADY_INITIALIZED = 2,
    KERNELEYE_ERROR_CONNECTION_FAILED = 3,
    KERNELEYE_ERROR_DRIVER_NOT_LOADED = 4,
    KERNELEYE_ERROR_INVALID_PARAMETER = 5,
    KERNELEYE_ERROR_INSUFFICIENT_RESOURCES = 6,
    KERNELEYE_ERROR_TIMEOUT = 7,
    KERNELEYE_ERROR_ACCESS_DENIED = 8,
    KERNELEYE_ERROR_DETECTION_TRIGGERED = 9,
    KERNELEYE_ERROR_UNKNOWN = 99
} KERNELEYE_STATUS;

// Threat levels
typedef enum _KERNELEYE_THREAT_LEVEL {
    KERNELEYE_THREAT_NONE = 0,
    KERNELEYE_THREAT_SUSPICIOUS = 1,
    KERNELEYE_THREAT_MODERATE = 2,
    KERNELEYE_THREAT_HIGH = 3,
    KERNELEYE_THREAT_CRITICAL = 4
} KERNELEYE_THREAT_LEVEL;

// Detection types
typedef enum _KERNELEYE_DETECTION_TYPE {
    KERNELEYE_DETECTION_MEMORY_TAMPERING = 1,
    KERNELEYE_DETECTION_CODE_INJECTION = 2,
    KERNELEYE_DETECTION_HOOK_DETECTED = 3,
    KERNELEYE_DETECTION_SUSPICIOUS_PROCESS = 4,
    KERNELEYE_DETECTION_SUSPICIOUS_DRIVER = 5,
    KERNELEYE_DETECTION_DEBUGGER_DETECTED = 6,
    KERNELEYE_DETECTION_VIRTUALIZATION = 7,
    KERNELEYE_DETECTION_BEHAVIORAL_ANOMALY = 8
} KERNELEYE_DETECTION_TYPE;

// Detection event callback
typedef void (*KERNELEYE_DETECTION_CALLBACK)(
    KERNELEYE_DETECTION_TYPE type,
    KERNELEYE_THREAT_LEVEL level,
    const char* description,
    void* userData
);

// Heartbeat callback
typedef void (*KERNELEYE_HEARTBEAT_CALLBACK)(
    bool connected,
    void* userData
);

// Configuration structure
typedef struct _KERNELEYE_CONFIG {
    uint32_t HeartbeatIntervalMs;       // Milliseconds between heartbeats
    uint32_t ScanIntervalMs;            // Milliseconds between scans
    bool EnableRealtimeScanning;        // Enable continuous scanning
    bool EnableBehavioralAnalysis;      // Enable behavioral detection
    bool EnableHardwareChecks;          // Enable hardware validation
    bool AutoProtectProcess;            // Automatically protect game process
    uint32_t LogLevel;                  // 0=None, 1=Error, 2=Warning, 3=Info, 4=Debug
} KERNELEYE_CONFIG;

// Statistics structure
typedef struct _KERNELEYE_STATS {
    uint64_t TotalScans;
    uint64_t TotalDetections;
    uint64_t MemoryScans;
    uint64_t HookScans;
    uint64_t ProcessEvents;
    uint64_t UptimeSeconds;
} KERNELEYE_STATS;

//
// Initialization and Shutdown
//

// Initialize the anti-cheat system
// Must be called before any other functions
KERNELEYE_API KERNELEYE_STATUS KernelEye_Initialize(
    const KERNELEYE_CONFIG* config
);

// Shutdown the anti-cheat system
// Cleans up all resources
KERNELEYE_API void KernelEye_Shutdown(void);

// Check if the system is initialized
KERNELEYE_API bool KernelEye_IsInitialized(void);

//
// Protection Control
//

// Start protecting the current process
KERNELEYE_API KERNELEYE_STATUS KernelEye_StartProtection(void);

// Stop protecting the current process
KERNELEYE_API KERNELEYE_STATUS KernelEye_StopProtection(void);

// Check if process is currently protected
KERNELEYE_API bool KernelEye_IsProtected(void);

//
// Scanning
//

// Request an immediate memory scan
KERNELEYE_API KERNELEYE_STATUS KernelEye_ScanMemory(void);

// Request an immediate hook scan
KERNELEYE_API KERNELEYE_STATUS KernelEye_ScanHooks(void);

// Request a full system scan
KERNELEYE_API KERNELEYE_STATUS KernelEye_ScanFull(void);

//
// Callbacks
//

// Register a callback for detection events
KERNELEYE_API KERNELEYE_STATUS KernelEye_SetDetectionCallback(
    KERNELEYE_DETECTION_CALLBACK callback,
    void* userData
);

// Register a callback for heartbeat events
KERNELEYE_API KERNELEYE_STATUS KernelEye_SetHeartbeatCallback(
    KERNELEYE_HEARTBEAT_CALLBACK callback,
    void* userData
);

//
// Configuration
//

// Get current configuration
KERNELEYE_API KERNELEYE_STATUS KernelEye_GetConfig(
    KERNELEYE_CONFIG* config
);

// Update configuration
KERNELEYE_API KERNELEYE_STATUS KernelEye_SetConfig(
    const KERNELEYE_CONFIG* config
);

//
// Statistics
//

// Get current statistics
KERNELEYE_API KERNELEYE_STATUS KernelEye_GetStatistics(
    KERNELEYE_STATS* stats
);

// Reset statistics
KERNELEYE_API KERNELEYE_STATUS KernelEye_ResetStatistics(void);

//
// Information
//

// Get client library version
KERNELEYE_API const char* KernelEye_GetVersion(void);

// Get driver version (if connected)
KERNELEYE_API const char* KernelEye_GetDriverVersion(void);

// Get last error message
KERNELEYE_API const char* KernelEye_GetLastError(void);

// Check if driver is loaded and accessible
KERNELEYE_API bool KernelEye_IsDriverLoaded(void);

//
// Advanced
//

// Manually send heartbeat to driver
KERNELEYE_API KERNELEYE_STATUS KernelEye_SendHeartbeat(void);

// Report custom event to anti-cheat
KERNELEYE_API KERNELEYE_STATUS KernelEye_ReportEvent(
    const char* eventName,
    const char* eventData
);

// Validate game module integrity
KERNELEYE_API KERNELEYE_STATUS KernelEye_ValidateModule(
    const char* moduleName
);

#ifdef __cplusplus
}
#endif
