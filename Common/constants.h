#pragma once

//
// KernelEye Anti-Cheat System - Common Constants
// Shared between kernel driver and user-mode components
//

// Device and symbolic link names
#define DEVICE_NAME             L"\\Device\\KernelEye"
#define SYMBOLIC_LINK_NAME      L"\\DosDevices\\KernelEye"
#define USER_DEVICE_NAME        L"\\\\.\\KernelEye"

// Version information
#define KERNELEYE_VERSION_MAJOR     1
#define KERNELEYE_VERSION_MINOR     0
#define KERNELEYE_VERSION_PATCH     0
#define KERNELEYE_VERSION_BUILD     1

// Pool tags (for memory allocation tracking)
#define KERNELEYE_POOL_TAG          'EleK'  // 'KelE' in reverse
#define SCAN_BUFFER_TAG             'nacS'
#define REPORT_BUFFER_TAG           'tpeR'

// Limits and sizes
#define MAX_PROCESS_NAME_LENGTH     260
#define MAX_MODULE_NAME_LENGTH      260
#define MAX_DRIVER_NAME_LENGTH      260
#define MAX_PATH_LENGTH             1024
#define MAX_SCAN_BUFFER_SIZE        (4 * 1024 * 1024)  // 4MB
#define MAX_REPORT_SIZE             (64 * 1024)         // 64KB

// Timing constants (in milliseconds)
#define HEARTBEAT_INTERVAL          5000    // 5 seconds
#define SCAN_INTERVAL_CRITICAL      100     // 100ms
#define SCAN_INTERVAL_STANDARD      1000    // 1 second
#define SCAN_INTERVAL_DEEP          30000   // 30 seconds

// Threat levels
#define THREAT_LEVEL_NONE           0
#define THREAT_LEVEL_SUSPICIOUS     1
#define THREAT_LEVEL_MEDIUM         2
#define THREAT_LEVEL_HIGH           3
#define THREAT_LEVEL_CRITICAL       4

// Scan flags
#define SCAN_FLAG_MEMORY            0x00000001
#define SCAN_FLAG_HOOKS             0x00000002
#define SCAN_FLAG_DRIVERS           0x00000004
#define SCAN_FLAG_PROCESSES         0x00000008
#define SCAN_FLAG_THREADS           0x00000010
#define SCAN_FLAG_CALLBACKS         0x00000020
#define SCAN_FLAG_HARDWARE          0x00000040
#define SCAN_FLAG_ALL               0xFFFFFFFF

// Protection flags
#define PROTECTION_FLAG_PROCESS     0x00000001
#define PROTECTION_FLAG_MEMORY      0x00000002
#define PROTECTION_FLAG_HANDLES     0x00000004
#define PROTECTION_FLAG_THREADS     0x00000008
#define PROTECTION_FLAG_ALL         0x0000000F

// Status codes (custom)
#define KERNELEYE_STATUS_SUCCESS                    0x00000000
#define KERNELEYE_STATUS_NOT_INITIALIZED            0xE0000001
#define KERNELEYE_STATUS_ALREADY_INITIALIZED        0xE0000002
#define KERNELEYE_STATUS_INVALID_PARAMETER          0xE0000003
#define KERNELEYE_STATUS_INSUFFICIENT_RESOURCES     0xE0000004
#define KERNELEYE_STATUS_ACCESS_DENIED              0xE0000005
#define KERNELEYE_STATUS_NOT_SUPPORTED              0xE0000006
#define KERNELEYE_STATUS_DETECTION_FOUND            0xE0000007
#define KERNELEYE_STATUS_TIMEOUT                    0xE0000008
#define KERNELEYE_STATUS_DRIVER_NOT_LOADED          0xE0000009
#define KERNELEYE_STATUS_COMMUNICATION_ERROR        0xE000000A

// Debug output levels
#define DEBUG_LEVEL_NONE            0
#define DEBUG_LEVEL_ERROR           1
#define DEBUG_LEVEL_WARNING         2
#define DEBUG_LEVEL_INFO            3
#define DEBUG_LEVEL_VERBOSE         4

#ifndef KERNELEYE_DEBUG_LEVEL
#ifdef _DEBUG
#define KERNELEYE_DEBUG_LEVEL       DEBUG_LEVEL_INFO
#else
#define KERNELEYE_DEBUG_LEVEL       DEBUG_LEVEL_ERROR
#endif
#endif
