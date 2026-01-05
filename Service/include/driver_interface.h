#pragma once

#include <windows.h>
#include <string>
#include <memory>
#include "../../../Common/constants.h"
#include "../../../Common/structures.h"
#include "../../../Common/protocol.h"

//
// KernelEye Service - Driver Interface
// Provides communication layer with kernel driver
//

class DriverInterface {
public:
    DriverInterface();
    ~DriverInterface();

    // Connection management
    bool Connect();
    void Disconnect();
    bool IsConnected() const { return m_hDevice != INVALID_HANDLE_VALUE; }

    // Driver operations
    bool GetVersion(KERNELEYE_VERSION& version);
    bool Initialize();
    bool Shutdown();
    bool GetStatistics(KERNELEYE_STATISTICS& stats);
    bool SendHeartbeat(UINT64 processId, UINT32 sequenceNumber);
    
    // Configuration
    bool SetConfig(const KERNELEYE_CONFIG& config);
    bool GetConfig(KERNELEYE_CONFIG& config);

    // Scanning operations
    bool ScanProcess(const KERNELEYE_SCAN_REQUEST& request, KERNELEYE_SCAN_RESULT& result);
    bool StartProtection(UINT64 processId, UINT32 flags);
    bool StopProtection(UINT64 processId);

    // Error information
    DWORD GetLastErrorCode() const { return m_lastError; }
    std::wstring GetLastErrorMessage() const;

private:
    // IOCTL helper
    bool SendIoctl(
        DWORD ioctlCode,
        LPVOID inputBuffer,
        DWORD inputSize,
        LPVOID outputBuffer,
        DWORD outputSize,
        LPDWORD bytesReturned
    );

    // Private members
    HANDLE m_hDevice;
    DWORD m_lastError;
    std::wstring m_devicePath;
};
