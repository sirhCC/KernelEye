//
// KernelEye Memory Scanner Test Utility
// Tests the memory scanning functionality of the driver
//

#include <windows.h>
#include <iostream>
#include <iomanip>
#include "../../../Common/constants.h"
#include "../../../Common/structures.h"
#include "../../../Common/protocol.h"

void PrintHeader()
{
    std::cout << "========================================\n";
    std::cout << "  KernelEye Memory Scanner Test Tool\n";
    std::cout << "  Version 1.0.0.1\n";
    std::cout << "========================================\n\n";
}

bool TestDriverConnection(HANDLE hDevice)
{
    std::cout << "[TEST] Testing driver connection...\n";

    KERNELEYE_VERSION version = {0};
    DWORD bytesReturned = 0;

    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_KERNELEYE_GET_VERSION,
        NULL, 0,
        &version, sizeof(KERNELEYE_VERSION),
        &bytesReturned,
        NULL
    );

    if (!result) {
        std::cerr << "[FAIL] Failed to get version: " << GetLastError() << "\n";
        return false;
    }

    std::cout << "[PASS] Driver version: " << version.Major << "." 
              << version.Minor << "." << version.Patch << "." 
              << version.Build << "\n\n";
    return true;
}

bool TestDriverInitialization(HANDLE hDevice)
{
    std::cout << "[TEST] Initializing driver...\n";

    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_KERNELEYE_INITIALIZE,
        NULL, 0,
        NULL, 0,
        &bytesReturned,
        NULL
    );

    if (!result) {
        std::cerr << "[FAIL] Failed to initialize driver: " << GetLastError() << "\n";
        return false;
    }

    std::cout << "[PASS] Driver initialized successfully\n\n";
    return true;
}

bool TestMemoryScan(HANDLE hDevice, DWORD processId)
{
    std::cout << "[TEST] Scanning memory for PID " << processId << "...\n";

    KERNELEYE_SCAN_REQUEST request = {0};
    request.ProcessId = processId;
    request.ScanFlags = SCAN_FLAG_MEMORY;
    request.Timeout = 30000; // 30 seconds
    request.Context = 0x12345678;

    KERNELEYE_SCAN_RESULT result = {0};
    DWORD bytesReturned = 0;

    BOOL success = DeviceIoControl(
        hDevice,
        IOCTL_KERNELEYE_CHECK_MEMORY,
        &request, sizeof(KERNELEYE_SCAN_REQUEST),
        &result, sizeof(KERNELEYE_SCAN_RESULT),
        &bytesReturned,
        NULL
    );

    if (!success) {
        std::cerr << "[FAIL] Memory scan failed: " << GetLastError() << "\n";
        return false;
    }

    std::cout << "[PASS] Memory scan completed\n";
    std::cout << "  Context: 0x" << std::hex << result.Context << std::dec << "\n";
    std::cout << "  Status: 0x" << std::hex << result.Status << std::dec << "\n";
    std::cout << "  Total Checks: " << result.TotalChecks << "\n";
    std::cout << "  Detections: " << result.DetectionCount << "\n";
    std::cout << "  Duration: " << result.ScanDuration << " ms\n";

    if (result.DetectionCount > 0) {
        std::cout << "\n[WARN] Found " << result.DetectionCount 
                  << " suspicious memory regions!\n";
    } else {
        std::cout << "\n[INFO] No suspicious memory regions found.\n";
    }

    std::cout << "\n";
    return true;
}

bool TestStatistics(HANDLE hDevice)
{
    std::cout << "[TEST] Getting driver statistics...\n";

    KERNELEYE_STATISTICS stats = {0};
    DWORD bytesReturned = 0;

    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_KERNELEYE_GET_STATISTICS,
        NULL, 0,
        &stats, sizeof(KERNELEYE_STATISTICS),
        &bytesReturned,
        NULL
    );

    if (!result) {
        std::cerr << "[FAIL] Failed to get statistics: " << GetLastError() << "\n";
        return false;
    }

    std::cout << "[PASS] Statistics retrieved\n";
    std::cout << "  Total Scans: " << stats.TotalScans << "\n";
    std::cout << "  Total Detections: " << stats.TotalDetections << "\n";
    std::cout << "  Protected Processes: " << stats.TotalProcessesProtected << "\n";
    std::cout << "  Uptime: " << stats.UptimeSeconds << " seconds\n";
    std::cout << "  Memory Usage: " << stats.MemoryUsage << " bytes\n";
    std::cout << "  CPU Usage: " << stats.CpuUsagePercent << "%\n\n";

    return true;
}

void RunAllTests(HANDLE hDevice)
{
    int passed = 0;
    int failed = 0;

    // Test 1: Connection
    if (TestDriverConnection(hDevice)) passed++; else failed++;

    // Test 2: Initialization
    if (TestDriverInitialization(hDevice)) passed++; else failed++;

    // Test 3: Scan current process
    if (TestMemoryScan(hDevice, GetCurrentProcessId())) passed++; else failed++;

    // Test 4: Scan explorer.exe (typically PID ~800-2000)
    DWORD explorerPid = 0;
    HWND hwnd = FindWindowW(L"Shell_TrayWnd", NULL);
    if (hwnd) {
        GetWindowThreadProcessId(hwnd, &explorerPid);
        if (explorerPid > 0) {
            std::cout << "[INFO] Testing scan on explorer.exe (PID " << explorerPid << ")\n";
            if (TestMemoryScan(hDevice, explorerPid)) passed++; else failed++;
        }
    }

    // Test 5: Statistics
    if (TestStatistics(hDevice)) passed++; else failed++;

    // Summary
    std::cout << "========================================\n";
    std::cout << "  Test Results\n";
    std::cout << "========================================\n";
    std::cout << "  Passed: " << passed << "\n";
    std::cout << "  Failed: " << failed << "\n";
    std::cout << "  Total:  " << (passed + failed) << "\n";
    std::cout << "========================================\n";
}

int main(int argc, char* argv[])
{
    PrintHeader();

    // Open driver device
    std::cout << "Opening driver device: " << USER_DEVICE_NAME << "\n";
    HANDLE hDevice = CreateFileW(
        USER_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "\n[ERROR] Failed to open driver device!\n";
        std::cerr << "Error code: " << GetLastError() << "\n";
        std::cerr << "\nPossible causes:\n";
        std::cerr << "  1. Driver not loaded (run: sc start KernelEye)\n";
        std::cerr << "  2. Not running as Administrator\n";
        std::cerr << "  3. Test signing not enabled (run: bcdedit /set testsigning on)\n\n";
        return 1;
    }

    std::cout << "[SUCCESS] Driver device opened successfully\n\n";

    // Run tests based on command line arguments
    if (argc > 1) {
        // Specific test
        DWORD pid = atoi(argv[1]);
        if (pid > 0) {
            std::cout << "Testing memory scan on PID " << pid << "\n\n";
            TestDriverConnection(hDevice);
            TestDriverInitialization(hDevice);
            TestMemoryScan(hDevice, pid);
        } else {
            std::cout << "Invalid PID: " << argv[1] << "\n";
        }
    } else {
        // Run all tests
        RunAllTests(hDevice);
    }

    // Cleanup
    CloseHandle(hDevice);

    std::cout << "\nPress Enter to exit...";
    std::cin.get();

    return 0;
}
