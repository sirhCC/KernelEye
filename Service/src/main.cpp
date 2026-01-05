//
// KernelEye Service - Main Entry Point
//

#include "../include/driver_interface.h"
#include "../include/logger.h"
#include <windows.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <csignal>

// Global flag for graceful shutdown
volatile bool g_Running = true;

void SignalHandler(int signal)
{
    if (signal == SIGINT || signal == SIGTERM) {
        LOG_INFO("Shutdown signal received");
        g_Running = false;
    }
}

int main(int argc, char* argv[])
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    // Initialize logger
    Logger::Instance().Initialize(L"KernelEyeService.log", LogLevel::Info);
    
    LOG_INFO("KernelEye Service starting...");
    LOG_INFO("Version: %d.%d.%d.%d", 
        KERNELEYE_VERSION_MAJOR, 
        KERNELEYE_VERSION_MINOR, 
        KERNELEYE_VERSION_PATCH, 
        KERNELEYE_VERSION_BUILD);

    // Setup signal handlers
    signal(SIGINT, SignalHandler);
    signal(SIGTERM, SignalHandler);

    // Create driver interface
    DriverInterface driverInterface;

    // Connect to driver
    if (!driverInterface.Connect()) {
        LOG_ERROR("Failed to connect to driver. Make sure the driver is loaded.");
        LOG_ERROR("Error: %ls", driverInterface.GetLastErrorMessage().c_str());
        Logger::Instance().Shutdown();
        return 1;
    }

    // Get driver version
    KERNELEYE_VERSION driverVersion = {0};
    if (driverInterface.GetVersion(driverVersion)) {
        LOG_INFO("Connected to driver version: %u.%u.%u.%u",
            driverVersion.Major, driverVersion.Minor, 
            driverVersion.Patch, driverVersion.Build);
    }

    // Initialize driver
    if (!driverInterface.Initialize()) {
        LOG_ERROR("Failed to initialize driver");
        driverInterface.Disconnect();
        Logger::Instance().Shutdown();
        return 1;
    }

    // Main service loop
    UINT32 heartbeatCounter = 0;
    DWORD currentProcessId = GetCurrentProcessId();

    LOG_INFO("Service is running. Press Ctrl+C to stop.");

    while (g_Running) {
        // Send heartbeat
        if (!driverInterface.SendHeartbeat(currentProcessId, ++heartbeatCounter)) {
            LOG_WARNING("Failed to send heartbeat");
        }

        // Get statistics
        KERNELEYE_STATISTICS stats = {0};
        if (driverInterface.GetStatistics(stats)) {
            LOG_VERBOSE("Driver uptime: %llu seconds, Total scans: %llu, Detections: %llu",
                stats.UptimeSeconds, stats.TotalScans, stats.TotalDetections);
        }

        // TODO: Check for detections
        // TODO: Process scan requests
        // TODO: Handle configuration updates

        // Sleep for heartbeat interval
        std::this_thread::sleep_for(std::chrono::milliseconds(HEARTBEAT_INTERVAL));
    }

    // Cleanup
    LOG_INFO("Service shutting down...");

    if (!driverInterface.Shutdown()) {
        LOG_WARNING("Failed to shutdown driver gracefully");
    }

    driverInterface.Disconnect();
    Logger::Instance().Shutdown();

    return 0;
}
