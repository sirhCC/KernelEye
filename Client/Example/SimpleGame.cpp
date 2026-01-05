//
// Example: Simple Game Integration
// Shows how to integrate KernelEye into a game
//

#include "../include/KernelEyeClient.h"
#include <iostream>
#include <thread>
#include <chrono>

// Detection callback
void OnDetection(
    KERNELEYE_DETECTION_TYPE type,
    KERNELEYE_THREAT_LEVEL level,
    const char* description,
    void* userData)
{
    (void)userData;
    
    const char* typeStr = "Unknown";
    switch (type) {
        case KERNELEYE_DETECTION_MEMORY_TAMPERING: typeStr = "Memory Tampering"; break;
        case KERNELEYE_DETECTION_CODE_INJECTION: typeStr = "Code Injection"; break;
        case KERNELEYE_DETECTION_HOOK_DETECTED: typeStr = "Hook Detected"; break;
        case KERNELEYE_DETECTION_SUSPICIOUS_PROCESS: typeStr = "Suspicious Process"; break;
        case KERNELEYE_DETECTION_SUSPICIOUS_DRIVER: typeStr = "Suspicious Driver"; break;
        case KERNELEYE_DETECTION_DEBUGGER_DETECTED: typeStr = "Debugger"; break;
        case KERNELEYE_DETECTION_VIRTUALIZATION: typeStr = "VM Detected"; break;
        case KERNELEYE_DETECTION_BEHAVIORAL_ANOMALY: typeStr = "Behavioral Anomaly"; break;
    }
    
    const char* levelStr = "Unknown";
    switch (level) {
        case KERNELEYE_THREAT_NONE: levelStr = "None"; break;
        case KERNELEYE_THREAT_SUSPICIOUS: levelStr = "Suspicious"; break;
        case KERNELEYE_THREAT_MODERATE: levelStr = "Moderate"; break;
        case KERNELEYE_THREAT_HIGH: levelStr = "High"; break;
        case KERNELEYE_THREAT_CRITICAL: levelStr = "Critical"; break;
    }
    
    std::cout << "[ANTI-CHEAT] Detection: " << typeStr 
              << " | Level: " << levelStr 
              << " | " << description << std::endl;
    
    // In a real game, you would:
    // - Log the detection
    // - Report to server
    // - Take action (kick, ban, etc.)
    if (level >= KERNELEYE_THREAT_HIGH) {
        std::cout << "[GAME] CRITICAL THREAT DETECTED - Would disconnect player" << std::endl;
    }
}

// Heartbeat callback
void OnHeartbeat(bool connected, void* userData)
{
    (void)userData;
    
    if (!connected) {
        std::cout << "[ANTI-CHEAT] Warning: Lost connection to driver!" << std::endl;
    }
}

int main()
{
    std::cout << "=== KernelEye Anti-Cheat Example ===" << std::endl;
    std::cout << "Client Version: " << KernelEye_GetVersion() << std::endl;
    
    // Check if driver is loaded
    if (!KernelEye_IsDriverLoaded()) {
        std::cout << "ERROR: KernelEye driver is not loaded!" << std::endl;
        std::cout << "Please install and start the driver first." << std::endl;
        return 1;
    }
    
    std::cout << "Driver detected, initializing..." << std::endl;
    
    // Configure anti-cheat
    KERNELEYE_CONFIG config{};
    config.HeartbeatIntervalMs = 5000;
    config.ScanIntervalMs = 30000;
    config.EnableRealtimeScanning = true;
    config.EnableBehavioralAnalysis = false;
    config.EnableHardwareChecks = false;
    config.AutoProtectProcess = true;
    config.LogLevel = 3;
    
    // Initialize
    KERNELEYE_STATUS status = KernelEye_Initialize(&config);
    if (status != KERNELEYE_SUCCESS) {
        std::cout << "ERROR: Failed to initialize anti-cheat: " << status << std::endl;
        std::cout << "Last error: " << KernelEye_GetLastError() << std::endl;
        return 1;
    }
    
    std::cout << "Anti-cheat initialized successfully" << std::endl;
    std::cout << "Driver Version: " << KernelEye_GetDriverVersion() << std::endl;
    
    // Register callbacks
    KernelEye_SetDetectionCallback(OnDetection, nullptr);
    KernelEye_SetHeartbeatCallback(OnHeartbeat, nullptr);
    
    std::cout << "Callbacks registered" << std::endl;
    
    // Check if process is protected
    if (KernelEye_IsProtected()) {
        std::cout << "Process is protected" << std::endl;
    } else {
        std::cout << "Warning: Process protection failed!" << std::endl;
    }
    
    // Simulate game running
    std::cout << "\n=== Game Running ===" << std::endl;
    std::cout << "Press Ctrl+C to exit...\n" << std::endl;
    
    for (int i = 0; i < 60; i++) {  // Run for 60 seconds
        // Simulate game loop
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        // Perform periodic scan every 10 seconds
        if (i % 10 == 0) {
            std::cout << "[" << i << "s] Performing full scan..." << std::endl;
            
            status = KernelEye_ScanFull();
            if (status != KERNELEYE_SUCCESS) {
                std::cout << "Scan failed: " << status << std::endl;
            } else {
                // Get statistics
                KERNELEYE_STATS stats{};
                if (KernelEye_GetStatistics(&stats) == KERNELEYE_SUCCESS) {
                    std::cout << "Stats - Scans: " << stats.TotalScans 
                              << " | Detections: " << stats.TotalDetections 
                              << " | Uptime: " << stats.UptimeSeconds << "s" << std::endl;
                }
            }
        }
        
        // Simulate game events
        if (i == 15) {
            std::cout << "\n[GAME] Player joined match" << std::endl;
            KernelEye_ReportEvent("player_joined", "match_id=12345");
        }
        
        if (i == 45) {
            std::cout << "\n[GAME] Player finished match" << std::endl;
            KernelEye_ReportEvent("match_end", "score=9999");
        }
    }
    
    // Shutdown
    std::cout << "\n=== Shutting Down ===" << std::endl;
    KernelEye_Shutdown();
    std::cout << "Anti-cheat shutdown complete" << std::endl;
    
    return 0;
}
