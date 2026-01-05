//
// KernelEye Service - Logger Implementation
//

#include "../include/logger.h"
#include <cstdio>
#include <cstdarg>
#include <ctime>
#include <chrono>
#include <sstream>
#include <iomanip>

Logger& Logger::Instance()
{
    static Logger instance;
    return instance;
}

void Logger::Initialize(const std::wstring& logPath, LogLevel level)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_initialized) {
        Shutdown();
    }

    m_logPath = logPath;
    m_level = level;

    m_logFile.open(logPath, std::ios::out | std::ios::app);
    if (!m_logFile.is_open()) {
        wprintf(L"[Logger] Failed to open log file: %s\n", logPath.c_str());
        return;
    }

    m_initialized = true;

    Info("=== KernelEye Service Started ===");
}

void Logger::Shutdown()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_initialized) {
        Info("=== KernelEye Service Stopped ===");
        m_logFile.close();
        m_initialized = false;
    }
}

void Logger::Error(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    Log(LogLevel::Error, format, args);
    va_end(args);
}

void Logger::Warning(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    Log(LogLevel::Warning, format, args);
    va_end(args);
}

void Logger::Info(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    Log(LogLevel::Info, format, args);
    va_end(args);
}

void Logger::Verbose(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    Log(LogLevel::Verbose, format, args);
    va_end(args);
}

void Logger::Log(LogLevel level, const char* format, va_list args)
{
    if (level > m_level) {
        return;
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    // Get current time
    auto now = std::chrono::system_clock::now();
    auto nowTime = std::chrono::system_clock::to_time_t(now);
    auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    struct tm timeinfo;
    localtime_s(&timeinfo, &nowTime);

    // Format timestamp
    char timestamp[64];
    sprintf_s(timestamp, sizeof(timestamp), "%04d-%02d-%02d %02d:%02d:%02d.%03lld",
        timeinfo.tm_year + 1900,
        timeinfo.tm_mon + 1,
        timeinfo.tm_mday,
        timeinfo.tm_hour,
        timeinfo.tm_min,
        timeinfo.tm_sec,
        nowMs.count());

    // Format message
    char message[4096];
    vsnprintf_s(message, sizeof(message), _TRUNCATE, format, args);

    // Build log entry
    char logEntry[4096];
    sprintf_s(logEntry, sizeof(logEntry), "[%s] [%s] %s\n",
        timestamp,
        GetLevelString(level),
        message);

    // Output to console
    printf("%s", logEntry);

    // Output to file
    if (m_initialized && m_logFile.is_open()) {
        m_logFile << logEntry;
        m_logFile.flush();
    }
}

const char* Logger::GetLevelString(LogLevel level)
{
    switch (level) {
        case LogLevel::Error:   return "ERROR";
        case LogLevel::Warning: return "WARN ";
        case LogLevel::Info:    return "INFO ";
        case LogLevel::Verbose: return "VERB ";
        default:                return "UNKN ";
    }
}
