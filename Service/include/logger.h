#pragma once

#include <string>
#include <fstream>
#include <mutex>
#include <windows.h>

//
// KernelEye Service - Logger
// Simple logging system for user-mode service
//

enum class LogLevel {
    None = 0,
    Error = 1,
    Warning = 2,
    Info = 3,
    Verbose = 4
};

class Logger {
public:
    static Logger& Instance();

    void Initialize(const std::wstring& logPath, LogLevel level = LogLevel::Info);
    void Shutdown();

    void Error(const char* format, ...);
    void Warning(const char* format, ...);
    void Info(const char* format, ...);
    void Verbose(const char* format, ...);

    void SetLevel(LogLevel level) { m_level = level; }
    LogLevel GetLevel() const { return m_level; }

private:
    Logger() : m_level(LogLevel::Info), m_initialized(false) {}
    ~Logger() { Shutdown(); }

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    void Log(LogLevel level, const char* format, va_list args);
    const char* GetLevelString(LogLevel level);

    std::wstring m_logPath;
    std::ofstream m_logFile;
    LogLevel m_level;
    bool m_initialized;
    std::mutex m_mutex;
};

// Convenience macros
#define LOG_ERROR(...)   Logger::Instance().Error(__VA_ARGS__)
#define LOG_WARNING(...) Logger::Instance().Warning(__VA_ARGS__)
#define LOG_INFO(...)    Logger::Instance().Info(__VA_ARGS__)
#define LOG_VERBOSE(...) Logger::Instance().Verbose(__VA_ARGS__)
