#pragma once

#include <atomic>
#include <string>
#include <fmt/core.h>

namespace Logging {

// Initialize logging (idempotent). Safe to call multiple times.
void initLogging();

// Shutdown logging and flush outputs. Safe to call multiple times.
void shutdownLogging();

// Returns whether logging has been initialized.
bool isInitialized();

enum class LogLevel { Info, Warn, Error, Debug, Trace };

// Internal sink used by the templates to avoid including spdlog headers
// in this header. Implemented in Logging.cpp.
void sinkLog(LogLevel level, const std::string& msg);

// Lightweight logging helpers that format via fmt and forward to spdlog
// when initialized, otherwise they print to stdout/stderr for diagnostics.
template<typename... Args>
inline void info(const char* format, Args&&... args) {
    std::string msg = fmt::format(fmt::runtime(format), std::forward<Args>(args)...);
    if (isInitialized()) { sinkLog(LogLevel::Info, msg); } else { fmt::print("[info] {}\n", msg); }
}

template<typename... Args>
inline void warn(const char* format, Args&&... args) {
    std::string msg = fmt::format(fmt::runtime(format), std::forward<Args>(args)...);
    if (isInitialized()) { sinkLog(LogLevel::Warn, msg); } else { fmt::print("[warn] {}\n", msg); }
}

template<typename... Args>
inline void error(const char* format, Args&&... args) {
    std::string msg = fmt::format(fmt::runtime(format), std::forward<Args>(args)...);
    if (isInitialized()) { sinkLog(LogLevel::Error, msg); } else { fmt::print("[error] {}\n", msg); }
}

template<typename... Args>
inline void debug(const char* format, Args&&... args) {
    std::string msg = fmt::format(fmt::runtime(format), std::forward<Args>(args)...);
    if (isInitialized()) { sinkLog(LogLevel::Debug, msg); } else { fmt::print("[debug] {}\n", msg); }
}

template<typename... Args>
inline void trace(const char* format, Args&&... args) {
    std::string msg = fmt::format(fmt::runtime(format), std::forward<Args>(args)...);
    if (isInitialized()) { sinkLog(LogLevel::Trace, msg); } else { fmt::print("[trace] {}\n", msg); }
}

} // namespace Logging
