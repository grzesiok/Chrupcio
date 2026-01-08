#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include "logging/Logging.h"
#include <filesystem>
#include <chrono>

namespace Logging {

static std::atomic<bool> s_initialized{false};

void initLogging() {
    bool expected = false;
    if (!s_initialized.compare_exchange_strong(expected, true)) {
        // already initialized
        return;
    }

    try {
        std::filesystem::create_directories("D:\\Chrupcio\\logs");
        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>("D:\\Chrupcio\\logs\\chrupcio.log", 5 * 1024 * 1024, 3);
        spdlog::set_default_logger(std::make_shared<spdlog::logger>("app", spdlog::sinks_init_list({file_sink}))); 
        spdlog::set_level(spdlog::level::info);
        spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");
        spdlog::flush_every(std::chrono::seconds(1));
        spdlog::info("Logging initialized");
    } catch (const std::exception &e) {
        // If logging fails, mark as not initialized so future attempts can retry
        s_initialized.store(false);
    }
}

void shutdownLogging() {
    bool expected = true;
    if (!s_initialized.compare_exchange_strong(expected, false)) {
        // was not initialized
        return;
    }

    try {
        spdlog::info("Shutting down logging");
        spdlog::shutdown();
    } catch (...) {
        // ignore
    }
}

bool isInitialized() {
    return s_initialized.load();
}

void sinkLog(LogLevel level, const std::string& msg) {
    if (!isInitialized()) return;
    switch (level) {
    case LogLevel::Info:  spdlog::info("{}", msg); break;
    case LogLevel::Warn:  spdlog::warn("{}", msg); break;
    case LogLevel::Error: spdlog::error("{}", msg); break;
    case LogLevel::Debug: spdlog::debug("{}", msg); break;
    case LogLevel::Trace: spdlog::trace("{}", msg); break;
    }
}

} // namespace Logging
