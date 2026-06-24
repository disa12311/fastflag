#include "Logger.hpp"

#include <iostream>

namespace fastflag {

static LogLevel globalLogLevel = LogLevel::Info;

void setLogLevel(LogLevel level) {
    globalLogLevel = level;
}

LogLevel logLevel() noexcept {
    return globalLogLevel;
}

void log(LogLevel level, std::string_view message) {
    if (level < globalLogLevel) {
        return;
    }

    switch (level) {
        case LogLevel::Debug:
            std::cerr << "[DEBUG] ";
            break;
        case LogLevel::Info:
            std::cerr << "[INFO] ";
            break;
        case LogLevel::Warning:
            std::cerr << "[WARN] ";
            break;
        case LogLevel::Error:
            std::cerr << "[ERROR] ";
            break;
    }
    std::cerr << message << std::endl;
}

} // namespace fastflag
