#pragma once

#include <string_view>

namespace fastflag {

enum class LogLevel {
    Debug = 0,
    Info,
    Warning,
    Error,
};

void setLogLevel(LogLevel level);
LogLevel logLevel() noexcept;
void log(LogLevel level, std::string_view message);

template <typename... Args>
void log(LogLevel level, std::string_view format, Args&&... args) {
    if (level < logLevel()) {
        return;
    }

    std::string message;
    message.reserve(256);
    ((message.append(args), message.push_back(' ')), ...);
    log(level, message);
}

} // namespace fastflag
