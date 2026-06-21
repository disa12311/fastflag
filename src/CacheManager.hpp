#pragma once

#include "Types.hpp"

#include <filesystem>
#include <optional>
#include <string>

namespace fastflag {

class CacheManager {
public:
    explicit CacheManager(std::filesystem::path cachePath);

    std::optional<CacheRecord> loadCache(const std::string& version) const;
    bool saveCache(const CacheRecord& record) const;

private:
    std::filesystem::path cachePath_;
};

} // namespace fastflag
