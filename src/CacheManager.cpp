#include "CacheManager.hpp"

#include <fstream>
#include <sstream>

namespace fastflag {

CacheManager::CacheManager(std::filesystem::path cachePath)
    : cachePath_(std::move(cachePath)) {}

std::optional<CacheRecord> CacheManager::loadCache(const std::string& version) const {
    if (!std::filesystem::exists(cachePath_)) {
        return std::nullopt;
    }
    std::ifstream input(cachePath_);
    if (!input) {
        return std::nullopt;
    }

    std::string line;
    while (std::getline(input, line)) {
        if (line.empty()) {
            continue;
        }
        std::istringstream stream(line);
        std::string versionKey;
        uint64_t rva;
        std::string strategy;
        float confidence;
        if (stream >> versionKey >> std::hex >> rva >> std::dec >> strategy >> confidence) {
            if (versionKey == version) {
                CacheRecord record;
                record.version = version;
                record.rva = rva;
                record.strategy = strategy;
                record.confidence = confidence;
                return record;
            }
        }
    }
    return std::nullopt;
}

bool CacheManager::saveCache(const CacheRecord& record) const {
    std::ostringstream outputBuffer;
    bool found = false;

    if (std::filesystem::exists(cachePath_)) {
        std::ifstream input(cachePath_);
        if (input) {
            std::string line;
            while (std::getline(input, line)) {
                if (line.empty()) {
                    continue;
                }
                std::istringstream stream(line);
                std::string versionKey;
                if (stream >> versionKey) {
                    if (versionKey == record.version) {
                        outputBuffer << record.version << " " << std::hex << record.rva << std::dec << " " << record.strategy << " " << record.confidence << "\n";
                        found = true;
                        continue;
                    }
                }
                outputBuffer << line << "\n";
            }
        }
    }

    if (!found) {
        outputBuffer << record.version << " " << std::hex << record.rva << std::dec << " " << record.strategy << " " << record.confidence << "\n";
    }

    std::ofstream output(cachePath_, std::ios::trunc);
    if (!output) {
        return false;
    }
    output << outputBuffer.str();
    return true;
}

} // namespace fastflag
