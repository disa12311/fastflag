#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace fastflag {

enum class FastFlagType {
    Unknown,
    FFlag,
    DFFlag,
    SFFlag,
    FInt,
    DFInt,
    FString,
    FLog,
    DFString,
};

struct FastFlagEntry {
    std::string name;
    FastFlagType type = FastFlagType::Unknown;
    uint64_t entryAddress = 0;
    uint64_t valueAddress = 0;
    uint64_t runtimeAddress = 0;
    uint64_t rva = 0;
    bool verified = false;
    float score = 0.0f;
    std::vector<std::string> verificationNotes;
};

struct ScanCandidate {
    uint64_t rva = 0;
    std::string strategy;
    float confidence = 0.0f;
    std::vector<FastFlagEntry> entries;
};

struct CacheRecord {
    std::string version;
    uint64_t rva = 0;
    std::string strategy;
    float confidence = 0.0f;
};

} // namespace fastflag
