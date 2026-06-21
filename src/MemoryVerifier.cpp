#include "MemoryVerifier.hpp"

#include <algorithm>

namespace fastflag {

MemoryVerifier::MemoryVerifier(uint64_t moduleBase, uint64_t moduleSize)
    : moduleBase_(moduleBase), moduleSize_(moduleSize) {
    prefixes_ = {"FFlag", "DFFlag", "SFFlag", "FInt", "DFInt", "FString", "FLog", "DFString"};
}

bool MemoryVerifier::isWithinModule(uint64_t address) const {
    return address >= moduleBase_ && address < moduleBase_ + moduleSize_;
}

bool MemoryVerifier::isAddressReadable(uint64_t address, size_t size) const {
    return address + size <= moduleBase_ + moduleSize_ && address >= moduleBase_;
}

float MemoryVerifier::scoreName(const std::string& name) const {
    for (const auto& prefix : prefixes_) {
        if (name.rfind(prefix, 0) == 0) {
            return 1.0f;
        }
    }
    return 0.0f;
}

MemoryVerifier::VerificationResult MemoryVerifier::verifyCandidate(const ScanCandidate& candidate) const {
    VerificationResult result;
    if (!isWithinModule(candidate.rva + moduleBase_)) {
        result.notes.push_back("candidate region outside module bounds");
        return result;
    }

    size_t total = candidate.entries.size();
    if (total == 0) {
        result.notes.push_back("no entries to verify");
        return result;
    }

    size_t validEntries = 0;
    for (const auto& entry : candidate.entries) {
        if (!isWithinModule(entry.entryAddress)) {
            result.notes.push_back("entry address outside module bounds: " + entry.name);
            continue;
        }
        if (entry.score < 0.8f) {
            result.notes.push_back("low scoring entry: " + entry.name);
            continue;
        }
        validEntries += 1;
    }

    result.confidence = static_cast<float>(validEntries) / static_cast<float>(total);
    result.valid = result.confidence >= 0.75f;
    if (result.valid) {
        result.notes.push_back("candidate verified with confidence " + std::to_string(result.confidence));
    } else {
        result.notes.push_back("candidate failed verification " + std::to_string(result.confidence));
    }
    return result;
}

} // namespace fastflag
