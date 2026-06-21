#pragma once

#include "Types.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace fastflag {

class MemoryVerifier {
public:
    struct VerificationResult {
        bool valid = false;
        float confidence = 0.0f;
        std::vector<std::string> notes;
    };

    explicit MemoryVerifier(uint64_t moduleBase, uint64_t moduleSize);

    VerificationResult verifyCandidate(const ScanCandidate& candidate) const;
    bool isAddressReadable(uint64_t address, size_t size) const;

private:
    bool isWithinModule(uint64_t address) const;
    float scoreName(const std::string& name) const;
    std::vector<std::string> prefixes_;
    uint64_t moduleBase_ = 0;
    uint64_t moduleSize_ = 0;
};

} // namespace fastflag
