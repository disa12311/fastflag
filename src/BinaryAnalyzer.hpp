#pragma once

#include "Types.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace fastflag {

struct SectionInfo {
    std::string name;
    uint64_t virtualAddress = 0;
    uint64_t virtualSize = 0;
    uint64_t rawAddress = 0;
    uint64_t rawSize = 0;
};

class BinaryAnalyzer {
public:
    explicit BinaryAnalyzer(const std::filesystem::path& imagePath);

    bool load();
    std::string versionString() const;
    std::optional<uint64_t> rvaFromOffset(uint64_t fileOffset) const;
    std::optional<uint64_t> offsetFromRva(uint64_t rva) const;
    std::vector<uint64_t> findAsciiStringsWithPrefixes(const std::vector<std::string>& prefixes) const;
    std::vector<uint64_t> findCrossReferences(uint64_t targetRva) const;
    std::vector<ScanCandidate> buildRegistryCandidates(const std::vector<std::string>& prefixes) const;

    const std::vector<SectionInfo>& sections() const { return sections_; }
    const std::filesystem::path& imagePath() const { return imagePath_; }
    const std::vector<uint8_t>& imageData() const { return imageData_; }

private:
    bool parseHeaders();
    bool isValidRva(uint64_t rva) const;
    std::optional<SectionInfo> sectionForRva(uint64_t rva) const;
    std::optional<SectionInfo> sectionForOffset(uint64_t offset) const;
    std::string readAsciiString(uint64_t fileOffset) const;
    FastFlagType classifyFastFlagType(const std::string& name) const;
    std::vector<uint64_t> locateStringData(const std::vector<std::string>& prefixes) const;
    std::vector<uint64_t> scanForPointers(uint64_t value, size_t pointerSize) const;
    ScanCandidate scoreCandidateRegion(uint64_t regionRva, const std::vector<std::string>& prefixes) const;

    std::filesystem::path imagePath_;
    std::vector<uint8_t> imageData_;
    uint64_t optionalHeaderImageBase_ = 0;
    uint64_t pointerSize_ = 0;
    std::vector<SectionInfo> sections_;
    std::string versionString_;
};

} // namespace fastflag
