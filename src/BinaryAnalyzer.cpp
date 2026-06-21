#include "BinaryAnalyzer.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <iterator>
#include <limits>

namespace fastflag {

namespace {
    constexpr uint32_t IMAGE_DOS_SIGNATURE = 0x5A4D; // MZ
    constexpr uint32_t IMAGE_NT_SIGNATURE = 0x00004550; // PE\0\0
    constexpr uint16_t IMAGE_FILE_MACHINE_AMD64 = 0x8664;
    constexpr uint16_t IMAGE_FILE_MACHINE_I386 = 0x014c;
    constexpr uint16_t IMAGE_DIRECTORY_ENTRY_IMPORT = 1;

    struct DosHeader {
        uint16_t e_magic;
        uint16_t e_cblp;
        uint16_t e_cp;
        uint16_t e_crlc;
        uint16_t e_cparhdr;
        uint16_t e_minalloc;
        uint16_t e_maxalloc;
        uint16_t e_ss;
        uint16_t e_sp;
        uint16_t e_csum;
        uint16_t e_ip;
        uint16_t e_cs;
        uint16_t e_lfarlc;
        uint16_t e_ovno;
        uint16_t e_res[4];
        uint16_t e_oemid;
        uint16_t e_oeminfo;
        uint16_t e_res2[10];
        uint32_t e_lfanew;
    };

    struct FileHeader {
        uint16_t Machine;
        uint16_t NumberOfSections;
        uint32_t TimeDateStamp;
        uint32_t PointerToSymbolTable;
        uint32_t NumberOfSymbols;
        uint16_t SizeOfOptionalHeader;
        uint16_t Characteristics;
    };

    struct OptionalHeader32 {
        uint16_t Magic;
        uint8_t MajorLinkerVersion;
        uint8_t MinorLinkerVersion;
        uint32_t SizeOfCode;
        uint32_t SizeOfInitializedData;
        uint32_t SizeOfUninitializedData;
        uint32_t AddressOfEntryPoint;
        uint32_t BaseOfCode;
        uint32_t BaseOfData;
        uint32_t ImageBase;
        uint32_t SectionAlignment;
        uint32_t FileAlignment;
        uint16_t MajorOperatingSystemVersion;
        uint16_t MinorOperatingSystemVersion;
        uint16_t MajorImageVersion;
        uint16_t MinorImageVersion;
        uint16_t MajorSubsystemVersion;
        uint16_t MinorSubsystemVersion;
        uint32_t Win32VersionValue;
        uint32_t SizeOfImage;
        uint32_t SizeOfHeaders;
        uint32_t CheckSum;
        uint16_t Subsystem;
        uint16_t DllCharacteristics;
        uint32_t SizeOfStackReserve;
        uint32_t SizeOfStackCommit;
        uint32_t SizeOfHeapReserve;
        uint32_t SizeOfHeapCommit;
        uint32_t LoaderFlags;
        uint32_t NumberOfRvaAndSizes;
    };

    struct OptionalHeader64 {
        uint16_t Magic;
        uint8_t MajorLinkerVersion;
        uint8_t MinorLinkerVersion;
        uint32_t SizeOfCode;
        uint32_t SizeOfInitializedData;
        uint32_t SizeOfUninitializedData;
        uint32_t AddressOfEntryPoint;
        uint32_t BaseOfCode;
        uint64_t ImageBase;
        uint32_t SectionAlignment;
        uint32_t FileAlignment;
        uint16_t MajorOperatingSystemVersion;
        uint16_t MinorOperatingSystemVersion;
        uint16_t MajorImageVersion;
        uint16_t MinorImageVersion;
        uint16_t MajorSubsystemVersion;
        uint16_t MinorSubsystemVersion;
        uint32_t Win32VersionValue;
        uint32_t SizeOfImage;
        uint32_t SizeOfHeaders;
        uint32_t CheckSum;
        uint16_t Subsystem;
        uint16_t DllCharacteristics;
        uint64_t SizeOfStackReserve;
        uint64_t SizeOfStackCommit;
        uint64_t SizeOfHeapReserve;
        uint64_t SizeOfHeapCommit;
        uint32_t LoaderFlags;
        uint32_t NumberOfRvaAndSizes;
    };

    struct SectionHeader {
        char Name[8];
        uint32_t VirtualSize;
        uint32_t VirtualAddress;
        uint32_t SizeOfRawData;
        uint32_t PointerToRawData;
        uint32_t PointerToRelocations;
        uint32_t PointerToLinenumbers;
        uint16_t NumberOfRelocations;
        uint16_t NumberOfLinenumbers;
        uint32_t Characteristics;
    };

    bool isPrintableAscii(uint8_t value) {
        return value >= 0x20 && value < 0x7F;
    }
}

BinaryAnalyzer::BinaryAnalyzer(const std::filesystem::path& imagePath)
    : imagePath_(imagePath) {}

bool BinaryAnalyzer::load() {
    std::ifstream file(imagePath_, std::ios::binary);
    if (!file) {
        return false;
    }

    imageData_ = std::vector<uint8_t>(std::istreambuf_iterator<char>(file), {});
    if (imageData_.size() < sizeof(DosHeader)) {
        return false;
    }

    return parseHeaders();
}

bool BinaryAnalyzer::parseHeaders() {
    const auto* dos = reinterpret_cast<const DosHeader*>(imageData_.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    if (dos->e_lfanew + sizeof(uint32_t) > imageData_.size()) {
        return false;
    }

    const uint32_t ntSignature = *reinterpret_cast<const uint32_t*>(imageData_.data() + dos->e_lfanew);
    if (ntSignature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    const auto* fileHeader = reinterpret_cast<const FileHeader*>(imageData_.data() + dos->e_lfanew + sizeof(uint32_t));
    const uint8_t* optionalHeaderData = imageData_.data() + dos->e_lfanew + sizeof(uint32_t) + sizeof(FileHeader);

    if (dos->e_lfanew + sizeof(uint32_t) + sizeof(FileHeader) + fileHeader->SizeOfOptionalHeader > imageData_.size()) {
        return false;
    }

    const uint16_t magic = *reinterpret_cast<const uint16_t*>(optionalHeaderData);
    if (magic == 0x10b) {
        const auto* optional = reinterpret_cast<const OptionalHeader32*>(optionalHeaderData);
        optionalHeaderImageBase_ = optional->ImageBase;
        pointerSize_ = 4;
    } else if (magic == 0x20b) {
        const auto* optional = reinterpret_cast<const OptionalHeader64*>(optionalHeaderData);
        optionalHeaderImageBase_ = optional->ImageBase;
        pointerSize_ = 8;
    } else {
        return false;
    }

    const uint8_t* sectionData = optionalHeaderData + fileHeader->SizeOfOptionalHeader;
    sections_.clear();
    for (uint16_t index = 0; index < fileHeader->NumberOfSections; ++index) {
        const auto* sectionHeader = reinterpret_cast<const SectionHeader*>(sectionData + index * sizeof(SectionHeader));
        SectionInfo section;
        section.name = std::string(sectionHeader->Name, sectionHeader->Name + 8);
        section.virtualAddress = sectionHeader->VirtualAddress;
        section.virtualSize = sectionHeader->VirtualSize;
        section.rawAddress = sectionHeader->PointerToRawData;
        section.rawSize = sectionHeader->SizeOfRawData;
        sections_.push_back(section);
    }

    const auto prefixes = std::vector<std::string>{"FFlag", "DFFlag", "SFFlag", "FInt", "DFInt", "FString", "FLog", "DFString"};
    auto strings = locateStringData(prefixes);
    for (uint64_t offset : strings) {
        std::string candidate = readAsciiString(offset);
        if (candidate.find("version") != std::string::npos || candidate.find("Roblox") != std::string::npos) {
            versionString_ = candidate;
            break;
        }
    }

    return true;
}

std::optional<uint64_t> BinaryAnalyzer::rvaFromOffset(uint64_t fileOffset) const {
    if (auto section = sectionForOffset(fileOffset)) {
        return section->virtualAddress + (fileOffset - section->rawAddress);
    }
    return std::nullopt;
}

std::optional<uint64_t> BinaryAnalyzer::offsetFromRva(uint64_t rva) const {
    if (auto section = sectionForRva(rva)) {
        return section->rawAddress + (rva - section->virtualAddress);
    }
    return std::nullopt;
}

bool BinaryAnalyzer::isValidRva(uint64_t rva) const {
    return sectionForRva(rva).has_value();
}

std::optional<SectionInfo> BinaryAnalyzer::sectionForRva(uint64_t rva) const {
    for (const auto& section : sections_) {
        if (rva >= section.virtualAddress && rva < section.virtualAddress + std::max<uint64_t>(1, section.virtualSize)) {
            return section;
        }
    }
    return std::nullopt;
}

std::optional<SectionInfo> BinaryAnalyzer::sectionForOffset(uint64_t offset) const {
    for (const auto& section : sections_) {
        if (offset >= section.rawAddress && offset < section.rawAddress + section.rawSize) {
            return section;
        }
    }
    return std::nullopt;
}

std::string BinaryAnalyzer::readAsciiString(uint64_t fileOffset) const {
    if (fileOffset >= imageData_.size()) {
        return {};
    }

    std::string result;
    for (uint64_t pos = fileOffset; pos < imageData_.size(); ++pos) {
        uint8_t ch = imageData_[pos];
        if (ch == 0) {
            break;
        }
        if (!isPrintableAscii(ch)) {
            break;
        }
        result.push_back(static_cast<char>(ch));
    }
    return result;
}

std::vector<uint64_t> BinaryAnalyzer::locateStringData(const std::vector<std::string>& prefixes) const {
    std::vector<uint64_t> results;
    for (const auto& section : sections_) {
        if (section.name != ".rdata" && section.name != ".data" && section.name != ".rodata") {
            continue;
        }
        const uint64_t endOffset = section.rawAddress + section.rawSize;
        uint64_t pos = section.rawAddress;
        while (pos + 8 < endOffset && pos + 1 < imageData_.size()) {
            if (!isPrintableAscii(imageData_[pos])) {
                ++pos;
                continue;
            }
            std::string str = readAsciiString(pos);
            if (str.size() < 5) {
                ++pos;
                continue;
            }
            for (const auto& prefix : prefixes) {
                if (str.rfind(prefix, 0) == 0) {
                    if (auto rva = rvaFromOffset(pos)) {
                        results.push_back(*rva);
                    }
                    break;
                }
            }
            pos += str.size() + 1;
        }
    }
    return results;
}

std::vector<uint64_t> BinaryAnalyzer::findAsciiStringsWithPrefixes(const std::vector<std::string>& prefixes) const {
    return locateStringData(prefixes);
}

std::vector<uint64_t> BinaryAnalyzer::scanForPointers(uint64_t value, size_t pointerSize) const {
    std::vector<uint64_t> results;
    const uint64_t maxOffset = imageData_.size();
    for (uint64_t pos = 0; pos + pointerSize <= maxOffset; ++pos) {
        uint64_t candidate = 0;
        for (size_t i = 0; i < pointerSize; ++i) {
            candidate |= static_cast<uint64_t>(imageData_[pos + i]) << (i * 8);
        }
        if (candidate == value) {
            if (auto rva = rvaFromOffset(pos)) {
                results.push_back(*rva);
            }
        }
    }
    return results;
}

std::vector<uint64_t> BinaryAnalyzer::findCrossReferences(uint64_t targetRva) const {
    std::vector<uint64_t> refs;
    const auto pointerBytes = pointerSize_;
    for (const auto& section : sections_) {
        if (section.name != ".text" && section.name != ".rdata" && section.name != ".data") {
            continue;
        }
        const uint64_t endOffset = section.rawAddress + section.rawSize;
        for (uint64_t pos = section.rawAddress; pos + pointerBytes <= endOffset; ++pos) {
            uint64_t candidate = 0;
            for (size_t i = 0; i < pointerBytes; ++i) {
                candidate |= static_cast<uint64_t>(imageData_[pos + i]) << (i * 8);
            }
            if (candidate == targetRva) {
                if (auto rva = rvaFromOffset(pos)) {
                    refs.push_back(*rva);
                }
            }
        }
    }
    std::sort(refs.begin(), refs.end());
    refs.erase(std::unique(refs.begin(), refs.end()), refs.end());
    return refs;
}

FastFlagType BinaryAnalyzer::classifyFastFlagType(const std::string& name) const {
    if (name.rfind("FFlag", 0) == 0) {
        return FastFlagType::FFlag;
    }
    if (name.rfind("DFFlag", 0) == 0) {
        return FastFlagType::DFFlag;
    }
    if (name.rfind("SFFlag", 0) == 0) {
        return FastFlagType::SFFlag;
    }
    if (name.rfind("FInt", 0) == 0) {
        return FastFlagType::FInt;
    }
    if (name.rfind("DFInt", 0) == 0) {
        return FastFlagType::DFInt;
    }
    if (name.rfind("FString", 0) == 0) {
        return FastFlagType::FString;
    }
    if (name.rfind("FLog", 0) == 0) {
        return FastFlagType::FLog;
    }
    if (name.rfind("DFString", 0) == 0) {
        return FastFlagType::DFString;
    }
    return FastFlagType::Unknown;
}

ScanCandidate BinaryAnalyzer::scoreCandidateRegion(uint64_t regionRva, const std::vector<std::string>& prefixes) const {
    ScanCandidate candidate;
    candidate.rva = regionRva;
    candidate.strategy = "structure_based";

    constexpr size_t maxEntries = 32;
    size_t goodCount = 0;
    size_t totalCount = 0;

    for (size_t entry = 0; entry < maxEntries; ++entry) {
        uint64_t entryRva = regionRva + entry * pointerSize_;
        if (!isValidRva(entryRva)) {
            break;
        }
        auto offset = offsetFromRva(entryRva);
        if (!offset) {
            break;
        }

        uint64_t referencedRva = 0;
        for (size_t i = 0; i < pointerSize_; ++i) {
            referencedRva |= static_cast<uint64_t>(imageData_[*offset + i]) << (i * 8);
        }
        if (!isValidRva(referencedRva)) {
            break;
        }

        auto nameOffset = offsetFromRva(referencedRva);
        if (!nameOffset) {
            break;
        }

        std::string name = readAsciiString(*nameOffset);
        if (name.empty()) {
            break;
        }

        auto type = classifyFastFlagType(name);
        if (type == FastFlagType::Unknown) {
            break;
        }

        FastFlagEntry entryData;
        entryData.name = std::move(name);
        entryData.type = type;
        entryData.entryAddress = optionalHeaderImageBase_ + entryRva;
        entryData.rva = entryRva;
        entryData.valueAddress = 0;
        entryData.runtimeAddress = 0;
        entryData.verified = false;
        entryData.score = 1.0f;
        candidate.entries.push_back(std::move(entryData));
        ++goodCount;
        ++totalCount;
    }

    if (totalCount > 0) {
        candidate.confidence = static_cast<float>(goodCount) / static_cast<float>(totalCount);
    }
    return candidate;
}

std::vector<ScanCandidate> BinaryAnalyzer::buildRegistryCandidates(const std::vector<std::string>& prefixes) const {
    std::vector<ScanCandidate> candidates;
    auto stringRvas = locateStringData(prefixes);
    std::vector<uint64_t> registrySources;

    for (uint64_t stringRva : stringRvas) {
        auto xrefs = findCrossReferences(stringRva);
        registrySources.insert(registrySources.end(), xrefs.begin(), xrefs.end());
    }
    std::sort(registrySources.begin(), registrySources.end());
    registrySources.erase(std::unique(registrySources.begin(), registrySources.end()), registrySources.end());

    for (uint64_t sourceRva : registrySources) {
        if (!isValidRva(sourceRva)) {
            continue;
        }
        auto candidate = scoreCandidateRegion(sourceRva, prefixes);
        if (!candidate.entries.empty()) {
            candidates.push_back(std::move(candidate));
        }
    }

    for (const auto& section : sections_) {
        if (section.name == ".rdata" || section.name == ".data" || section.name == ".rodata") {
            const auto start = section.virtualAddress;
            const auto end = section.virtualAddress + section.rawSize;
            const uint64_t step = pointerSize_;
            for (uint64_t rva = start; rva + step <= end; rva += step) {
                auto candidate = scoreCandidateRegion(rva, prefixes);
                if (candidate.confidence > 0.5f && candidate.entries.size() >= 4) {
                    candidates.push_back(std::move(candidate));
                }
            }
        }
    }

    std::sort(candidates.begin(), candidates.end(), [](const ScanCandidate& a, const ScanCandidate& b) {
        return a.confidence > b.confidence;
    });
    return candidates;
}

std::string BinaryAnalyzer::versionString() const {
    return versionString_;
}

} // namespace fastflag
