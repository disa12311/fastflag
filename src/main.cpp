#include "BinaryAnalyzer.hpp"
#include "CacheManager.hpp"
#include "MemoryVerifier.hpp"
#include "ResultDumper.hpp"
#include "RuntimeResolver.hpp"
#include "Types.hpp"

#include <algorithm>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

using namespace fastflag;

static std::vector<std::string> defaultPrefixes() {
    return {"FFlag", "DFFlag", "SFFlag", "FInt", "DFInt", "FString", "FLog", "DFString"};
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: fastflag_scanner <path_to_RobloxPlayerBeta.exe> [cache_file]" << std::endl;
        return 1;
    }

    const std::filesystem::path executablePath = argv[1];
    const std::filesystem::path cachePath = (argc >= 3) ? argv[2] : std::filesystem::path("fastflag_cache.txt");

    BinaryAnalyzer analyzer(executablePath);
    if (!analyzer.load()) {
        std::cerr << "Failed to load binary: " << executablePath << std::endl;
        return 1;
    }

    const auto prefixes = defaultPrefixes();
    CacheManager cacheManager(cachePath);
    const std::string version = analyzer.versionString().empty() ? "unknown" : analyzer.versionString();

    RuntimeResolver runtimeResolver;
    const std::wstring processName = L"RobloxPlayerBeta.exe";
    const bool attached = runtimeResolver.attachToProcess(processName);

    std::optional<ModuleInfo> moduleInfo;
    if (attached) {
        moduleInfo = runtimeResolver.findModule(processName);
        if (!moduleInfo) {
            std::cerr << "Warning: attached to process but could not locate module " << std::string(processName.begin(), processName.end()) << std::endl;
        }
    }

    std::optional<CacheRecord> cached = cacheManager.loadCache(version);
    std::optional<ScanCandidate> selectedCandidate;

    const auto validateCandidate = [&](ScanCandidate candidate) -> std::optional<ScanCandidate> {
        if (moduleInfo) {
            const auto moduleBase = moduleInfo->base;
            for (auto& entry : candidate.entries) {
                entry.runtimeAddress = runtimeResolver.resolveRuntimeAddress(moduleBase, entry.rva);
                entry.entryAddress = entry.runtimeAddress;
            }
            MemoryVerifier verifier(moduleInfo->base, moduleInfo->size);
            auto result = verifier.verifyCandidate(candidate);
            if (result.valid) {
                for (auto& entry : candidate.entries) {
                    entry.verified = true;
                    entry.verificationNotes.push_back("verified via runtime bounds check");
                }
                return candidate;
            }
            return std::nullopt;
        }
        for (auto& entry : candidate.entries) {
            entry.verified = true;
            entry.verificationNotes.push_back("static verification only");
        }
        return candidate;
    };

    if (cached.has_value()) {
        std::cout << "Found cache for version: " << cached->version << "\n";
        auto candidates = analyzer.buildRegistryCandidates(prefixes);
        auto it = std::find_if(candidates.begin(), candidates.end(), [&](const ScanCandidate& item) {
            return item.rva == cached->rva;
        });
        if (it != candidates.end()) {
            std::cout << "Verifying cached candidate...\n";
            auto verified = validateCandidate(*it);
            if (verified) {
                selectedCandidate = verified;
            }
        }
    }

    if (!selectedCandidate.has_value()) {
        std::cout << "Scanning binary for FastFlag registry candidates...\n";
        auto candidates = analyzer.buildRegistryCandidates(prefixes);
        for (auto& candidate : candidates) {
            auto verified = validateCandidate(candidate);
            if (verified) {
                selectedCandidate = verified;
                break;
            }
        }
    }

    if (!selectedCandidate.has_value()) {
        std::cerr << "No FastFlag registry candidate could be verified." << std::endl;
        return 2;
    }

    ResultDumper::dumpCandidate(*selectedCandidate, std::cout);

    CacheRecord record;
    record.version = version;
    record.rva = selectedCandidate->rva;
    record.strategy = selectedCandidate->strategy;
    record.confidence = selectedCandidate->confidence;
    if (!cacheManager.saveCache(record)) {
        std::cerr << "Warning: failed to save cache" << std::endl;
    }

    return 0;
}
