#include "BinaryAnalyzer.hpp"
#include "CacheManager.hpp"
#include "Logger.hpp"
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

static void printUsage(std::ostream& output, const std::string& programName) {
    output << "Usage: " << programName << " <path_to_RobloxPlayerBeta.exe> [cache_file]" << std::endl;
    output << "  <path_to_RobloxPlayerBeta.exe>  Path to the Roblox executable to scan." << std::endl;
    output << "  [cache_file]                    Optional cache file path." << std::endl;
}

int main(int argc, char* argv[]) {
    const std::string programName = (argc > 0) ? argv[0] : "fastflag_scanner";
    if (argc < 2) {
        printUsage(std::cerr, programName);
        return 1;
    }

    const std::string firstArg = argv[1];
    if (firstArg == "-h" || firstArg == "--help") {
        printUsage(std::cout, programName);
        return 0;
    }

    const std::filesystem::path executablePath = argv[1];
    if (!std::filesystem::exists(executablePath)) {
        std::cerr << "Error: path not found: " << executablePath << std::endl;
        printUsage(std::cerr, programName);
        return 1;
    }

    const std::filesystem::path cachePath = (argc >= 3) ? argv[2] : std::filesystem::path("fastflag_cache.txt");

    setLogLevel(LogLevel::Debug);
    log(LogLevel::Info, "Starting scan", executablePath.string());
    log(LogLevel::Debug, "Cache file", cachePath.string());

    BinaryAnalyzer analyzer(executablePath);
    if (!analyzer.load()) {
        log(LogLevel::Error, "Failed to load binary", executablePath.string());
        return 1;
    }

    const auto prefixes = defaultPrefixes();
    log(LogLevel::Debug, "Using prefixes", "FFlag DFFlag SFFlag FInt DFInt FString FLog DFString");
    CacheManager cacheManager(cachePath);
    const std::string version = analyzer.versionString().empty() ? "unknown" : analyzer.versionString();

    RuntimeResolver runtimeResolver;
    const std::wstring processName = L"RobloxPlayerBeta.exe";
    log(LogLevel::Debug, "Attempting to attach to process", "RobloxPlayerBeta.exe");
    const bool attached = runtimeResolver.attachToProcess(processName);

    std::optional<ModuleInfo> moduleInfo;
    if (attached) {
        moduleInfo = runtimeResolver.findModule(processName);
        if (!moduleInfo) {
            log(LogLevel::Warning, "Attached but could not locate module", "RobloxPlayerBeta.exe");
        } else {
            log(LogLevel::Info, "Found module base", std::to_string(moduleInfo->base));
        }
    } else {
        log(LogLevel::Warning, "Could not attach to Roblox process");
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
        log(LogLevel::Info, "Found cache for version", cached->version);
        auto candidates = analyzer.buildRegistryCandidates(prefixes);
        auto it = std::find_if(candidates.begin(), candidates.end(), [&](const ScanCandidate& item) {
            return item.rva == cached->rva;
        });
        if (it != candidates.end()) {
            log(LogLevel::Info, "Verifying cached candidate");
            auto verified = validateCandidate(*it);
            if (verified) {
                selectedCandidate = verified;
            } else {
                log(LogLevel::Warning, "Cached candidate verification failed");
            }
        } else {
            log(LogLevel::Warning, "Cached candidate missing from current scan results");
        }
    }

    if (!selectedCandidate.has_value()) {
        log(LogLevel::Info, "Scanning binary for FastFlag registry candidates...");
        auto candidates = analyzer.buildRegistryCandidates(prefixes);
        log(LogLevel::Debug, "Candidate count", std::to_string(candidates.size()));
        for (auto& candidate : candidates) {
            auto verified = validateCandidate(candidate);
            log(LogLevel::Debug, "Candidate", std::to_string(candidate.rva), "confidence", std::to_string(candidate.confidence));
            if (verified) {
                selectedCandidate = verified;
                break;
            }
        }
    }

    if (!selectedCandidate.has_value()) {
        log(LogLevel::Error, "No FastFlag registry candidate could be verified.");
        return 2;
    }

    ResultDumper::dumpCandidate(*selectedCandidate, std::cout);

    CacheRecord record;
    record.version = version;
    record.rva = selectedCandidate->rva;
    record.strategy = selectedCandidate->strategy;
    record.confidence = selectedCandidate->confidence;
    if (!cacheManager.saveCache(record)) {
        log(LogLevel::Warning, "Failed to save cache", cachePath.string());
    } else {
        log(LogLevel::Info, "Cache saved for version", record.version);
    }

    return 0;
}
