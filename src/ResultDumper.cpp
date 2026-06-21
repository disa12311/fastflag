#include "ResultDumper.hpp"

#include <iomanip>
#include <string_view>

namespace fastflag {

void ResultDumper::dumpCandidate(const ScanCandidate& candidate, std::ostream& output) {
    output << "Candidate RVA: 0x" << std::hex << candidate.rva << std::dec << "\n";
    output << "Strategy: " << candidate.strategy << "\n";
    output << "Confidence: " << candidate.confidence << "\n";
    output << "Entries: " << candidate.entries.size() << "\n\n";

    for (const auto& entry : candidate.entries) {
        output << "- Name: " << entry.name << "\n";
        output << "  Type: ";
        switch (entry.type) {
            case FastFlagType::FFlag: output << "FFlag"; break;
            case FastFlagType::DFFlag: output << "DFFlag"; break;
            case FastFlagType::SFFlag: output << "SFFlag"; break;
            case FastFlagType::FInt: output << "FInt"; break;
            case FastFlagType::DFInt: output << "DFInt"; break;
            case FastFlagType::FString: output << "FString"; break;
            case FastFlagType::FLog: output << "FLog"; break;
            case FastFlagType::DFString: output << "DFString"; break;
            default: output << "Unknown"; break;
        }
        output << "\n";
        output << "  Entry Address: 0x" << std::hex << entry.entryAddress << std::dec << "\n";
        output << "  Runtime Address: 0x" << std::hex << entry.runtimeAddress << std::dec << "\n";
        output << "  Value Address: 0x" << std::hex << entry.valueAddress << std::dec << "\n";
        output << "  RVA: 0x" << std::hex << entry.rva << std::dec << "\n";
        output << "  Verified: " << (entry.verified ? "yes" : "no") << "\n";
        output << "  Score: " << entry.score << "\n";
        if (!entry.verificationNotes.empty()) {
            output << "  Notes:\n";
            for (const auto& note : entry.verificationNotes) {
                output << "    - " << note << "\n";
            }
        }
        output << "\n";
    }
}

} // namespace fastflag
