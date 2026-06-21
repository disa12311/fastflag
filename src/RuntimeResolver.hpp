#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace fastflag {

struct ModuleInfo {
    uint64_t base = 0;
    uint64_t size = 0;
    std::string name;
};

class RuntimeResolver {
public:
    RuntimeResolver() = default;
    ~RuntimeResolver();

    bool attachToProcess(const std::wstring& processName);
    std::optional<ModuleInfo> findModule(const std::wstring& moduleName) const;
    bool readMemory(uint64_t address, void* buffer, size_t size) const;
    uint64_t resolveRuntimeAddress(uint64_t moduleBase, uint64_t rva) const;

private:
#ifdef _WIN32
    void* processHandle_ = nullptr;
#endif
};

} // namespace fastflag
