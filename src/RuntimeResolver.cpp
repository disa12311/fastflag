#include "RuntimeResolver.hpp"

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#else
#include <unistd.h>
#endif

namespace fastflag {

RuntimeResolver::~RuntimeResolver() {
#ifdef _WIN32
    if (processHandle_) {
        CloseHandle(static_cast<HANDLE>(processHandle_));
    }
#endif
}

bool RuntimeResolver::attachToProcess(const std::wstring& processName) {
#ifdef _WIN32
    const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot, &entry)) {
        CloseHandle(snapshot);
        return false;
    }

    bool attached = false;
    do {
        if (processName == entry.szExeFile) {
            processHandle_ = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, entry.th32ProcessID);
            attached = processHandle_ != nullptr;
            break;
        }
    } while (Process32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    return attached;
#else
    (void)processName;
    return false;
#endif
}

std::optional<ModuleInfo> RuntimeResolver::findModule(const std::wstring& moduleName) const {
#ifdef _WIN32
    if (!processHandle_) {
        return std::nullopt;
    }

    const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(static_cast<HANDLE>(processHandle_)));
    if (snapshot == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }

    MODULEENTRY32W moduleEntry{};
    moduleEntry.dwSize = sizeof(moduleEntry);
    if (!Module32FirstW(snapshot, &moduleEntry)) {
        CloseHandle(snapshot);
        return std::nullopt;
    }

    std::optional<ModuleInfo> found;
    do {
        if (moduleName == moduleEntry.szModule || moduleName == moduleEntry.szExePath) {
            found = ModuleInfo{
                .base = reinterpret_cast<uint64_t>(moduleEntry.modBaseAddr),
                .size = static_cast<uint64_t>(moduleEntry.modBaseSize),
                .name = std::wstring(moduleEntry.szModule, moduleEntry.szModule + wcslen(moduleEntry.szModule)).empty() ? "" : std::string(),
            };
            break;
        }
    } while (Module32NextW(snapshot, &moduleEntry));

    CloseHandle(snapshot);
    return found;
#else
    (void)moduleName;
    return std::nullopt;
#endif
}

bool RuntimeResolver::readMemory(uint64_t address, void* buffer, size_t size) const {
#ifdef _WIN32
    if (!processHandle_ || !buffer || size == 0) {
        return false;
    }
    SIZE_T bytesRead = 0;
    return ReadProcessMemory(static_cast<HANDLE>(processHandle_), reinterpret_cast<LPCVOID>(address), buffer, size, &bytesRead) != 0 && bytesRead == size;
#else
    (void)address;
    (void)buffer;
    (void)size;
    return false;
#endif
}

uint64_t RuntimeResolver::resolveRuntimeAddress(uint64_t moduleBase, uint64_t rva) const {
    return moduleBase + rva;
}

} // namespace fastflag
