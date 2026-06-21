cmake_minimum_required(VERSION 3.20)
project(FastFlagScanner VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(fastflag_scanner
    src/main.cpp
    src/BinaryAnalyzer.cpp
    src/MemoryVerifier.cpp
    src/CacheManager.cpp
    src/RuntimeResolver.cpp
    src/ResultDumper.cpp
)

target_include_directories(fastflag_scanner PRIVATE src)

if(MSVC)
    target_compile_options(fastflag_scanner PRIVATE /W4 /permissive-)
else()
    target_compile_options(fastflag_scanner PRIVATE -Wall -Wextra -Wpedantic)
endif()
