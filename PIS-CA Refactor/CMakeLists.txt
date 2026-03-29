cmake_minimum_required(VERSION 3.14)
project(PIS_CA_Refactor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# OpenSSL
find_package(OpenSSL REQUIRED)

# NTL from vcpkg or manual path
if(DEFINED ENV{VCPKG_ROOT})
    set(NTL_INCLUDE_DIR "$ENV{VCPKG_ROOT}/packages/ntl_x64-windows/include" CACHE PATH "NTL include")
    set(NTL_LIBRARY "$ENV{VCPKG_ROOT}/packages/ntl_x64-windows/lib/ntl.lib" CACHE FILEPATH "NTL library")
else()
    set(NTL_INCLUDE_DIR "D:/NTL/WinNTL-11_5_1/include" CACHE PATH "NTL include")
    set(NTL_LIBRARY "D:/NTL/WinNTL-11_5_1/lib/ntl.lib" CACHE FILEPATH "NTL library")
endif()

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${NTL_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

# Source files
set(CORE_SOURCES
    core/params.hpp
    core/encryption.hpp
    core/encryption.cpp
)

set(COMMITMENT_SOURCES
    commitment/vector_commitment.hpp
    commitment/vector_commitment.cpp
)

# Main executable
add_executable(cs_tests 
    main.cpp
    ${CORE_SOURCES}
    ${COMMITMENT_SOURCES}
)

target_link_libraries(cs_tests
    OpenSSL::SSL
    OpenSSL::Crypto
    ${NTL_LIBRARY}
)

if(MSVC)
    target_compile_options(cs_tests PRIVATE /EHsc /W3 /MP)
endif()

# Enable testing
enable_testing()
add_test(NAME CS_Tests COMMAND cs_tests)
