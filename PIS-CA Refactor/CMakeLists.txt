cmake_minimum_required(VERSION 3.14)
project(PIS_CA_Refactor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(OpenSSL REQUIRED)

# NTL library (manual specification required)
# Adjust these paths according to your NTL installation
if(NOT DEFINED NTL_INCLUDE_DIR)
    set(NTL_INCLUDE_DIR "/usr/local/include" CACHE PATH "NTL include directory")
endif()

if(NOT DEFINED NTL_LIBRARY)
    set(NTL_LIBRARY "/usr/local/lib/libntl.so" CACHE FILEPATH "NTL library")
endif()

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
    ${NTL_INCLUDE_DIR}
)

# Source files
set(CS_SOURCES
    src/cs_encryption.cpp
    src/cs_commitment.cpp
    src/cs_context.cpp
    src/cs_utils.cpp
)

# Create static library
add_library(cs_crypto STATIC ${CS_SOURCES})

target_link_libraries(cs_crypto
    ${OPENSSL_LIBRARIES}
    ${NTL_LIBRARY}
    gmp  # NTL dependency
)

# Test executable
add_executable(test_cs_system tests/test_cs_system.cpp)
target_link_libraries(test_cs_system cs_crypto)

# Example executable
add_executable(simple_example examples/simple_example.cpp)
target_link_libraries(simple_example cs_crypto)

# Enable testing
enable_testing()
add_test(NAME CS_System_Test COMMAND test_cs_system)

# Installation
install(TARGETS cs_crypto
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(DIRECTORY include/
    DESTINATION include
    FILES_MATCHING PATTERN "*.hpp"
)
