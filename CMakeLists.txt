cmake_minimum_required(VERSION 3.10)

project(sig-net-sdk
    VERSION 0.15
    LANGUAGES CXX
    DESCRIPTION "Sig-Net Protocol Framework SDK"
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# Core library sources (platform-independent + conditional crypto backend)
# ---------------------------------------------------------------------------
set(SIGNET_SOURCES
    sig-net-coap.cpp
    sig-net-crypto.cpp
    sig-net-security.cpp
    sig-net-send.cpp
    sig-net-tlv.cpp
    sig-net-parse.cpp
    sig-net-node-data.cpp
)

set(SIGNET_HEADERS
    sig-net-constants.hpp
    sig-net-types.hpp
    sig-net-coap.hpp
    sig-net-crypto.hpp
    sig-net-security.hpp
    sig-net-send.hpp
    sig-net-tlv.hpp
    sig-net-parse.hpp
    sig-net-node-data.hpp
    sig-net-node-profile.hpp
    sig-net-tid-strings.hpp
    sig-net-selftest.hpp
    sig-net.hpp
)

# ---------------------------------------------------------------------------
# Static library
# ---------------------------------------------------------------------------
add_library(sig-net STATIC ${SIGNET_SOURCES} ${SIGNET_HEADERS})
target_include_directories(sig-net PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# ---------------------------------------------------------------------------
# Platform-specific link dependencies
# ---------------------------------------------------------------------------
if(WIN32)
    target_link_libraries(sig-net PUBLIC bcrypt ws2_32)
else()
    find_package(OpenSSL REQUIRED)
    target_link_libraries(sig-net PUBLIC OpenSSL::SSL OpenSSL::Crypto)
endif()

# ---------------------------------------------------------------------------
# Self-test executable
# ---------------------------------------------------------------------------
add_executable(sig-net-selftest
    sig-net-self-test-cli/sig-net-selftest-main.cpp
    sig-net-selftest.cpp
    sig-net-selftest.hpp
)
target_link_libraries(sig-net-selftest PRIVATE sig-net)

# Run self-test as a CTest
enable_testing()
add_test(NAME selftest COMMAND sig-net-selftest)
