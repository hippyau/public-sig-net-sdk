cmake_minimum_required(VERSION 3.16)

if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
endif()

project(sig-net-example-imgui LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)

set(FETCHCONTENT_UPDATES_DISCONNECTED ON CACHE BOOL "" FORCE)

FetchContent_Declare(
    imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG v1.91.8
)

FetchContent_GetProperties(imgui)
if(NOT imgui_POPULATED)
    FetchContent_Populate(imgui)
endif()

find_package(OpenGL REQUIRED)

set(SIGNET_IMGUI_SDL2_TARGET "")
find_package(SDL2 QUIET CONFIG)
if(TARGET SDL2::SDL2)
    set(SIGNET_IMGUI_SDL2_TARGET SDL2::SDL2)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SDL2 REQUIRED IMPORTED_TARGET sdl2)
    set(SIGNET_IMGUI_SDL2_TARGET PkgConfig::SDL2)
endif()

add_library(sig-net-imgui-sdk STATIC
    ../sig-net-coap.cpp
    ../sig-net-crypto.cpp
    ../sig-net-security.cpp
    ../sig-net-send.cpp
    ../sig-net-tlv.cpp
    ../sig-net-parse.cpp
    ../sig-net-selftest.cpp
)
target_include_directories(sig-net-imgui-sdk PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)

# Crypto backend selection (mirrors the root CMakeLists.txt).
# The SDK sources are compiled directly here, so the matching compile
# definition must be set or the #elif defined(USE_OPENSSL/USE_MBEDTLS)
# branches in sig-net-crypto.cpp are skipped and the crypto functions
# become no-ops.
set(SIGNET_CRYPTO_BACKEND "AUTO" CACHE STRING "Crypto backend: AUTO, OPENSSL, MBEDTLS, WINCRYPT")
set_property(CACHE SIGNET_CRYPTO_BACKEND PROPERTY STRINGS AUTO OPENSSL MBEDTLS WINCRYPT)

if(SIGNET_CRYPTO_BACKEND STREQUAL "AUTO")
    if(WIN32)
        set(SIGNET_CRYPTO_BACKEND "WINCRYPT")
    else()
        set(SIGNET_CRYPTO_BACKEND "OPENSSL")
    endif()
endif()

message(STATUS "sig-net-imgui crypto backend: ${SIGNET_CRYPTO_BACKEND}")

if(SIGNET_CRYPTO_BACKEND STREQUAL "WINCRYPT")
    if(NOT WIN32)
        message(FATAL_ERROR "WINCRYPT backend is only available on Windows")
    endif()
    target_compile_definitions(sig-net-imgui-sdk PUBLIC USE_WINCRYPT)
    target_link_libraries(sig-net-imgui-sdk PUBLIC bcrypt ws2_32)
elseif(SIGNET_CRYPTO_BACKEND STREQUAL "OPENSSL")
    find_package(OpenSSL REQUIRED)
    target_compile_definitions(sig-net-imgui-sdk PUBLIC USE_OPENSSL)
    target_link_libraries(sig-net-imgui-sdk PUBLIC OpenSSL::SSL OpenSSL::Crypto)
elseif(SIGNET_CRYPTO_BACKEND STREQUAL "MBEDTLS")
    find_path(MBEDTLS_INCLUDE_DIR mbedtls/version.h)
    find_library(MBEDTLS_CRYPTO_LIBRARY mbedcrypto)
    if(NOT MBEDTLS_INCLUDE_DIR OR NOT MBEDTLS_CRYPTO_LIBRARY)
        message(FATAL_ERROR "Mbed TLS requested, but headers/library were not found")
    endif()
    target_compile_definitions(sig-net-imgui-sdk PUBLIC USE_MBEDTLS)
    target_include_directories(sig-net-imgui-sdk PUBLIC ${MBEDTLS_INCLUDE_DIR})
    target_link_libraries(sig-net-imgui-sdk PUBLIC ${MBEDTLS_CRYPTO_LIBRARY})
else()
    message(FATAL_ERROR "Unsupported SIGNET_CRYPTO_BACKEND='${SIGNET_CRYPTO_BACKEND}'")
endif()

add_library(imgui-sdl2-opengl3 STATIC
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_demo.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_sdl2.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp
)
target_include_directories(imgui-sdl2-opengl3 PUBLIC
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends
)
target_link_libraries(imgui-sdl2-opengl3 PUBLIC ${SIGNET_IMGUI_SDL2_TARGET} OpenGL::GL)

add_executable(sig-net-example-imgui
    main.cpp
    network.cpp
    app.cpp
    ui.cpp
)
target_compile_definitions(sig-net-example-imgui PRIVATE SDL_MAIN_HANDLED)
target_link_libraries(sig-net-example-imgui PRIVATE
    sig-net-imgui-sdk
    imgui-sdl2-opengl3
    ${SIGNET_IMGUI_SDL2_TARGET}
    OpenGL::GL
)
