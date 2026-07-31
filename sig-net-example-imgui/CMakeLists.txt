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

if(WIN32)
    target_link_libraries(sig-net-imgui-sdk PUBLIC bcrypt ws2_32)
else()
    find_package(OpenSSL REQUIRED)
    target_link_libraries(sig-net-imgui-sdk PUBLIC OpenSSL::SSL OpenSSL::Crypto)
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
)
target_compile_definitions(sig-net-example-imgui PRIVATE SDL_MAIN_HANDLED)
target_link_libraries(sig-net-example-imgui PRIVATE
    sig-net-imgui-sdk
    imgui-sdl2-opengl3
    ${SIGNET_IMGUI_SDL2_TARGET}
    OpenGL::GL
)
