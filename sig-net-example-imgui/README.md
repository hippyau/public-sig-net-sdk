# sig-net-example-imgui

This is a standalone SDL2/OpenGL3/ImGui transmitter example for the Sig-Net SDK.

It is intentionally isolated from the repository root build. Configure it directly from this folder so the root `CMakeLists.txt` stays focused on the core library and self-test.

## What it does

- Fetches ImGui into the example build directory via CMake `FetchContent`
- Uses the SDL2/OpenGL3 ImGui backend pattern
- Recreates the original TID Level sender workflow in a cross-platform desktop app
- Supports K0 derivation, announce send, level send, keep-alive, dynamic RGB pattern, bad-frame injection, packet hex preview, and a rolling event log

## Build

```sh
cmake -S sig-net-example-imgui -B build/sig-net-example-imgui
cmake --build build/sig-net-example-imgui
```

## Run

```sh
./build/sig-net-example-imgui/sig-net-example-imgui
```

## Notes

- ImGui is fetched into the example build tree under `build/sig-net-example-imgui/_deps/`.
- SDL2 development files and OpenGL development files must already be installed on the host.
- The example compiles the parent Sig-Net sources directly, so changes to the SDK are immediately reflected here.
