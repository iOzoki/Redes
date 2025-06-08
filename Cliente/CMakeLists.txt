cmake_minimum_required(VERSION 3.20)
project(Cliente)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(Cliente
        client_win.cpp
        imgui.cpp
        imgui_draw.cpp
        imgui_tables.cpp
        imgui_widgets.cpp
        imgui_impl_win32.cpp
        imgui_impl_dx11.cpp
        imgui_demo.cpp
)

target_link_libraries(Cliente
        PRIVATE
        ws2_32
        d3d11
        d3dcompiler
        gdi32
        dwmapi
)

set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++")
set(CMAKE_SHARED_LINKER_FLAGS "-static-libgcc -static-libstdc++")
