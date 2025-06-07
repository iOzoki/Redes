cmake_minimum_required(VERSION 3.31)
project(Cliente)

set(CMAKE_CXX_STANDARD 20)

add_executable(Cliente client_win.cpp
        cmake-build-debug/ChatCliente.h)

target_link_libraries(Cliente ws2_32)

set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++")
set(CMAKE_SHARED_LINKER_FLAGS "-static-libgcc -static-libstdc++")