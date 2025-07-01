cmake_minimum_required(VERSION 3.20)
project(ChatProject)

set(CMAKE_CXX_STANDARD 20)

add_executable(server server_win.cpp)
target_link_libraries(server ws2_32)

set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++")
set(CMAKE_SHARED_LINKER_FLAGS "-static-libgcc -static-libstdc++")