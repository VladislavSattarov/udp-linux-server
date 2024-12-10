cmake_minimum_required(VERSION 3.10)
project(udp_server)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED True)


set(CMAKE_C_FLAGS_ASAN "-g -fsanitize=address,undefined -fno-sanitize-recover=all -O2"
    CACHE STRING "Compiler flags in asan build"
    FORCE)

message("ASAN build compiler flags: " ${CMAKE_C_FLAGS_ASAN})


find_package(CMocka REQUIRED)

add_subdirectory(src)
add_subdirectory(tests)
