cmake_minimum_required(VERSION 3.5)
project(diy-bitcoin)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic")

include_directories(src)
include_directories(deps/)
file(GLOB SOURCES "src/*.c")

add_executable(diy-bitcoin
        ${SOURCES}
        deps/sha256/sha256.c
)
target_link_libraries(diy-bitcoin ${CMAKE_CURRENT_SOURCE_DIR}/deps/uv/libuv_a.a)
