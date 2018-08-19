cmake_minimum_required(VERSION 3.5)
project(diy-bitcoin)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic")

include_directories(src)
include_directories(deps/)
include_directories(deps/uv)
file(GLOB SOURCES ${SOURCES} "src/*.c")
file(GLOB SOURCES ${SOURCES} "src/messages/*.c")

file(GLOB SOURCES ${SOURCES} "src/test/*.c")

add_executable(diy-bitcoin
        ${SOURCES}
        deps/sha256/sha256.c
)
target_link_libraries(diy-bitcoin ${CMAKE_CURRENT_SOURCE_DIR}/deps/uv/libuv_a.a)
target_link_libraries(diy-bitcoin ${CMAKE_CURRENT_SOURCE_DIR}/deps/redis/libhiredis.a)

add_custom_command(
        TARGET diy-bitcoin PRE_BUILD
        COMMAND cp -R
        ${CMAKE_CURRENT_SOURCE_DIR}/src/test/fixtures/*.dat
        ${CMAKE_CURRENT_BINARY_DIR}/fixtures
)

add_custom_command(
        TARGET diy-bitcoin PRE_BUILD
        COMMAND cp -R
        ${CMAKE_CURRENT_SOURCE_DIR}/src/genesis.dat
        ${CMAKE_CURRENT_BINARY_DIR}/
)
