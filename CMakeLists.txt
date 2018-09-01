cmake_minimum_required(VERSION 3.5)
project(tinybtc)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic -O3 -march=native")

include_directories(src)
include_directories(deps/)
include_directories(deps/uv)
include_directories(deps/openssl)
file(GLOB SOURCES ${SOURCES} "src/*.c")
file(GLOB SOURCES ${SOURCES} "src/messages/*.c")
file(GLOB SOURCES ${SOURCES} "src/test/*.c")

add_executable(tinybtc ${SOURCES})
target_link_libraries(tinybtc ${CMAKE_CURRENT_SOURCE_DIR}/deps/uv/libuv_a.a)
target_link_libraries(tinybtc ${CMAKE_CURRENT_SOURCE_DIR}/deps/hiredis/libhiredis.a)
target_link_libraries(tinybtc ${CMAKE_CURRENT_SOURCE_DIR}/deps/openssl/libcrypto.a)

add_custom_command(
        TARGET tinybtc PRE_BUILD
        COMMAND mkdir -p
        ${CMAKE_CURRENT_BINARY_DIR}/fixtures/
)

add_custom_command(
        TARGET tinybtc PRE_BUILD
        COMMAND touch ${CMAKE_CURRENT_BINARY_DIR}/peers.dat
)

add_custom_command(
        TARGET tinybtc PRE_BUILD
        COMMAND cp -R
        ${CMAKE_CURRENT_SOURCE_DIR}/src/test/fixtures/*.dat
        ${CMAKE_CURRENT_BINARY_DIR}/fixtures/
)

add_custom_command(
        TARGET tinybtc PRE_BUILD
        COMMAND cp -R
        ${CMAKE_CURRENT_SOURCE_DIR}/src/genesis.dat
        ${CMAKE_CURRENT_BINARY_DIR}/
)
