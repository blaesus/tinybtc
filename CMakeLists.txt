cmake_minimum_required(VERSION 3.5)
project(tinybtc)

set(CMAKE_C_STANDARD 11)

list(APPEND cflags -Wall -Wextra)
list(APPEND cflags -O3 -march=native)
list(APPEND cflags -Wno-unused-function) # A lot of unused functions in test

add_subdirectory(deps/libuv)
add_subdirectory(deps/leveldb)
include_directories(src)
include_directories(deps/)
include_directories(deps/libuv/include)
include_directories(deps/leveldb/include)
include_directories(deps/openssl)
file(GLOB SOURCES ${SOURCES} "src/*.c")
file(GLOB SOURCES ${SOURCES} "src/messages/*.c")
file(GLOB SOURCES ${SOURCES} "src/test/*.c")

add_executable(tinybtc ${SOURCES})
target_compile_options(tinybtc PRIVATE ${cflags})
target_link_libraries(tinybtc uv)
target_link_libraries(tinybtc leveldb)
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
