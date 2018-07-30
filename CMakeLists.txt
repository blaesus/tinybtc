cmake_minimum_required(VERSION 3.5)
project(diy-bitcoin)

set(CMAKE_C_STANDARD 11)

include_directories(src)
set(SOURCE_FILES src/main.c src/constants.h src/Block.h)
add_executable(diy-bitcoin ${SOURCE_FILES})
