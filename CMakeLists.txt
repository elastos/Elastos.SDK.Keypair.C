cmake_minimum_required(VERSION 3.0)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD_REQUIRED ON)

link_directories(thirdparty/openssl/libs/linux-x86_64)
include_directories(thirdparty)
include_directories(thirdparty/openssl)

add_subdirectory(src)
