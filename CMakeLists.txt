cmake_minimum_required(VERSION 3.0)


set(TARGET_DIR $ENV{TARGET_PLATFORM}-$ENV{TARGET_ABI})

link_directories(${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/openssl/libs/${TARGET_DIR})

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD_REQUIRED ON)

#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIRECTORY}/build/${TARGET_DIR})
#set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIRECTORY}/build/${TARGET_DIR})

if("$ENV{TARGET_PLATFORM}" STREQUAL "android")

    set(CMAKE_SYSTEM_NAME Android)
    set(CMAKE_ANDROID_NDK $ENV{ANDROID_NDK})
    set(CMAKE_ANDROID_NDK_TOOLCHAIN_VERSION clang)
    set(CMAKE_ANDROID_STL_TYPE c++_static)

    string(APPEND CMAKE_C_FLAGS " -fPIE -fPIC")
    string(APPEND CMAKE_LINK_FLAGS " -pie")

    #choose Android version. This is not the version of Cmake.
    set(CMAKE_SYSTEM_VERSION 21)

    #choose Android ABI. Mine is armeabi-v7a
    message($ENV{TARGET_ABI})
    set(CMAKE_ANDROID_ARCH_ABI $ENV{TARGET_ABI})

endif("$ENV{TARGET_PLATFORM}" STREQUAL "android")

project(utility)

set(CMAKE_VERBOSE_MAKEFILE OFF)

string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,--no-undefined")

include_directories(
  thirdparty
  thirdparty/openssl
  ${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory(src)


if("$ENV{TARGET_PLATFORM}" STREQUAL "linux")
    add_subdirectory(test)
endif("$ENV{TARGET_PLATFORM}" STREQUAL "linux")

