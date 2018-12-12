if ("${ANDROID_NDK_HOME}" STREQUAL "")
	message(FATAL_ERROR "Fatal: ANDROID_NDK_HOME is not valid.")
endif()

set(CMAKE_CROSSCOMPILING TRUE)
set(CMAKE_SYSTEM_NAME Android)

#choose Android version. This is not the version of Cmake.
if("${CFG_TARGET_ABI}" STREQUAL "armeabi-v7a")
	set(CMAKE_SYSTEM_VERSION 19)
elseif("${CFG_TARGET_ABI}" STREQUAL "arme64-v8a")
	set(CMAKE_SYSTEM_VERSION 21)
else()
	set(CMAKE_SYSTEM_VERSION 21)
endif()

set(CMAKE_ANDROID_NDK "${ANDROID_NDK_HOME}")
set(CMAKE_ANDROID_NDK_TOOLCHAIN_VERSION clang)
set(CMAKE_ANDROID_ARCH_ABI ${CFG_TARGET_ABI})
set(CMAKE_ANDROID_STL_TYPE c++_static)

#list(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,--no-undefined")

