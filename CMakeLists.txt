cmake_minimum_required(VERSION 3.0)

link_directories(/home/zuo/work/Elastos.ORG.Wallet.Utility/thirdparty/openssl/libs/linux-x86_64)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD_REQUIRED ON)

string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,--no-undefined")

include_directories(thirdparty)
include_directories(thirdparty/openssl)

add_subdirectory(src)

add_subdirectory(test)

add_custom_command(
    COMMENT "Copy headers and libraries..."
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/linux-x86_64/Elastos.Wallet.Utility.h
           ${CMAKE_CURRENT_BINARY_DIR}/linux-x86_64/libElastos.Wallet.Utility.so
           ${CMAKE_CURRENT_BINARY_DIR}/linux-x86_64/TestUtility
           ${CMAKE_CURRENT_BINARY_DIR}/linux-x86_64/libcrypto.so.1.1
           ${CMAKE_CURRENT_BINARY_DIR}/linux-x86_64/libssl.so.1.1
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/linux-x86_64
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/src/Elastos.Wallet.Utility.h ${CMAKE_CURRENT_BINARY_DIR}/linux-x86_64
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/src/libElastos.Wallet.Utility.so ${CMAKE_CURRENT_BINARY_DIR}/linux-x86_64
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/test/TestUtility ${CMAKE_CURRENT_BINARY_DIR}/linux-x86_64
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/openssl/libs/linux-x86_64/libcrypto.so.1.1 ${CMAKE_CURRENT_BINARY_DIR}/linux-x86_64
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/openssl/libs/linux-x86_64/libssl.so.1.1 ${CMAKE_CURRENT_BINARY_DIR}/linux-x86_64
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/src/Data/BIP39WordsMulti.tar.gz ${CMAKE_CURRENT_BINARY_DIR}/linux-x86_64
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/Elastos.Wallet.Utility.h
            ${CMAKE_CURRENT_BINARY_DIR}/src/libElastos.Wallet.Utility.so
            ${CMAKE_CURRENT_BINARY_DIR}/test/TestUtility
            ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/openssl/libs/linux-x86_64/libcrypto.so.1.1
            ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/openssl/libs/linux-x86_64/libssl.so.1.1
)

add_custom_target(build_utility ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/linux-x86_64/Elastos.Wallet.Utility.h)
