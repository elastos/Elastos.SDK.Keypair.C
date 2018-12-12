include(bigint.cmake)

file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/null.cpp" "")
add_library(thirdparty OBJECT "${CMAKE_CURRENT_BINARY_DIR}/null.cpp")
target_include_directories(thirdparty PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_include_directories(thirdparty PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/nlohmann")
target_include_directories(thirdparty PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/bigint-2010.04.30")
target_link_libraries(thirdparty bigint)
