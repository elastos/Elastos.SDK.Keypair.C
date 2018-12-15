cmake_minimum_required(VERSION 3.12)

include(config/cmake/CMakeLists.txt)

project(Elastos.ORG.Wallet.Lib.C)
add_subdirectory(thirdparty)
add_subdirectory(src)

if(DEFINED CFG_WITH_TEST)
	add_subdirectory(test)
endif()
