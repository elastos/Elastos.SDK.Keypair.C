cmake_minimum_required(VERSION 3.12)

include(config/cmake/CMakeLists.txt)

project(Elastos.SDK.Keypair.C)
add_subdirectory(thirdparty)
add_subdirectory(src)

if(DEFINED CFG_WITH_TEST)
	add_subdirectory(test)
endif()

configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/Elastos.SDK.Keypair.C.pc.in
	${CMAKE_CURRENT_BINARY_DIR}/Elastos.SDK.Keypair.C.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/Elastos.SDK.Keypair.C.pc DESTINATION lib/pkgconfig)
