pkg_search_module(pkg-openssl REQUIRED openssl)
message(STATUS "openssl include path: ${pkg-openssl_INCLUDE_DIRS}")
message(STATUS "openssl library path: ${pkg-openssl_STATIC_LDFLAGS}")

file( GLOB Elastos.ORG.Wallet.Lib.C-SOURCES "*.cpp" "*.c" "Transaction/*.cpp")
file( GLOB Elastos.ORG.Wallet.Lib.C-HEADERS "Elastos.Wallet.Utility.h" )

add_library(Elastos.ORG.Wallet.Lib.C)
target_sources(Elastos.ORG.Wallet.Lib.C PRIVATE
	${Elastos.ORG.Wallet.Lib.C-SOURCES}
	$<TARGET_OBJECTS:thirdparty>)
target_include_directories(Elastos.ORG.Wallet.Lib.C PRIVATE
	"${pkg-openssl_INCLUDE_DIRS}"
	"${CMAKE_CURRENT_SOURCE_DIR}/secp256k1"
	"${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/include")
target_link_libraries(Elastos.ORG.Wallet.Lib.C
	thirdparty
	${pkg-openssl_STATIC_LDFLAGS})
if("${CFG_TARGET_PLATFORM}" STREQUAL "Android")
	target_link_libraries(Elastos.ORG.Wallet.Lib.C log)
endif()

set_target_properties(Elastos.ORG.Wallet.Lib.C PROPERTIES PUBLIC_HEADER "${Elastos.ORG.Wallet.Lib.C-HEADERS}")
install(TARGETS Elastos.ORG.Wallet.Lib.C
		RUNTIME DESTINATION bin
		LIBRARY DESTINATION lib
		ARCHIVE DESTINATION lib
		PUBLIC_HEADER DESTINATION include/Elastos.ORG.Wallet.Lib.C)
