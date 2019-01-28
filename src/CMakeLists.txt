pkg_search_module(pkg-openssl REQUIRED openssl)
message(STATUS "openssl include path: ${pkg-openssl_INCLUDE_DIRS}")
message(STATUS "openssl library path: ${pkg-openssl_STATIC_LDFLAGS}")

file( GLOB Elastos.SDK.Keypair.C-SOURCES "*.cpp" "*.c" "Transaction/*.cpp")
file( GLOB Elastos.SDK.Keypair.C-HEADERS "Elastos.Wallet.Utility.h" )

add_library(Elastos.SDK.Keypair.C)
target_sources(Elastos.SDK.Keypair.C PRIVATE
	${Elastos.SDK.Keypair.C-SOURCES})
target_sources(Elastos.SDK.Keypair.C PRIVATE
	$<TARGET_OBJECTS:thirdparty>)
target_include_directories(Elastos.SDK.Keypair.C PRIVATE
	"${pkg-openssl_INCLUDE_DIRS}"
	"${CMAKE_CURRENT_SOURCE_DIR}/secp256k1"
	"${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/include")
target_link_libraries(Elastos.SDK.Keypair.C PUBLIC
	${pkg-openssl_STATIC_LDFLAGS})
target_link_libraries(Elastos.SDK.Keypair.C PRIVATE
    thirdparty)
if("${CFG_TARGET_PLATFORM}" STREQUAL "Android")
	target_link_libraries(Elastos.SDK.Keypair.C log)
endif()

set_target_properties(Elastos.SDK.Keypair.C PROPERTIES PUBLIC_HEADER "${Elastos.SDK.Keypair.C-HEADERS}")
install(TARGETS Elastos.SDK.Keypair.C
		RUNTIME DESTINATION bin
		LIBRARY DESTINATION lib
		ARCHIVE DESTINATION lib
		PUBLIC_HEADER DESTINATION include/Elastos.SDK.Keypair.C)
