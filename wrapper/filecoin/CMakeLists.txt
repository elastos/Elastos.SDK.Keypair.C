file( GLOB filecoin-SOURCES "*.cpp" "*.c")
file( GLOB filecoin-HEADERS "*.hpp" )

if(${CMAKE_VERSION} VERSION_LESS "3.12")
    add_library(filecoin STATIC ${filecoin-SOURCES})
else()
    add_library(filecoin OBJECT ${filecoin-SOURCES})
endif()
target_include_directories(filecoin PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${PROJECT_SOURCE_DIR}/src"
    "${CMAKE_INSTALL_PREFIX}/include")

target_link_libraries(filecoin PUBLIC
    "filecoin_signer_ffi"
)

if("${CFG_TARGET_PLATFORM}" STREQUAL "iOS")
target_link_libraries(filecoin PUBLIC
    "objc"
    "-framework Security"
    )
endif()

target_link_libraries(filecoin PRIVATE
	thirdparty)


set(CMAKE_INCLUDE_CURRENT_DIR TRUE)

set_target_properties(filecoin PROPERTIES PUBLIC_HEADER "${filecoin-HEADERS}")
install(TARGETS filecoin
		PUBLIC_HEADER DESTINATION include/Elastos.SDK.Keypair.C)
