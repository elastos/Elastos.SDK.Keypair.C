
file( GLOB SOURCES "*.cpp")

add_executable(TestUtility ${SOURCES})

target_link_libraries(TestUtility
    Elastos.SDK.Keypair.C
)
