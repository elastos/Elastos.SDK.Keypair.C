

set(SOURCES
    main.cpp
)

add_executable(TestUtility ${SOURCES})

target_link_libraries(TestUtility
    Elastos.Wallet.Utility
)
