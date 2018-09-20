

set(SOURCES
    BTCKey.cpp
    BRInt.c
    BRKey.c
    BRCrypto.c
    BRAddress.c
    BRBase58.c
    BRBech32.c
    BRBIP39Mnemonic.c
    Mnemonic.cpp
    WalletTool.cpp
    Utils.cpp
    BTCBase58.cpp
    AES_256_CCM.cpp
    Base64.cpp
    ElaController.cpp
    ByteStream.cpp
    Transaction/Attribute.cpp
    Transaction/Program.cpp
    Transaction/Transaction.cpp
    Transaction/TxOutput.cpp
    Transaction/UTXOInput.cpp
    Elastos.Wallet.Utility.cpp
)

add_library(Elastos.Wallet.Utility SHARED ${SOURCES})

if("$ENV{TARGET_PLATFORM}" STREQUAL "android")
    target_link_libraries(Elastos.Wallet.Utility
        ssl
        crypto
    )
elseif("$ENV{TARGET_PLATFORM}" STREQUAL "linux")
    target_link_libraries(Elastos.Wallet.Utility
        ssl
        crypto
        pthread
    )
endif()
