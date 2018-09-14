
#ifndef __ELASTOS_WALLET_UTILITY_H__
#define __ELASTOS_WALLET_UTILITY_H__

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

char* generatePrivateKey();

char* getPublicKey(const char* privateKey);

char* getAddress(const char* publicKey);

char* generateMnemonic(const char* language, const char* path);

char* getPrivateKey(const char* mmemonic, const char* language, const char* path);

int sign(const char* privateKey, const void* data, int len, void** signedData);

bool verify(const char* publicKey, const void* data, int len, const void* signedData, int signedLen);

char* generateRawTransaction(const char* transaction);


#ifdef __cplusplus
}
#endif

#endif //__ELASTOS_WALLET_UTILITY_H__
