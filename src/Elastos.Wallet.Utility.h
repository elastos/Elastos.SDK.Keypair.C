
#ifndef __ELASTOS_WALLET_UTILITY_H__
#define __ELASTOS_WALLET_UTILITY_H__

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EXTERNAL_CHAIN     0
#define INTERNAL_CHAIN     1

#define COIN_TYPE_ELA      0

typedef struct
{
    uint32_t fingerPrint;
    uint8_t chainCode[32];
    uint8_t publicKey[33];
} MasterPublicKey;

char* getSinglePublicKey(const void* seed, int seedLen);

char* getSinglePrivateKey(const void* seed, int seedLen);

MasterPublicKey* getMasterPublicKey(const void* seed, int seedLen, int coinType);

char* getAddress(const char* publicKey);

char* generateMnemonic(const char* language, const char* words);

int getSeedFromMnemonic(void** seed, const char* mnemonic, const char* language, const char* words, const char* mnemonicPassword);

int sign(const char* privateKey, const void* data, int len, void** signedData);

bool verify(const char* publicKey, const void* data, int len, const void* signedData, int signedLen);

char* generateRawTransaction(const char* transaction);

char* generateSubPrivateKey(const void* seed, int seedLen, int coinType, int chain, int index);

char* generateSubPublicKey(const MasterPublicKey* masterPublicKey, int chain, int index);

void freeBuf(void* buf);

char* getPublicKeyFromPrivateKey(const char* privateKey);

bool isAddressValid(const char* address);

// Apis for DID
MasterPublicKey* getIdChainMasterPublicKey(const void* seed, int seedLen);

char* generateIdChainSubPrivateKey(const void* seed, int seedLen, int purpose, int index);

char* generateIdChainSubPublicKey(const MasterPublicKey* masterPublicKey, int purpose, int index);

char* getDid(const char* publicKey);

// Apis for multi sign
char* getMultiSignAddress(char** publicKeys, int length, int requiredSignCount);

char* multiSignTransaction(const char* privateKey, char** publicKeys, int length, int requiredSignCount, const char* transaction);

char* serializeMultiSignTransaction(const char* transaction);

#ifdef __cplusplus
}
#endif

#endif //__ELASTOS_WALLET_UTILITY_H__
