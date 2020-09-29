
#ifndef __ELASTOS_FILECOIN_H__
#define __ELASTOS_FILECOIN_H__

#include <string>

namespace FileCoin {

char* GetSinglePrivateKey(const void* seed, int seedLen);
char* GetSinglePublicKey(const void* seed, int seedLen);
char* GetPublicKeyFromPrivateKey(const char* privateKey);
char* GetAddress(const char* publicKey);

int Sign(const char* privateKey,
         const void* data, int len,
         void** signedData);
bool Verify(const char* publicKey,
            const void* data, int len,
            const void* signedData, int signedLen);

char* GenerateRawTransaction(const char* privateKey, const char* transaction);

} // namespace FileCoin

#endif //__ELASTOS_FILECOIN_H__
