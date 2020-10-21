
#ifndef __ELASTOS_FILECOIN_H__
#define __ELASTOS_FILECOIN_H__

#include <string>

namespace FileCoin {

int GetSeedFromMnemonic(void** seed, const char* mnemonic, const char* mnemonicPassword);
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

/**
 * \~English
 * Generate raw transaction data, sign transaction and serialize.
 *
 * @param
 *      privateKey    [in] the private key.
 *      transaction   [in] the transaction data in json string.
 *                  ex. {
 *                        "to": "t3xcnpgqifiwjivr65ylnxrvk3qjxb2hu5wz5b26z6kzr7z5shu4bicfwhv5vyoxyfiy6pjpj44cwndtmwe4ka",
 *                        "from": "t3s7px2ud2iajvsuxnynq4dvf4wbxrey4ipt3csk444irrgsorq5ctrknrtqml5kwewifbgqikecgdgnmbpq5a",
 *                        "value": "1",
 *                        "gasPremium": "1000000",
 *                        "gasFeeCap": "1000000",
 *                        "gasLimit": 80000000,
 *                        "method": 0,
 *                        "nonce": 0,
 *                        "params": ""
 *                      }
 * @return
 *      the raw transaction data if succeeded, or nullptr if failed.
 *      if you no longer use, call freeBuf to free memory.
 *      ex.{
 *           "Message": {
 *             "to": "t3xcnpgqifiwjivr65ylnxrvk3qjxb2hu5wz5b26z6kzr7z5shu4bicfwhv5vyoxyfiy6pjpj44cwndtmwe4ka",
 *             "from": "t3s7px2ud2iajvsuxnynq4dvf4wbxrey4ipt3csk444irrgsorq5ctrknrtqml5kwewifbgqikecgdgnmbpq5a",
 *             "value": "1",
 *             "gasPremium": "1000000",
 *             "gasFeeCap": "1000000",
 *             "gasLimit": 80000000,
 *             "method": 0,
 *             "nonce": 0,
 *             "params": ""
 *           },
 *	         "Signature": {
 *             "Type": 2,
 *             "Data": "tkDHJTSQed2Iwzl5k6UrvB3A/bSXUDywcsmPzHfCvy7cI7u5/yLl3IEyfE9FKP9tA9+B5v0mSalgFkd1iR7JTKmrus9XIIPreuJIBnmtvxA+KSBGrxrBEjAYGzeIMeo8"
 *	       }
}
 */
char* GenerateRawTransaction(const char* privateKey, const char* transaction);

} // namespace FileCoin

#endif //__ELASTOS_FILECOIN_H__
