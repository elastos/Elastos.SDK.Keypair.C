
#ifndef __ELASTOS_WALLET_UTILITY_H__
#define __ELASTOS_WALLET_UTILITY_H__

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \~English
 * Indicate the external chain.
 */
extern const int EXTERNAL_CHAIN;

/**
 * \~English
 * Indicate the internal chain.
 */
extern const int INTERNAL_CHAIN;

extern const int COIN_TYPE_ELA;
extern const int COIN_TYPE_IDCHAIN;

extern const char* ELA_ASSERT_ID;

struct MasterPublicKey
{
    uint32_t fingerPrint;
    uint8_t chainCode[32];
    uint8_t publicKey[33];
} ;

/**
 * \~English
 * Get single address wallet public key.
 *
 * @param
 *      seed     [in] binary conent of seed.
 * @param
 *      seedLen  [in] the length of seed.
 *
 * @return
 *      the public key if succeeded, or nullptr if failed.
 *      if you no longer use, call freeBuf to free memory.
 */
char* getSinglePublicKey(const void* seed, int seedLen);

/**
 * \~English
 * Get single address wallet private key.
 *
 * @param
 *      seed     [in] binary conent of seed.
 * @param
 *      seedLen  [in] the length of seed.
 *
 * @return
 *      the private key if succeeded, or nullptr if failed.
 *      if you no longer use, call freeBuf to free memory.
 */
char* getSinglePrivateKey(const void* seed, int seedLen);

/**
 * \~English
 * Get master public key for HD wallet.
 *
 * @param
 *      seed     [in] binary conent of seed.
 * @param
 *      seedLen  [in] the length of seed.
 * @param
 *      coinType [in] coin type.
 *
 * @return
 *      the master public key if succeeded, or nullptr if failed.
 *      if you no longer use, delete the pointer of MasterPublicKey.
 */
MasterPublicKey* getMasterPublicKey(const void* seed, int seedLen, int coinType);

/**
 * \~English
 * Get address from public key.
 *
 * @param
 *      publicKey     [in] the public key.
 *
 * @return
 *      the address if succeeded, or nullptr if failed.
 *      if you no longer use, call freeBuf to free memory.
 */
char* getAddress(const char* publicKey);

/**
 * \~English
 * Generate mnemonic.
 *
 * @param
 *      language     [in] language, such as english, chinese etc.
 * @param
 *      words        [in] the words, seperated by ' ', if the language is english, words is empty string.
 *
 * @return
 *      mnemonic if succeeded, or nullptr if failed.
 *      if you no longer use, call freeBuf to free memory.
 */
char* generateMnemonic(const char* language, const char* words);

/**
 * \~English
 * Get seed from mnemonic.
 *
 * @param
 *      seed                [out] the seed content, if no longer user, call freeBuf to free memory.
 * @param
 *      mnemonic            [in] mnemonic, seperated by ' '.
 * @param
 *      mnemonicPassword    [in] mnemonic password, empty string or effctive password.
 *
 * @return
 *      the seed buffer length if succeeded, or 0 if failed.
 */
int getSeedFromMnemonic(void** seed, const char* mnemonic, const char* mnemonicPassword);

/**
 * \~English
 * Sign data.
 *
 * @param
 *      privateKey          [in] the private key to sign the data.
 * @param
 *      data                [in] the data buffer.
 * @param
 *      len                 [in] length of data buffer.
 * @param
 *      signedData          [out] the signed data, if no longer user, call freeBuf to free memory.
 *
 * @return
 *      the signed data length if succeeded, or 0 if failed.
 */
int sign(const char* privateKey, const void* data, int len, void** signedData);

/**
 * \~English
 * Verify data.
 *
 * @param
 *      publicKey           [in] the publik key to verify the data.
 * @param
 *      data                [in] the source data.
 * @param
 *      len                 [in] length of source data.
 * @param
 *      signedData          [in] the signed data.
 * @param
 *      signedLen           [in] the signed data length.
 *
 * @return
 *      true if verification passed, or false if failed.
 */
bool verify(const char* publicKey, const void* data, int len, const void* signedData, int signedLen);

/**
 * \~English
 * Generate raw transaction data, sign transaction and serialize.
 *
 * @param
 *      transaction          [in] the transaction data in json string.
 *
 * @return
 *      the raw transaction data if succeeded, or nullptr if failed.
 *      if you no longer use, call freeBuf to free memory.
 */
char* generateRawTransaction(const char* transaction, const char* assertId = ELA_ASSERT_ID);

/**
 * \~English
 * Generate sub private key for HD wallet.
 *
 * @param
 *      seed          [in] binary conent of seed.
 * @param
 *      seedLen       [in] the length of seed.
 * @param
 *      coinType      [in] the coin type, for example COIN_TYPE_ELA.
 * @param
 *      chain         [in] the chain code, EXTERNAL_CHAIN or INTERNAL_CHAIN.
 * @param
 *      index         [in] the index of the key.
 *
 * @return
 *      the sub private key if succeeded, or nullptr if failed.
 *      if you no longer use, call freeBuf to free memory.
 */
char* generateSubPrivateKey(const void* seed, int seedLen, int coinType, int chain, int index);

/**
 * \~English
 * Generate sub public key for HD wallet.
 *
 * @param
 *      masterPublicKey          [in] the master public key.
 * @param
 *      chain                    [in] the chain code, EXTERNAL_CHAIN or INTERNAL_CHAIN.
 * @param
 *      index                    [in] the index of the key.
 *
 * @return
 *      the sub public key if succeeded, or nullptr if failed.
 *      if you no longer use, call freeBuf to free memory.
 */
char* generateSubPublicKey(const MasterPublicKey* masterPublicKey, int chain, int index);

/**
 * \~English
 * Free buffer.
 *
 * @param
 *      buf          [in] the buffer to be freed.
 */
void freeBuf(void* buf);

/**
 * \~English
 * Get public key from private key.
 *
 * @param
 *      privateKey          [in] the private key.
 *
 * @return
 *      the public key if succeeded, or nullptr if failed.
 *      if you no longer use, call freeBuf to free memory.
 */
char* getPublicKeyFromPrivateKey(const char* privateKey);

/**
 * \~English
 * Check the address is valid.
 *
 * @param
 *      address          [in] the address.
 *
 * @return
 *      true if valid address, or false if not.
 */
bool isAddressValid(const char* address);

// Apis for DID
/**
 * \~English
 * Generate DID from public key.
 *
 * @param
 *      publicKey          [in] the public key of ID chain.
 *
 * @return
 *      the DID if succeeded, or nullptr if failed.
 *      if you no longer use, call freeBuf to free memory.
 */
char* getDid(const char* publicKey);

// Apis for multi sign
/**
 * \~English
 * Get the multi sign address.
 *
 * @param
 *      publicKeys          [in] public key array of signers.
 * @param
 *      length              [in] the length of public key array.
 * @param
 *      requiredSignCount   [in] the require sign count.
 *
 * @return
 *      the address of multi sign if succeeded, or nullptr if failed.
 *      if you no longer use, call freeBuf to free memory.
 */
char* getMultiSignAddress(char** publicKeys, int length, int requiredSignCount);

/**
 * \~English
 * Generate the multi sign transaction json string, the json string can be send to the next signer.
 *
 * @param
 *      privateKey          [in] the private key to sign the transaction.
 * @param
 *      publicKeys          [in] public key array of signers.
 * @param
 *      length              [in] the length of public key array.
 * @param
 *      requiredSignCount   [in] the require sign count.
 * @param
 *      transaction         [in] the transaction data in json string.
 *
 * @return
 *      the signed transaction data in json string if succeeded, or nullptr if failed.
 *      if you no longer use, call freeBuf to free memory.
 */
char* multiSignTransaction(const char* privateKey, char** publicKeys, int length, int requiredSignCount, const char* transaction, const char* assertId = ELA_ASSERT_ID);

/**
 * \~English
 * Serialize the multi signed transaction json string.
 *
 * @param
 *      transaction          [in] the signed transaction data in json string.
 *
 * @return
 *      the serialized transaction data in json string if succeeded, or nullptr if failed.
 *      if you no longer use, call freeBuf to free memory.
 */
char* serializeMultiSignTransaction(const char* transaction, const char* assertId = ELA_ASSERT_ID);

char** getSignedSigners(const char* transaction, int* outLen, const char* assertId = ELA_ASSERT_ID);

char* eciesEncrypt(const char* publicKey, const char* plainText);

char* eciesDecrypt(const char* privateKey, const char* cipherText, int* len);

char* getPublicKeyFromXpub(const char* xpub, int chain, int index);

#ifdef __cplusplus
}
#endif

#endif //__ELASTOS_WALLET_UTILITY_H__
