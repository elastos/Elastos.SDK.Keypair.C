
#ifndef __CIPHERTEXT_H__
#define __CIPHERTEXT_H__

int ecies_encrypt(const void *pubKey, size_t pubKeyLen, const char* plainText, char* cipherText, size_t* cipherLen);

int ecies_decrypt(const void *privKey, size_t privKeyLen, const char* cipherText, char* plainText, size_t* plainLen);

#endif //__CIPHERTEXT_H__
