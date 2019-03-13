Getting started with the wallet API
########################################

.. toctree::
  :maxdepth: 3

.. constants:

Constants
---------

.. c:macro:: EXTERNAL_CHAIN

  Indicate the external chain.

.. c:macro:: INTERNAL_CHAIN

  Indicate the internal chain.

.. c:macro:: COIN_TYPE_ELA

  Indicate the coin type ela.

.. c:macro:: ELA_ASSERT_ID

  The ela assert id.

.. api:

APIs
------

getSinglePublicKey
~~~~~~~~~~~~~~~~~~~

.. c:function:: char* getSinglePublicKey(const void* seed, int seedLen)

  Get single address wallet public key.

  **Return**
    the public key if succeeded, or nullptr if failed.

    *if you no longer use, call freeBuf to free memory.*

  **Parameter**
    :[in] seed: binary conent of seed.
    :[in] seedLen: the length of seed.


getSinglePrivateKey
~~~~~~~~~~~~~~~~~~~

.. c:function:: char* getSinglePrivateKey(const void* seed, int seedLen)

  Get single address wallet private key.

  **Return**
    the private key if succeeded, or nullptr if failed.

    *if you no longer use, call freeBuf to free memory.*

  **Parameter**
    :[in] seed: binary conent of seed.
    :[in] seedLen: the length of seed.


getMasterPublicKey
~~~~~~~~~~~~~~~~~~~

.. c:function:: MasterPublicKey* getMasterPublicKey(const void* seed, int seedLen, int coinType)

  Get master public key for HD wallet.

  **Return**
    the master public key if succeeded, or nullptr if failed.

    *if you no longer use, delete the pointer of MasterPublicKey.*

  **Parameter**
    :[in] seed: binary conent of seed.
    :[in] seedLen: the length of seed.
    :[in] coinType: coin type.


getAddress
~~~~~~~~~~~~~~~~~~~

.. c:function:: char* getAddress(const char* publicKey)

  Get address from public key.

  **Return**
    the address if succeeded, or nullptr if failed.

    *if you no longer use, call freeBuf to free memory.*

  **Parameter**
    :[in] publicKey: the public key.


generateMnemonic
~~~~~~~~~~~~~~~~~~~

.. c:function:: char* generateMnemonic(const char* language, const char* words)

  Generate mnemonic.

  **Return**
    the mnemonic if succeeded, or nullptr if failed.

    *if you no longer use, call freeBuf to free memory.*

  **Parameter**
    :[in] language: language, such as english, chinese etc.
    :[in] words: the words, seperated by ' ', if the language is english, words is empty string.


getSeedFromMnemonic
~~~~~~~~~~~~~~~~~~~

.. c:function:: int getSeedFromMnemonic(void** seed, const char* mnemonic, const char* language, const char* words, const char* mnemonicPassword)

  Get seed from mnemonic.

  **Return**
    the seed buffer length if succeeded, or 0 if failed.

  **Parameter**
    :[out] seed: the seed content, if no longer user, call freeBuf to free memory.
    :[in] mnemonic: mnemonic, seperated by ' '.
    :[in] language: language, such as english, chinese etc.
    :[in] words: the words, seperated by ' ', if the language is english, words is empty string.
    :[in] mnemonicPassword: mnemonic password, empty string or effctive password.


sign
~~~~~~~~~~~~~~~~~~~

.. c:function:: int sign(const char* privateKey, const void* data, int len, void** signedData)

  Sign data.

  **Return**
    the signed data length if succeeded, or 0 if failed.

  **Parameter**
    :[in] privateKey: the private key to sign the data.
    :[in] data: the data to be sign.
    :[in] len: length of data buffer.
    :[out] signedData: the signed data, if no longer user, call freeBuf to free memory.


verify
~~~~~~~~~~~~~~~~~~~

.. c:function:: bool verify(const char* publicKey, const void* data, int len, const void* signedData, int signedLen)

  Verify data.

  **Return**
    true if verification passed, or false if failed.

  **Parameter**
    :[in] publicKey: the publik key to sign the data.
    :[in] data: the source data to be verify.
    :[in] len: length of source data buffer.
    :[in] signedData: the signed data.
    :[in] signedData: the signed data length.


generateRawTransaction
~~~~~~~~~~~~~~~~~~~~~~~

.. c:function:: char* generateRawTransaction(const char* transaction)

  Generate raw transaction data, sign transaction and serialize.

  **Return**
    the raw transaction data if succeeded, or nullptr if failed.

    *if you no longer use, call freeBuf to free memory.*

  **Parameter**
    :[in] transaction: the transaction data in json string.


  sample of transaction:

  normal transaction
.. sourcecode:: json
  {
    "Transactions": [
        {
            "UTXOInputs": [
                {
                    "address": "ELbKQrj8DTYn2gU7KBejcNWb4ix4EAGDmy",
                    "txid": "378941ffe7ad7a25ae90db35142ba131dd7a1f9344a951851f4e051754d38577",
                    "index": 0,
                    "privateKey": {privateKey}
                }
            ],
            "Fee": 100,
            "Outputs": [
                {
                    "amount": 100,
                    "address": "ELbKQrj8DTYn2gU7KBejcNWb4ix4EAGDmy"
                },
                {
                    "amount": 11810,
                    "address": "ELbKQrj8DTYn2gU7KBejcNWb4ix4EAGDmy"
                }
            ]
        }
    ]
  }

  vote transaction
.. sourcecode:: json
  {
    "Transactions": [
        {
            "UTXOInputs": [
                {
                    "address": "ELbKQrj8DTYn2gU7KBejcNWb4ix4EAGDmy",
                    "txid": "378941ffe7ad7a25ae90db35142ba131dd7a1f9344a951851f4e051754d38577",
                    "index": 0,
                    "privateKey": {privateKey}
                }
            ],
            "Fee": 100,
            "Outputs": [
                {
                    "amount": 100,
                    "address": "ELbKQrj8DTYn2gU7KBejcNWb4ix4EAGDmy",
                    "payload":
                        {
                            "type": "delegate",
                            "candidatePublicKeys": ["033c495238ca2b6bb8b7f5ae172363caea9a55cf245ffb3272d078126b1fe3e7cd"]
                        }
                },
                {
                    "amount": 11810,
                    "address": "ELbKQrj8DTYn2gU7KBejcNWb4ix4EAGDmy"
                }
            ]
        }
    ]
  }


generateSubPrivateKey
~~~~~~~~~~~~~~~~~~~~~~~

.. c:function:: char* generateSubPrivateKey(const void* seed, int seedLen, int coinType, int chain, int index)

  Generate sub private key for HD wallet.

  **Return**
    the sub private key if succeeded, or nullptr if failed.

    *if you no longer use, call freeBuf to free memory.*

  **Parameter**
    :[in] seed: binary conent of seed.
    :[in] seedLen: the length of seed.
    :[in] coinType: the coin type, for example COIN_TYPE_ELA.
    :[in] chain: the chain code, EXTERNAL_CHAIN or INTERNAL_CHAIN.
    :[in] index: the index of the key.


generateSubPublicKey
~~~~~~~~~~~~~~~~~~~~~~~

.. c:function:: char* generateSubPublicKey(const MasterPublicKey* masterPublicKey, int chain, int index)

  Generate sub public key for HD wallet.

  **Return**
    the sub public key if succeeded, or nullptr if failed.

    *if you no longer use, call freeBuf to free memory.*

  **Parameter**
    :[in] masterPublicKey: the master public key.
    :[in] chain: the chain code, EXTERNAL_CHAIN or INTERNAL_CHAIN.
    :[in] index: the index of the key.


freeBuf
~~~~~~~~~~~~~~~~~~~~~~~

.. c:function:: void freeBuf(void* buf)

  Free buffer.

  **Parameter**
    :[in] buf: the buffer to be freed.


getPublicKeyFromPrivateKey
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. c:function:: char* getPublicKeyFromPrivateKey(const char* privateKey)

  Get public key from private key.

  **Return**
    the public key if succeeded, or nullptr if failed.

    *if you no longer use, call freeBuf to free memory.*

  **Parameter**
    :[in] privateKey: the private key.


isAddressValid
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. c:function:: bool isAddressValid(const char* address)

  Check the address is valid.

  **Return**
    true if valid address, or false if not.

  **Parameter**
    :[in] address: the address.


getDid
~~~~~~~~~~~~~~~~~~~

.. c:function:: char* getDid(const char* publicKey)

  Get DID from public key.

  **Return**
    the DID if succeeded, or nullptr if failed.

    *if you no longer use, call freeBuf to free memory.*

  **Parameter**
    :[in] publicKey: the public key of Id chain.



getMultiSignAddress
~~~~~~~~~~~~~~~~~~~

.. c:function:: char* getMultiSignAddress(char** publicKeys, int length, int requiredSignCount)

  Get the multi sign address.

  **Return**
    the multi sign address if succeeded, or nullptr if failed.

    *if you no longer use, call freeBuf to free memory.*

  **Parameter**
    :[in] publicKeys: public key array of signers.
    :[in] length: the length of public key array.
    :[in] requiredSignCount: the require sign count.


multiSignTransaction
~~~~~~~~~~~~~~~~~~~~~

.. c:function:: char* multiSignTransaction(const char* privateKey, char** publicKeys, int length, int requiredSignCount, const char* transaction)

  Generate the multi sign transaction json string, the json string can be send to the next signer.

  **Return**
    the signed transaction data in json string if succeeded, or nullptr if failed.

    *if you no longer use, call freeBuf to free memory.*

  **Parameter**
    :[in] privateKey: the private key to sign the transaction.
    :[in] publicKeys: public key array of signers.
    :[in] length: the length of public key array.
    :[in] requiredSignCount: the require sign count.
    :[in] transaction: the transaction data in json string.


serializeMultiSignTransaction
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. c:function:: char* serializeMultiSignTransaction(const char* transaction)

  Serialize the multi signed transaction json string.

  **Return**
    the serialized transaction data if succeeded, or nullptr if failed.

    *if you no longer use, call freeBuf to free memory.*

  **Parameter**
    :[in] transaction: the transaction data in json string.

