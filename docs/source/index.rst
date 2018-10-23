.. ElastosWalletLibC documentation master file, created by
   sphinx-quickstart on Tue Oct 23 11:06:17 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to ElastosWalletLibC's documentation!
=============================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

Introduction
------------
Wallet C APIs, include single address wallet, HD wallet, DID, sign transaction, multi sign transaction, verify transaction.

Constants
---------

.. doxygendefine:: EXTERNAL_CHAIN
    :project: ElastosWalletLibC

.. doxygendefine:: INTERNAL_CHAIN
    :project: ElastosWalletLibC

APIs
----

getSinglePublicKey
~~~~~~~~~~~~~~~~~~
.. doxygenfunction:: getSinglePublicKey
    :project: ElastosWalletLibC

getSinglePrivateKey
~~~~~~~~~~~~~~~~~~~
.. doxygenfunction:: getSinglePrivateKey
    :project: ElastosWalletLibC

getMasterPublicKey
~~~~~~~~~~~~~~~~~~
.. doxygenfunction:: getMasterPublicKey
    :project: ElastosWalletLibC

getAddress
~~~~~~~~~~
.. doxygenfunction:: getAddress
    :project: ElastosWalletLibC

generateMnemonic
~~~~~~~~~~~~~~~~
.. doxygenfunction:: generateMnemonic
    :project: ElastosWalletLibC

getSeedFromMnemonic
~~~~~~~~~~~~~~~~~~~
.. doxygenfunction:: getSeedFromMnemonic
    :project: ElastosWalletLibC

sign
~~~~
.. doxygenfunction:: sign
    :project: ElastosWalletLibC

verify
~~~~~~
.. doxygenfunction:: verify
    :project: ElastosWalletLibC

generateRawTransaction
~~~~~~~~~~~~~~~~~~~~~~
.. doxygenfunction:: generateRawTransaction
    :project: ElastosWalletLibC

generateSubPrivateKey
~~~~~~~~~~~~~~~~~~~~~
.. doxygenfunction:: generateSubPrivateKey
    :project: ElastosWalletLibC

generateSubPublicKey
~~~~~~~~~~~~~~~~~~~~
.. doxygenfunction:: generateSubPublicKey
    :project: ElastosWalletLibC

freeBuf
~~~~~~~
.. doxygenfunction:: freeBuf
    :project: ElastosWalletLibC

getPublicKeyFromPrivateKey
~~~~~~~~~~~~~~~~~~~~~~~~~~
.. doxygenfunction:: getPublicKeyFromPrivateKey
    :project: ElastosWalletLibC

isAddressValid
~~~~~~~~~~~~~~
.. doxygenfunction:: isAddressValid
    :project: ElastosWalletLibC

getIdChainMasterPublicKey
~~~~~~~~~~~~~~~~~~~~~~~~~
.. doxygenfunction:: getIdChainMasterPublicKey
    :project: ElastosWalletLibC

generateIdChainSubPrivateKey
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. doxygenfunction:: generateIdChainSubPrivateKey
    :project: ElastosWalletLibC

generateIdChainSubPublicKey
~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. doxygenfunction:: generateIdChainSubPublicKey
    :project: ElastosWalletLibC

getDid
~~~~~~
.. doxygenfunction:: getDid
    :project: ElastosWalletLibC

getMultiSignAddress
~~~~~~~~~~~~~~~~~~~
.. doxygenfunction:: getMultiSignAddress
    :project: ElastosWalletLibC

multiSignTransaction
~~~~~~~~~~~~~~~~~~~~
.. doxygenfunction:: multiSignTransaction
    :project: ElastosWalletLibC

serializeMultiSignTransaction
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. doxygenfunction:: serializeMultiSignTransaction
    :project: ElastosWalletLibC

Indices and tables
==================

* :ref:`genindex`
* :ref:`search`
