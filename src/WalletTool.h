// Copyright (c) 2012-2018 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef __WALLET_TOOL_H__
#define __WALLET_TOOL_H__

#include "CMemBlock.h"

class WalletTool {
private:
    static CMBlock GetRandom(size_t bits);

public:
    static CMBlock GenerateSeed128();

    static CMemBlock<char>
    GeneratePhraseFromSeed(const CMBlock &seed, const std::vector<std::string> &WordList);

    static bool PhraseIsValid(const CMemBlock<char> &phrase, const std::vector<std::string> &WordList);
};

#endif //__WALLET_TOOL_H__
