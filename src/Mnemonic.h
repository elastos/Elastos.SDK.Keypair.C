// Copyright (c) 2012-2018 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef __MNEMONICS_H__
#define __MNEMONICS_H__

#include <string>
#include <vector>


class Mnemonic {
public:
    explicit Mnemonic(const std::string &language = "english");

    Mnemonic(const std::string &language, const std::string &path);

    const std::vector<std::string> &words() const;

    void setLanguage(const std::string &language);
    std::string getLanguage() const;

    void setI18nPath(const std::string &path);

private:
    void loadLanguage(const std::string &path);

private:
    std::string _language;
    char _i18nPath[512];
    std::vector<std::string> _words;
};


#endif //__MNEMONICS_H__
