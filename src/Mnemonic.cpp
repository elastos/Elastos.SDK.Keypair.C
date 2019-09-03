// Copyright (c) 2012-2018 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <fstream>
#include <sstream>

#include "BRBIP39WordsEn.h"

#include "Mnemonic.h"
#include <string.h>

#define MNEMONIC_PREFIX "mnemonic_"
#define MNEMONIC_EXTENSION ".txt"
// #include "SDK/Common/ParamChecker.h"


Mnemonic::Mnemonic(const std::string &language) :
    _i18nPath("data") {
    _language = language;
    setLanguage(language, "");
}

Mnemonic::Mnemonic(const std::string &language, const std::string &words) {
    // setI18nPath(path);
    _language = language;
    setLanguage(language, words);
}

void Mnemonic::setLanguage(const std::string &language, const std::string &words) {
    _words.clear();

    _words.reserve(BIP39_WORDLIST_COUNT);
    _language = language;

    if (language == "english" || language == "") {
        for (std::string str : BRBIP39WordsEn) {
            _words.push_back(str);
        }
    } else {
        // char fileName[512];
        // strcpy(fileName, _i18nPath);
        // strcat(fileName, MNEMONIC_PREFIX);
        // strcat(fileName, language.c_str());
        // strcat(fileName, MNEMONIC_EXTENSION);
        loadLanguage(words);
    }

    // ParamChecker::checkLangWordsCnt(_words.size());
}

std::string Mnemonic::getLanguage() const {
    return _language;
}

void Mnemonic::loadLanguage(const std::string &words) {
    // std::fstream infile(path);
    // std::string line;
    // while (std::getline(infile, line)) {
    //     _words.push_back(line);
    // }

    std::istringstream iss(words);

    std::string line;
    while (std::getline(iss, line))
    {
        _words.push_back(line);
    }
}

void Mnemonic::setI18nPath(const std::string &path) {
    strcpy(_i18nPath, path.c_str());
}

const std::vector<std::string> &Mnemonic::words() const {
    return _words;
}

