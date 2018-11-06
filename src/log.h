
#ifndef __WALLET_C_LOG_H__
#define __WALLET_C_LOG_H__

#ifdef __ANDROID__
#include <android/log.h>
#define WALLET_C_LOG(...) __android_log_print(ANDROID_LOG_DEBUG, "ElastosWalletLibC", __VA_ARGS__)
#else
#define WALLET_C_LOG printf
#endif


#endif //__WALLET_C_LOG_H__
