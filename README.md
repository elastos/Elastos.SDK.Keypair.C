# Elastos.Wallet.Utility

## Build on Ubuntu 64bit
### Check the required tools
Make sure your computer have installed the required packages below:
* [git](https://www.git-scm.com/downloads)
* [cmake](https://cmake.org/download)
* [wget](https://www.gnu.org/software/wget)

### Build for linux

```shell
$ cd build
$ . ./linux.sh
$ mkdir linux
$ cd linux
$ cmake ../..
$ make
```

### Build for android

```shell
$ export ANDROID_NDK=~/your_android_ndk_dir
$ cd build
$ . ./android armeavi-v7a
$ mkdir android
$ cd android
$ cmake ../..
$ make
```


## Build on Mac
### Build for ios simulator

```shell
$ cd build
$ . ios.sh x86_64
$ cd ios
$ cmake ../..
$ make -j4
```
