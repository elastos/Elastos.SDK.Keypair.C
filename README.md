# Elastos.Wallet.Utility

## Use dockerized Untuntu_64bit build environment

### Check the required tools
Install docker and docker-compose
Follow the official instructions to install Docker and Docker Compose.

* [Docker](https://docs.docker.com/install/)
* [Docker Compose](https://docs.docker.com/compose/install/)

### Build the docker image

```shell
$ cd docker
$ docker-compose build --build-arg HOST_USER_UID=`id -u` --build-arg HOST_USER_GID=`id -g` build-env

```

### Enter the dockerized build environment

```shell
$ cd docker
$ docker-compose run --rm build-env

```
Type exit if you want to exit the docker build environment. And type docker-compose run --rm build-env if you want to re-enter it.

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
$ . ./android armeavi-v7a(for armv7)/arm64(for armv8)
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
