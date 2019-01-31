# Elastos.SDK.Keypair.C

[Elastos.SDK.Keypair.C documentation](https://elastoswalletlibc.readthedocs.io)

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
* clang 8.0.0 or newer version.

### Build for linux


```shell
$ ./script/build.sh
```

### Build for android

```shell
$ ./script/build.sh -f Android
```


## Build on Mac
### Build for ios simulator

```shell
$ ./script/build.sh
```

## Build script

./script/build.sh -h for more infomation.
