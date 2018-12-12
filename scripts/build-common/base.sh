#!/bin/bash

set -o errexit
set -o nounset

logdbg()
{
	if [[ $DEBUG_VERBOSE == false ]]; then
		return;
	fi

	echo -e " [d]: $@";
}

logtrace()
{
	echo -e "\033[1;34m [-]: $@ \033[00m";
}

loginfo()
{
	echo -e "\033[1;32m [+]: $@ \033[00m";
}

logwarn()
{
	echo -e "\033[1;33m [!]: $@ \033[00m";
}

logerr_and_exit()
{
	echo -e "\033[1;31m [x]: $@ \033[00m";
	exit 1;
}

trim() {
	local var="$*"
	var="${var#"${var%%[![:space:]]*}"}"   # remove leading whitespace characters
	var="${var%"${var##*[![:space:]]}"}"   # remove trailing whitespace characters
	echo -n "$var"
}

MAX_JOBS=2
if [ -f /proc/cpuinfo ]; then
	MAX_JOBS=$(grep flags /proc/cpuinfo |wc -l)
elif [ ! -z $(which sysctl) ]; then
	MAX_JOBS=$(sysctl -n hw.ncpu)
fi

CURRENT_DIR=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd);
SCRIPT_DIR=$(dirname "$CURRENT_DIR");
PROJECT_DIR=$(dirname "$SCRIPT_DIR");
BUILD_BASE_DIR="$PROJECT_DIR/build";
BUILD_ROOT_DIR="$BUILD_BASE_DIR/sysroot";

DEBUG_VERBOSE=false;

source "$CURRENT_DIR/tarball-config.sh";
