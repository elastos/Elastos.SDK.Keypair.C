#!/bin/bash

set -o errexit
set -o nounset

CURRENT_DIR=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd);
PROJECT_DIR=$(dirname "$CURRENT_DIR")
DEPENDS_DIR="$PROJECT_DIR/config";

cd "$PROJECT_DIR";
git submodule init;
git submodule update;

custom_getopt_usage()
{
	echo "
           --with-filecoin
                 Optional. build with filecoin library.";
}
custom_getopt_options()
{
	echo ";with-filecoin";
}
custom_getopt_processor()
{
	custom_getopt_processor_ret=-1;
	case "$1" in
		(     --with-filecoin)
			export CFG_WITH_FILECOIN=true;
			custom_getopt_processor_ret=1;
			;;
	esac
}

build_extfunc_depends()
{
	"$DEPENDS_DIR/scripts/build-openssl.sh" $@;

	logdbg "CFG_WITH_FILECOIN=$CFG_WITH_FILECOIN";
	if [[ $CFG_WITH_FILECOIN == true ]]; then
		#"$DEPENDS_DIR/scripts/build-cpp-filecoin.sh" $@;
        "$DEPENDS_DIR/scripts/build-filecoin-ffi.sh" $@;
        "$DEPENDS_DIR/scripts/build-filecoin-signing-tools/build.sh" $@;
	fi

    CFG_CMAKE_EXTARGS="-DCFG_WITH_FILECOIN=ON";
}

export CFG_PROJECT_NAME="Elastos.SDK.Keypair.C";
export CFG_PROJECT_DIR="$PROJECT_DIR";
export CFG_CMAKELIST_DIR="$PROJECT_DIR";
export CFG_WITH_FILECOIN=false;
source "$DEPENDS_DIR/scripts/build.sh" $@ --force-build;

