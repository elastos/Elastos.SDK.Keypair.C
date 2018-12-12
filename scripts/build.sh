#!/bin/bash

set -o errexit
set -o nounset

getopt_extfunc_usage()
{
	echo "
       -s, --enable-static
                 Optional. build static library. If unspecified, use [shared] as default.

       -d, --without-depends
                 Optional. build without dependencies. If unspecified, use [false] as default.

       -t, --with-test
                 Optional. build test case.

       -i, --ignore-build
                 Optional. only config project but don't build.";
}
getopt_extfunc_options()
{
	echo "sdti;enable-static,without-depends,with-test,ignore-build";
}
getopt_extfunc_processor()
{
	getopt_extfunc_processor_ret=-1;
	case "$1" in
		(-s | --enable-static)
			CFG_ENABLE_SHARED_LIB=OFF;
			getopt_extfunc_processor_ret=1;
			;;
		(-d | --without-depends)
			CFG_WITHOUT_DEPENDS=true;
			getopt_extfunc_processor_ret=1;
			;;
		(-t | --with-test)
			CFG_WITH_TEST=true;
			getopt_extfunc_processor_ret=1;
			;;
		(-i | --ignore-build)
			CFG_IGNORE_BUILD=true;
			getopt_extfunc_processor_ret=1;
			;;
	esac
}

build_project()
{
	mkdir -p "$PROJECT_BUILDDIR" && cd "$PROJECT_BUILDDIR";
	loginfo "change directory to $PROJECT_BUILDDIR";

	local cmake_ext_args="";
	if [[ $CFG_WITH_TEST == true ]]; then
		cmake_ext_args+=" -DCFG_WITH_TEST=";
	fi
	echo $cmake_ext_args;

	cd "$PROJECT_BUILDDIR";
	cmake "$PROJECT_DIR" \
		-DCMAKE_INSTALL_PREFIX="$OUTPUT_DIR" \
		-DBUILD_SHARED_LIBS=$CFG_ENABLE_SHARED_LIB \
		-DCFG_TARGET_PLATFORM=$CFG_TARGET_PLATFORM \
		-DCFG_TARGET_ABI=$CFG_TARGET_ABI \
		$cmake_ext_args;

	if [[ $CFG_IGNORE_BUILD == false ]]; then
		make -j$MAX_JOBS && make install;
	fi
}

main_run()
{
	loginfo "parsing options";
	export GETOPT_IGNORE_UNRECOGNIZED=false;
	getopt_parse_options $@;

	# build dependencies first.
	if [[ $CFG_WITHOUT_DEPENDS == false ]]; then
		export GETOPT_IGNORE_UNRECOGNIZED=true;
		"$SCRIPT_DIR/build-openssl.sh" $@;
		export GETOPT_IGNORE_UNRECOGNIZED=false;
	fi

	case "$CFG_TARGET_PLATFORM" in
		(Android)
			source "$SCRIPT_DIR/build-common/setenv-android.sh";
			;;
		(iOS)
			source "$SCRIPT_DIR/build-common/setenv-ios.sh";
			;;
		(*)
			source "$SCRIPT_DIR/build-common/setenv-unixlike.sh";
			;;
	esac

	PROJECT_NAME="Elastos.SDK.Wallet.C";
	PROJECT_BUILDDIR="$BUILD_DIR/$PROJECT_NAME";

	build_project $@;

	loginfo "DONE !!!";
}

SCRIPT_DIR=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd);
source "$SCRIPT_DIR/build-common/getopt.sh";

CFG_ENABLE_SHARED_LIB=ON;
CFG_WITHOUT_DEPENDS=false;
CFG_WITH_TEST=false;
CFG_IGNORE_BUILD=false;

main_run $@;
