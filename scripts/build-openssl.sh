#!/bin/bash

set -o errexit
set -o nounset

download_tarball()
{
	if [ ! -e "$TARBALL_DIR/.$OPENSSL_NAME" ]; then
		openssl_url="$OPENSSL_BASE_URL/$OPENSSL_TARBALL";
		echo curl "$openssl_url" --output "$TARBALL_DIR/$OPENSSL_TARBALL";
		curl "$openssl_url" --output "$TARBALL_DIR/$OPENSSL_TARBALL";
		echo "$openssl_url" > "$TARBALL_DIR/.$OPENSSL_NAME";
	fi

	loginfo "$OPENSSL_TARBALL has been downloaded."
}

build_openssl()
{
	mkdir -p "$OPENSSL_BUILDDIR" && cd "$OPENSSL_BUILDDIR";
	loginfo "change directory to $OPENSSL_BUILDDIR";

	if [ ! -e "$OPENSSL_BUILDDIR/$OPENSSL_NAME" ]; then
		tar xf "$TARBALL_DIR/$OPENSSL_TARBALL";
	fi
	loginfo "$OPENSSL_TARBALL has been unpacked."
	cd "$OPENSSL_BUILDDIR/$OPENSSL_NAME";
	$@ --prefix=$OUTPUT_DIR \
		no-asm \
		no-shared \
		no-cast \
		no-idea \
		no-camellia;

	#make -j$MAX_JOBS && make install_engine
	make install_dev
}

main_run()
{
	loginfo "parsing options";
	getopt_parse_options $@;

	case "$CFG_TARGET_PLATFORM" in
		(Android)
			source "$SCRIPT_DIR/build-common/setenv-android.sh";
			export ANDROID_NDK="$ANDROID_TOOLCHAIN_PATH";
			local arch=${CFG_TARGET_ABI%-*};
			arch=${arch%eabi};
			CONFIG_PARAM="./Configure android-$arch";
			;;
		(iOS)
			source "$SCRIPT_DIR/build-common/setenv-ios.sh";
			[[ "$CFG_TARGET_ABI" = "x86_64" ]] && arch="iossimulator" || arch="ios64"
			CONFIG_PARAM="./Configure $arch-xcrun"

			;;
		(*)
			source "$SCRIPT_DIR/build-common/setenv-unixlike.sh";
			CONFIG_PARAM="./config";
			;;
	esac

	OPENSSL_BUILDDIR="$BUILD_DIR/openssl";

	download_tarball;

	build_openssl $CONFIG_PARAM;

	loginfo "DONE !!!";
}

SCRIPT_DIR=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd);

source "$SCRIPT_DIR/build-common/getopt.sh";

main_run $@;
