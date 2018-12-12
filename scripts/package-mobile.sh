#!/bin/bash

set -o errexit
set -o nounset

build_all()
{
	local target_platforms=(Android
	                        iOS);
	                        #$(uname -s));

	local target_abis=(armeabi-v7a  arm64-v8a  x86_64
	                   -            arm64      x86_64
	                   -            -          x86_64);
	local target_abi_type=$((${#target_abis[@]} / ${#target_platforms[@]}));

	for pidx in "${!target_platforms[@]}"; do
		local platform="${target_platforms[pidx]}";

		for (( tidx = 0; tidx < $target_abi_type; tidx++)); do
			local aidx=$((${target_abi_type} * ${pidx} + ${tidx}));
			#echo "==========================$aidx";
			local abi="${target_abis[aidx]}";
			if [[ "$abi" == "-" ]]; then
				continue;
			fi

			echo "Build for $platform ($abi)";
			"$SCRIPT_DIR/build.sh" --platform=$platform --arch=$abi --enable-static;
		done
	done
}

make_android_manifest()
{
	local package_name=$1;
	local manifest_xml=$2;

	echo '<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="'$package_name'">
    <uses-sdk android:minSdkVersion="19" android:targetSdkVersion="21"/>
</manifest>' \
	> "$manifest_xml";
}

package_android()
{
	local pkg_android_dir="$PACKAGE_DIR/Android";

	local abi_list=$(ls "$BUILD_ROOT_DIR/Android");
	for abi in $abi_list; do
		mkdir -p "$pkg_android_dir/jni/$abi";
		cp -rv "$BUILD_ROOT_DIR/Android/$abi/lib/lib"*.a "$pkg_android_dir/jni/$abi/";

		mkdir -p "$pkg_android_dir/jni/include";
		cp -rv "$BUILD_ROOT_DIR/Android/$abi/include/$PROJECT_NAME/"* "$pkg_android_dir/jni/include/";
	done

	local package_name="org.elastos.sdk.wallet.c";
	make_android_manifest "$package_name" "$pkg_android_dir/AndroidManifest.xml";

	cd "$pkg_android_dir";
	zip -r "${PACKAGE_DIR}/${PROJECT_NAME}.aar" jni AndroidManifest.xml;
	#jar cvf "${PACKAGE_DIR}/${PROJECT_NAME}.aar" -C "$pkg_android_dir" jni AndroidManifest.xml;
	loginfo "Success to create ${PACKAGE_DIR}/${PROJECT_NAME}.aar";
}

package_ios()
{
	local pkg_ios_dir="$PACKAGE_DIR/iOS";

	local package_list=()
	local abi_list=$(ls "$BUILD_ROOT_DIR/iOS");
	for abi in $abi_list; do
		mkdir -p "$pkg_ios_dir/$abi";
		cp -rv "$BUILD_ROOT_DIR/iOS/$abi/lib/lib"*.a "$pkg_ios_dir/$abi/";

		echo "lipo $abi library ..."
		cd "$pkg_ios_dir/$abi/";
		libtool -static -o "${pkg_ios_dir}/$abi/${PROJECT_NAME}.raw" *.a

		package_list+=("$pkg_ios_dir/$abi/$PROJECT_NAME.raw")

		mkdir -p "$pkg_ios_dir/include";
		cp -rv "$BUILD_ROOT_DIR/iOS/$abi/include/$PROJECT_NAME/"* "$pkg_ios_dir/include/";
	done

	echo "Creating ${PROJECT_NAME}.framework"
	cd "$pkg_ios_dir/";
	mkdir -p "${PACKAGE_DIR}/${PROJECT_NAME}.framework/Headers";
	cp -r "$pkg_ios_dir/include/"* "${PACKAGE_DIR}/${PROJECT_NAME}.framework/Headers";
	lipo -create ${package_list[@]} -output "$PACKAGE_DIR/${PROJECT_NAME}.framework/${PROJECT_NAME}"

	loginfo "Success to create ${PACKAGE_DIR}/${PROJECT_NAME}.framework";
}

main_run()
{
	build_all;

	loginfo "Remove previous packages in $PACKAGE_DIR";
	rm -rf "$PACKAGE_DIR";

	package_android;

	package_ios;
}

SCRIPT_DIR=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd);
source "$SCRIPT_DIR/build-common/base.sh";
PROJECT_NAME="Elastos.ORG.Wallet.Lib.C"
PACKAGE_DIR="$BUILD_BASE_DIR/package";

main_run $@;
