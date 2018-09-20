
if [[ -z "$ANDROID_NDK" ]]; then
    echo "Could not find Android NDK."
    echo "    You should set an environment variable:"
    echo "      export ANDROID_NDK=~/my-android-ndk"
    return 1
fi

export TARGET_PLATFORM=android

if [[ "$1" == "arm64" ]]; then
    export TARGET_ABI=arm64-v8a
else
    export TARGET_ABI=armeabi-v7a
fi

