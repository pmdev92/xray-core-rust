#!/bin/bash
set -ex

CRATE_NAME="xray_ffi_android"

rm -rf ./build/android
mkdir -p ./build/android
cp -r ./xray_scripts/android ./build/
unzip ./build/android/gradle.zip -d ./build/android/gradle
rm -rf ./build/android/gradle.zip

if [ -z "$ANDROID_HOME" ]; then
  export ANDROID_HOME="$HOME/Library/Android/sdk"
fi

if [ -z "$ANDROID_NDK_HOME" ]; then
  export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/28.2.13676358"
fi

if [ -z "$ANDROID_NDK" ]; then
  export ANDROID_NDK="$ANDROID_NDK_HOME"
fi

if [ -z "$OPENSSL_DIR" ]; then
  export OPENSSL_DIR="$(brew --prefix openssl@3)"
fi


if [ "$1" = "all" ]; then
  targets="aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android"
else
	targets="aarch64-linux-android"
fi

for target in $targets; do
	rustup target add $target
done

ndk_targets=""
for target in $targets; do
    case $target in
        aarch64-linux-android) ndk_targets="$ndk_targets -t arm64-v8a" ;;
        armv7-linux-androideabi) ndk_targets="$ndk_targets -t armeabi-v7a" ;;
        x86_64-linux-android) ndk_targets="$ndk_targets -t x86_64" ;;
        i686-linux-android) ndk_targets="$ndk_targets -t x86" ;;
    esac
done

cargo install cargo-ndk
cargo ndk $ndk_targets -o ./build/android/src/main/jni build --package $CRATE_NAME --release
cargo run -p $CRATE_NAME --bin uniffi-bindgen generate --lib-file ./build/android/src/main/jni/arm64-v8a/libxray_ffi_android.so -c ./$CRATE_NAME/uniffi.toml --no-format --language kotlin --out-dir ./build/android/src/main/java ./$CRATE_NAME/src/xray.udl

./build/android/gradle/gradle-8.14.3/bin/gradle -p ./build/android clean assembleRelease
mv ./build/android/build/outputs/aar/core.aar ./build/LibXrayCoreRust.aar
#rm -rf ./build/android



#curl -L https://services.gradle.org/distributions/gradle-8.14.3-bin.zip -o gradle.zip
#unzip gradle.zip -d ./gradle