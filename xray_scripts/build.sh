#!/bin/bash

set -e
set -o pipefail

# =====================
# Config
# =====================
CRATE_NAME="xray_ffi_ios"
OUTPUT_NAME="LibXrayCoreRust"
OUTPUT_DIR="build"
PACKAGE_NAME="LibXrayCoreRust"

HEADERS_DIR="${OUTPUT_DIR}/Headers"
HEADER_FILE="${HEADERS_DIR}/${CRATE_NAME}/${CRATE_NAME}.h"
MODULEMAP_FILE="${HEADERS_DIR}/${CRATE_NAME}/module.modulemap"
XCFRAMEWORK_DIR="${OUTPUT_DIR}/${OUTPUT_NAME}.xcframework"

TOOLCHAIN=$(cat rust-toolchain.toml | grep -E 'channel\s*=' | cut -d'"' -f2)
TARGET_DIR=$(cargo metadata --no-deps --format-version=1 | jq -r '.target_directory')

# =====================
# BUILD MODE
# =====================
BUILD_MODE=${BUILD_MODE:-all}
echo "Build mode: $BUILD_MODE"

IOS_ARCHS=("aarch64-apple-ios" "x86_64-apple-ios" "aarch64-apple-ios-sim")
MACOS_ARCHS=("aarch64-apple-darwin" "x86_64-apple-darwin")

IOS_DEVICE=("aarch64-apple-ios")
IOS_SIM=("x86_64-apple-ios" "aarch64-apple-ios-sim")
MAC_ONLY=("aarch64-apple-darwin" "x86_64-apple-darwin")

TARGETS=()

case "$BUILD_MODE" in
  ios)
    TARGETS=("${IOS_DEVICE[@]}")
    ;;
  simulator)
    TARGETS=("${IOS_DEVICE[@]}" "${IOS_SIM[@]}")
    ;;
  macos)
    TARGETS=("${MAC_ONLY[@]}")
    ;;
  all|*)
    TARGETS=("${IOS_ARCHS[@]}" "${MACOS_ARCHS[@]}")
    ;;
esac

# =====================
# tools
# =====================
if ! command -v cbindgen &> /dev/null; then
  cargo +$TOOLCHAIN install cbindgen
fi

# =====================
# header
# =====================
mkdir -p "$HEADERS_DIR"

cbindgen --config $CRATE_NAME/cbindgen.toml \
         --crate $CRATE_NAME \
         --output $HEADER_FILE

cat > "$MODULEMAP_FILE" <<EOF
module $PACKAGE_NAME {
    umbrella header "$(basename $HEADER_FILE)"
    export *
}
EOF

# =====================
# build rust
# =====================
for target in "${TARGETS[@]}"; do
    echo "Building $target"

    rustup target add "$target" --toolchain $TOOLCHAIN || true

    IPHONEOS_DEPLOYMENT_TARGET=10.0 \
    cargo +$TOOLCHAIN build \
        --package "$CRATE_NAME" \
        --target "$target" \
        --release

    mkdir -p "$OUTPUT_DIR/$target"

    cp "$TARGET_DIR/$target/release/lib${CRATE_NAME}.a" \
       "$OUTPUT_DIR/$target/"
done

# =====================
# LIPO (unchanged logic but safe)
# =====================
mkdir -p "$OUTPUT_DIR/ios-simulator-universal"
mkdir -p "$OUTPUT_DIR/macos-universal"

if [[ "$BUILD_MODE" == "simulator" || "$BUILD_MODE" == "all" ]]; then
lipo -create \
    "$OUTPUT_DIR/x86_64-apple-ios/lib${CRATE_NAME}.a" \
    "$OUTPUT_DIR/aarch64-apple-ios-sim/lib${CRATE_NAME}.a" \
    -output "$OUTPUT_DIR/ios-simulator-universal/lib${CRATE_NAME}.a"
fi

if [[ "$BUILD_MODE" == "macos" || "$BUILD_MODE" == "all" ]]; then
lipo -create \
    "$OUTPUT_DIR/aarch64-apple-darwin/lib${CRATE_NAME}.a" \
    "$OUTPUT_DIR/x86_64-apple-darwin/lib${CRATE_NAME}.a" \
    -output "$OUTPUT_DIR/macos-universal/lib${CRATE_NAME}.a"
fi

# =====================
# Framework wrappers
# =====================
echo "Creating framework wrappers..."

DEVICE_FWK="${OUTPUT_DIR}/aarch64-apple-ios/${OUTPUT_NAME}.framework"
SIM_FWK="${OUTPUT_DIR}/ios-simulator-universal/${OUTPUT_NAME}.framework"
MAC_FWK="${OUTPUT_DIR}/macos-universal/${OUTPUT_NAME}.framework"

mkdir -p "$HEADERS_DIR"

# helper function
create_fwk () {
  FWK_PATH=$1
  BIN=$2
  IDENT=$3

  mkdir -p "$FWK_PATH/Headers" "$FWK_PATH/Modules"

  cp "$BIN" "$FWK_PATH/$OUTPUT_NAME"
  cp "$HEADER_FILE" "$FWK_PATH/Headers/"

  cat > "$FWK_PATH/Modules/module.modulemap" <<EOF
framework module $OUTPUT_NAME {
    umbrella header "${CRATE_NAME}.h"
    export *
}
EOF

  cat > "$FWK_PATH/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>$IDENT</string>
</dict>
</plist>
EOF
}

if [[ "$BUILD_MODE" == "ios" || "$BUILD_MODE" == "simulator" || "$BUILD_MODE" == "all" ]]; then
  create_fwk "$DEVICE_FWK" \
    "$OUTPUT_DIR/aarch64-apple-ios/lib${CRATE_NAME}.a" \
    "com.rust.$OUTPUT_NAME.ios"
fi

if [[ "$BUILD_MODE" == "simulator" || "$BUILD_MODE" == "all" ]]; then
  create_fwk "$SIM_FWK" \
    "$OUTPUT_DIR/ios-simulator-universal/lib${CRATE_NAME}.a" \
    "com.rust.$OUTPUT_NAME.simulator"
fi

if [[ "$BUILD_MODE" == "macos" || "$BUILD_MODE" == "all" ]]; then
  create_fwk "$MAC_FWK" \
    "$OUTPUT_DIR/macos-universal/lib${CRATE_NAME}.a" \
    "com.rust.$OUTPUT_NAME.macos"
fi

# =====================
# XCFramework
# =====================
rm -rf "$XCFRAMEWORK_DIR"

echo "Creating XCFramework..."

ARGS=()

if [[ "$BUILD_MODE" == "ios" || "$BUILD_MODE" == "simulator" || "$BUILD_MODE" == "all" ]]; then
  ARGS+=("-framework" "$DEVICE_FWK")
fi

if [[ "$BUILD_MODE" == "simulator" || "$BUILD_MODE" == "all" ]]; then
  ARGS+=("-framework" "$SIM_FWK")
fi

if [[ "$BUILD_MODE" == "macos" || "$BUILD_MODE" == "all" ]]; then
  ARGS+=("-framework" "$MAC_FWK")
fi

xcodebuild -create-xcframework \
  "${ARGS[@]}" \
  -output "$XCFRAMEWORK_DIR"

# =====================
# cleanup (UNCHANGED)
# =====================
echo "Cleaning up intermediate files..."
find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 ! -name "$(basename $XCFRAMEWORK_DIR)" -exec rm -rf {} +

echo "Done!"