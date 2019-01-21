#!/bin/bash

set -o errexit
set -o nounset

CURRENT_DIR=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd);
PROJECT_DIR=$(dirname "$CURRENT_DIR")
DEPENDS_DIR="$PROJECT_DIR/config";
BUILD_SH="$CURRENT_DIR/build.sh";

cd "$PROJECT_DIR";
git submodule init;
git submodule update;

build_extfunc()
{
	"$BUILD_SH" $@;
}
export CFG_PROJECT_DIR="$PROJECT_DIR";
export CFG_PROJECT_NAME="Elastos.SDK.Keypair.C";
source "$DEPENDS_DIR/scripts/package-mobile.sh" $@;
