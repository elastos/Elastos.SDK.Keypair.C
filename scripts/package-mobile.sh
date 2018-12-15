#!/bin/bash

set -o errexit
set -o nounset

CURRENT_DIR=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd);
PROJECT_DIR=$(dirname "$CURRENT_DIR")
DEPENDS_DIR="$PROJECT_DIR/config/scripts";
BUILD_SH="$CURRENT_DIR/build.sh";

build_extfunc()
{
	"$BUILD_SH" $@;
}
export CFG_PROJECT_DIR="$PROJECT_DIR";
export CFG_PROJECT_NAME="Elastos.ORG.Wallet.Lib.C";
source "$DEPENDS_DIR/package-mobile.sh" $@;
