#!/bin/bash

set -o errexit
set -o nounset

CURRENT_DIR=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd);
PROJECT_DIR=$(dirname "$CURRENT_DIR")
DEPENDS_DIR="$PROJECT_DIR/config";

cd "$PROJECT_DIR";
git submodule init;
git submodule update;

build_extfunc_depends()
{
	"$DEPENDS_DIR/scripts/build-openssl.sh" $@;
}

export CFG_PROJECT_NAME="Elastos.SDK.Keypair.C";
export CFG_PROJECT_DIR="$PROJECT_DIR";
export CFG_CMAKELIST_DIR="$PROJECT_DIR";
source "$DEPENDS_DIR/scripts/build.sh" $@ --force-build;

