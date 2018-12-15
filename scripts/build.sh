#!/bin/bash

set -o errexit
set -o nounset

CURRENT_DIR=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd);
PROJECT_DIR=$(dirname "$CURRENT_DIR")
SCRIPT_DIR="$PROJECT_DIR/config/scripts";

if [ ! -d "$SCRIPT_DIR" ]; then
	git submodule init;
	git submodule update;
fi

build_extfunc_depends()
{
	"$SCRIPT_DIR/build-openssl.sh" $@;
}
CFG_PROJECT_DIR="$PROJECT_DIR";
source "$SCRIPT_DIR/build.sh" $@;

