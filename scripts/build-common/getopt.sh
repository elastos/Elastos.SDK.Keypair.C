#!/bin/bash

set -o errexit
set -o nounset

GETOPT_IGNORE_UNRECOGNIZED=${GETOPT_IGNORE_UNRECOGNIZED:=false};

getopt_parse_options()
{
	local getopt_cmd="getopt";
	if [ "$(uname -s)" == "Darwin" ]; then
		getopt_cmd="/usr/local/Cellar/gnu-getopt/1.1.6/bin/getopt";
	fi

	getopt_ext=([0]= [1]=);
	type getopt_extfunc_options &>/dev/null && local ret=$(getopt_extfunc_options) && getopt_ext=(${ret//;/ });

	local args="--name getopt-script --options p:m:${getopt_ext[0]}h --longoptions platform:,arch:,${getopt_ext[1]},help";
	#echo "getopt args: $args";

	if [[ $GETOPT_IGNORE_UNRECOGNIZED  == true ]]; then
		local getopt_opts=$($getopt_cmd --quiet $args -- "$@");
		eval set -- "$getopt_opts";
	else
		local getopt_opts=$($getopt_cmd $args  -- "$@" 2>&1);
		if [[ "$getopt_opts" =~ "getopt:" ]]; then
			echo "Failed: $getopt_opts" >&2;
			exit 1;
		fi
		eval set -- "$getopt_opts";
	fi
	while true; do
		case "$1" in
			(-p | --platform)
				CFG_TARGET_PLATFORM=$2;
				shift 2;
				;;
			(-m | --arch)
				CFG_TARGET_ABI=$2;
				shift 2;
				;;
			(-h | --help)
				getopt_print_usage;
				exit 0;
				;;
			(- | --)
				shift;
				break;
				;;
			(*)
				type getopt_extfunc_processor &>/dev/null && getopt_extfunc_processor "$1" "$2";
				if ((  $getopt_extfunc_processor_ret > 0 )); then
					shift $getopt_extfunc_processor_ret;
				else
					echo "Internal error!";
					exit 1;
				fi
				;;
		esac
	done

	if [[ -z "$CFG_TARGET_ABI" ]]; then
		case "$CFG_TARGET_PLATFORM" in
			(Android)
				CFG_TARGET_ABI="armeabi-v7a";
				;;
			(iOS)
				CFG_TARGET_ABI="arm64";
				;;
			(*)
				CFG_TARGET_ABI="x86_64";
				;;
		esac
	fi

	getopt_print_input_log;
}

getopt_print_usage()
{
	echo '
NAME
       getopt-script

SYNOPSIS
       getopt-script [options]

DESCRIPTION
       getopt script.

OPTIONS
       -p, --platform=(Android | iOS)
                 Optional. target platform. If unspecified, use [`uname -m`] as default.

       -m, --arch=(ARCH)
                 Optional. target platform abi.
                 For native compile, use [x86_64] as default.
                 For Android, use [armeabi-v7a] as default.
                 For iOS, use [arm64] as default.';
	type getopt_extfunc_usage &>/dev/null && getopt_extfunc_usage;
	echo '
       -h, --help
                 Optional. Print help infomation and exit successfully.';
}

getopt_print_input_log()
{
	logtrace "*********************************************************";
	logtrace " Input infomation";
	logtrace "    platform        : $CFG_TARGET_PLATFORM";
	logtrace "    abi             : $CFG_TARGET_ABI";
	logtrace "    debug verbose   : $DEBUG_VERBOSE";
	logtrace "*********************************************************";
}

CURRENT_DIR=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd);
SCRIPT_DIR=$(dirname "$CURRENT_DIR");
source "$SCRIPT_DIR/build-common/base.sh";

CFG_TARGET_PLATFORM=$(uname -s);
CFG_TARGET_ABI=;

