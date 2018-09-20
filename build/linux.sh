
if [[  $OSTYPE != *linux* ]]; then
 echo "Not supported OSTYPE($OSTYPE)."
 exit 1
fi

export TARGET_PLATFORM=linux
export TARGET_ABI=x86_64
