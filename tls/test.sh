#!/usr/bin/env bash

module="vibe/detect_openssl11.d"
echo "module vibe.detect_openssl11;" "$module"

if true ; then
    echo "enum detectedOpenSSL11 = 1;" >> "$module"
fi
