#!/bin/sh

# Update this line as they make new releases.
VERSION=20121212

URL=https://closure-compiler.googlecode.com/files/compiler-$VERSION.tar.gz
TMPFILE=$(mktemp /tmp/compiler.tgz.XXXX)

echo "Downloading closure-compiler $VERSION"
curl "$URL" > "$TMPFILE"
tar -tzf "$TMPFILE" compiler.jar
# Bleh.
touch compiler.jar

rm "$TMPFILE"
