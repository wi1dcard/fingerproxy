#!/bin/bash -xeuo pipefail

TAG=v0.21.0
TAG_ARCHIVE_FILENAME=$TAG.tar.gz
LOCAL_ARCHIVE_FILENAME=/tmp/$TAG_ARCHIVE_FILENAME

wget -O $LOCAL_ARCHIVE_FILENAME https://github.com/golang/net/archive/refs/tags/$TAG_ARCHIVE_FILENAME

TMP_SRCDIR=$(mktemp -d)
BASEDIR=$(dirname $0)
TARBALL_ROOTDIR=$(tar tf $LOCAL_ARCHIVE_FILENAME | head -n1)

tar xzf $LOCAL_ARCHIVE_FILENAME --directory $TMP_SRCDIR

rsync -avhW --no-compress --delete $TMP_SRCDIR/$TARBALL_ROOTDIR/http2/ $BASEDIR/pkg/http2/
rsync -avhW --no-compress $TMP_SRCDIR/$TARBALL_ROOTDIR/LICENSE $BASEDIR/pkg/http2/

rm -rf $TMP_SRCDIR
