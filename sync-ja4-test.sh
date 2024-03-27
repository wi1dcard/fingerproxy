#!/usr/bin/env -S bash -exuo pipefail

HEAD=main
HEAD_ARCHIVE_FILENAME=$HEAD.tar.gz
LOCAL_ARCHIVE_FILENAME=/tmp/$HEAD_ARCHIVE_FILENAME

wget -O $LOCAL_ARCHIVE_FILENAME https://github.com/FoxIO-LLC/ja4/archive/refs/heads/$HEAD_ARCHIVE_FILENAME

TMP_SRCDIR=$(mktemp -d)
BASEDIR=$(dirname $0)
TARBALL_ROOTDIR=$(tar tf $LOCAL_ARCHIVE_FILENAME | head -n1)

tar xzf $LOCAL_ARCHIVE_FILENAME --directory $TMP_SRCDIR

rsync -avhW --no-compress --delete $TMP_SRCDIR/$TARBALL_ROOTDIR/pcap/ $BASEDIR/pkg/ja4pcap/testdata/pcap/
rsync -avhW --no-compress --delete $TMP_SRCDIR/$TARBALL_ROOTDIR/rust/ja4/src/snapshots/ $BASEDIR/pkg/ja4pcap/testdata/snapshots/

rm -rf $TMP_SRCDIR
