#!/usr/bin/env -S bash -exuo pipefail

#
# Sync the test cases from the official JA4 repo.
#

cd $(dirname "$0")

HEAD=main
HEAD_ARCHIVE_FILENAME=$HEAD.tar.gz
LOCAL_ARCHIVE_FILENAME=/tmp/$HEAD_ARCHIVE_FILENAME

wget -O $LOCAL_ARCHIVE_FILENAME https://github.com/FoxIO-LLC/ja4/archive/refs/heads/$HEAD_ARCHIVE_FILENAME

TMP_SRCDIR=$(mktemp -d)
TARBALL_ROOTDIR=$(tar tf $LOCAL_ARCHIVE_FILENAME | head -n1)

tar xzf $LOCAL_ARCHIVE_FILENAME --directory $TMP_SRCDIR

rsync -avhW --no-compress --delete $TMP_SRCDIR/$TARBALL_ROOTDIR/pcap/ ./testdata/pcap/
rsync -avhW --no-compress --delete $TMP_SRCDIR/$TARBALL_ROOTDIR/rust/ja4/src/snapshots/ ./testdata/snapshots/

rm -rf $TMP_SRCDIR
