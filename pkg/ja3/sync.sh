#!/bin/sh

#
# The JA3 algoritm source code is cloned from https://github.com/dreadl0ck/ja3.
#
# This package imports https://github.com/google/gopacket which depends on pcap. However,
# Fingerproxy does not need pcap and it causes trouble while cross compiling, for example,
# it requires to install libpcap-dev which makes no sense for Fingerproxy. Therefore, we
# decided to take the shortcut - copy-paste the algorithm part source code.
#

cd $(dirname "$0")

wget https://raw.githubusercontent.com/dreadl0ck/ja3/master/ja3.go
