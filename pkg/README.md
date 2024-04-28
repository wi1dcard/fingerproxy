# Use Fingerproxy as a Library

For the documentation, refer to [godoc](https://pkg.go.dev/github.com/wi1dcard/fingerproxy/pkg).

There are some vendored packages:

- Package `http2` is a fork of standard http2 package in [`x/net`](https://github.com/golang/net/tree/master/http2). Follow and sync upstream whenever you want using [./sync-http2-pkg.sh](./sync-http2-pkg.sh).
- Package `ja3` is cloned from <https://github.com/dreadl0ck/ja3>. See [./ja3/sync.sh](./ja3/sync.sh) for more info.

If you want to use them, please import from the origin.
