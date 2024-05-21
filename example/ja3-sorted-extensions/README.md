# Fingerproxy Example - JA3 Variant with Sorted Extensions

JA3 is relatively old. The original implementation is outdated in certain use cases.

For example, Google Chrome has a feature called [TLS ClientHello extension permutation](https://chromestatus.com/feature/5124606246518784). It permutes the set of TLS extensions sent in the ClientHello message, resulting in a different JA3 fingerprint with every new connection from the browser.

Therefore we can no longer rely on the order of extensions. Sorting is necessary. Here is a very ugly example. It just demonstrates the possibility of extensibility of Fingerproxy. You might want to implement your own variant of JA3 fingerprint.

## Usage

```bash
# Generate fake certificates tls.crt and tls.key
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -days 3650 \
  -nodes -keyout tls.key -out tls.crt -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1"

# TLS server listens on :8443, forwarding requests to httpbin
go run . -listen-addr :8443 -forward-url https://httpbin.org

# Then test in another terminal
curl "https://localhost:8443/headers" --insecure
```

Output:

```yaml
{
  "headers": {
    "Accept": "*/*",
    "Accept-Encoding": "gzip",
    "Host": "httpbin.org",
    "User-Agent": "curl/8.6.0",
    "X-Amzn-Trace-Id": "Root=1-664c0b9c-4f89ce9c411f2cf22acd59bb",
    "X-Forwarded-Host": "localhost:8443",
    "X-Http2-Fingerprint": "3:100;4:10485760;2:0|1048510465|0|m,s,a,p",
    "X-Ja3-Fingerprint": "0149f47eabf9a20d0893e2a44e5a6323",
    "X-Ja4-Fingerprint": "t13d3112h2_e8f1e7e78f70_6bebaf5329ac",
    ## HERE ##
    "X-Sorted-Ja3-Fingerprint": "22441e3edb4a151c17462a438c7a10a5"
  }
}
```

Exit chrome and open again, you will see `X-Ja3-Fingerprint` changed but `X-Sorted-Ja3-Fingerprint` didn't.

## More Information

- <https://www.fastly.com/blog/a-first-look-at-chromes-tls-clienthello-permutation-in-the-wild/>
- <https://github.com/net4people/bbs/issues/220>
