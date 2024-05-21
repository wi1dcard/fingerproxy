# Fingerproxy Example - My Fingerprint

This is an example of implementing a customized fingerprint with TLS ClientHello.

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
    "X-Amzn-Trace-Id": "Root=1-664c08ef-4efb8ea50d0d59181a2b1565",
    "X-Forwarded-Host": "localhost:8443",
    "X-Http2-Fingerprint": "3:100;4:10485760;2:0|1048510465|0|m,s,a,p",
    "X-Ja3-Fingerprint": "0149f47eabf9a20d0893e2a44e5a6323",
    "X-Ja4-Fingerprint": "t13d3112h2_e8f1e7e78f70_6bebaf5329ac",
    ## HERE ##
    "X-My-Fingerprint": "alpn:h2,http/1.1|supported_versions:772,771"
  }
}
```
