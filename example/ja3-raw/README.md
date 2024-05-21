# Fingerproxy Example - JA3 Raw

This example demonstrates passing the JA3 raw result (without final MD5 hashing) to the backend.

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
    "X-Amzn-Trace-Id": "Root=1-664c0810-09f1e3a03376e930030b20f7",
    "X-Forwarded-Host": "localhost:8443",
    "X-Http2-Fingerprint": "3:100;4:10485760;2:0|1048510465|0|m,s,a,p",
    "X-Ja3-Fingerprint": "0149f47eabf9a20d0893e2a44e5a6323",
    ## HEADER BELOW ##
    "X-Ja3-Raw-Fingerprint": "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-16-22-23-49-13-43-45-51-21,29-23-30-25-24-256-257-258-259-260,0-1-2",
    ## HEADER ABOVE ##
    "X-Ja4-Fingerprint": "t13d3112h2_e8f1e7e78f70_6bebaf5329ac"
  }
}
```
