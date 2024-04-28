# Fingerproxy

Inspired by [gospider007/fp](https://github.com/gospider007/fp). Fingerproxy is an HTTPS reverse proxy. It creates JA3, JA4, Akamai HTTP2 fingerprints, and forwards to backend via HTTP request headers.

```
         TLS                            HTTP/1.1 or HTTP/2
Client ------>   Fingerproxy    ------------------------------------>  HTTP Backend
                (listens :443)    | With request headers:        |    (127.0.0.1:80)
                                  | X-JA3-Fingerprint: abcd...   |
                                  | X-JA4-Fingerprint: t13d...   |
                                  | X-HTTP2-Fingerprint: 3:100...|
```

Fingerprints can be used for bot detection, DDoS mitigation, client identification, etc. To use these fingerprints, just get HTTP request headers in your backend apps.

Fingerproxy is also a Go library, allows you implementing your own fingerprinting algorithm.

## Usage

> [!TIP]
> Try fingerproxy in one minute:

Fingerproxy binary is available in GitHub releases: https://github.com/wi1dcard/fingerproxy/releases

```bash
# Generate fake certificates tls.crt and tls.key
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -days 3650 \
  -nodes -keyout tls.key -out tls.crt -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1"

# TLS server listens on :8443, forwarding requests to httpbin
./fingerproxy -listen-addr :8443 -forward-url https://httpbin.org

# Then test in another terminal
curl "https://localhost:8443/anything?show_env=1" --insecure
```

Fingerprints are in the HTTP request headers:

```yaml
{
  "headers": {
    # ...
    "X-Forwarded-Host": "localhost:8443",
    "X-Forwarded-Port": "443",
    "X-Forwarded-Proto": "https",
    "X-Http2-Fingerprint": "3:100;4:10485760;2:0|1048510465|0|m,s,a,p",
    "X-Ja3-Fingerprint": "0149f47eabf9a20d0893e2a44e5a6323",
    "X-Ja4-Fingerprint": "t13d3112h2_e8f1e7e78f70_6bebaf5329ac"
  },
  # ...
}
```

Fingerproxy supports Kubernetes liveness probe and Prometheus metrics. For the complete CLI options, see `fingerproxy --help`.

## Implement Your Fingerprinting Algorithm

Check out the example [`customize-fingerprint`](example/customize-fingerprint/). No code fork needed.

## Use as a Library

Fingerproxy is degigned to be highly customizable. It is separated into serveral packages. You can find all packages in the [`pkg`](pkg/) dir and use them to build your own fingerprinting server.

Here is an example [`echo-server`](example/echo-server/). Instead of forwarding HTTP requests, it simply responds back to client with the fingerprints.

## Similar Projects

### [gospider007/fp](https://github.com/gospider007/fp)

Great implementation based on golang net stack, works nice with golang HTTP handler. Fingerproxy rewrites TLS ClientHello capturing according to it.

Why not just use it?

- The JA3 and JA4 implementations contain bugs. For example,
  - In [fp.go](https://github.com/gospider007/ja3/blob/a58a93a771b99909e859ead9a9492015dd916947/fp.go#L337), `_` should be used instead of `,` as the separator of extensions and signature algorithms.
  - In [fp.go](https://github.com/gospider007/ja3/blob/a58a93a771b99909e859ead9a9492015dd916947/fp.go#L80), the protocol version in ClientHello handshake should be used for JA3.
  - In [ja3.go](https://github.com/gospider007/ja3/blob/a58a93a771b99909e859ead9a9492015dd916947/ja3.go#L769), `;` should be used instead of `,` as the parameters separator in HTTP2 settings frame.
  - Priority frame used in HTTP2 fingerprinting has not implemented yet.
- KISS
  - JA4H can be calculated in backend applications. Do not do it in the reverse proxy.
  - Complex design, unused methods, and copy-pastes from unknown source.

### [sleeyax/ja3rp](https://github.com/sleeyax/ja3rp)

Discontinued.

### [h3adex/guardgress](https://github.com/h3adex/guardgress)

Relies on [gospider007/fp](https://github.com/gospider007/fp).

### [wwhtrbbtt/TrackMe](https://github.com/wwhtrbbtt/TrackMe)

An HTTPS echo server that responds the fingerprints.

Why not just use it?

- It is not designed for forwarding the requests.
- Bugs too. In [ja4.go](https://github.com/wwhtrbbtt/TrackMe/blob/41b7933efe9ea364ade88ac6ea0e79a7b0203227/ja4.go#L85), the padding extension (21) somehow has preserved. Therefore there would be two duplicated `21` extension which is incorrect.

## Useful Websites

- <https://browserleaks.com/tls>

  JA3 and JA3 with sorted TLS extensions.

- <https://scrapfly.io/web-scraping-tools/ja3-fingerprint>

  JA3 and HTTP2 fingerprint; JA3 result is probably incorrect (doesn't match Wireshark's result).

- <https://tls.peet.ws/>

  Public deployment of [wwhtrbbtt/TrackMe](https://github.com/wwhtrbbtt/TrackMe); JA4 result might be incorrect (see above).

## References

- JA3 fingerprint: <https://github.com/salesforce/ja3>
- JA4 fingerprint: <https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md>
- Akamai HTTP2 fingerprinting: <https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf>
