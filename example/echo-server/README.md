# Fingerproxy's echo-server

This is an example of using Fingerproxy as a library. It utilizes the packages provided by Fingerproxy to create an echo service. Unlike the `fingerproxy` command, it does not forward requests to a backend, instead, `echo-server` simply responds back to client with the fingerprints.

> [!WARNING]
> The echo-server is just a PoC which does not follow Fingerproxy's SemVer. It is not tested in production. The APIs may be changed in any release. Please remember use it at your own risk.

## Usage

1. Download echo-server binary from GitHub releases: <https://github.com/wi1dcard/fingerproxy/releases/latest>
2. Prepare certificates or generate self-signed certificates.
3. Run echo-server: `./echo-server`.
4. Optional: use `-verbose` or `-quiet` to get more or less logs.

## API

### GET `/`

Get the fingerprints.

<details>
<summary>Example</summary>

```bash
$ curl https://localhost:8443/ --insecure
```

Response:

```
User-Agent: curl/8.6.0
TLS ClientHello Record: 1603010200010001fc030343e508c0a4676da67fe2f68a0f045d56f0504b9f572828189c020f3773ef838120225f9cf0a9a1a6ec2a5ae5987dc80e57ebb2d9cc60384d8664b3b47b01c3cf9f003e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff010001750000000e000c0000096c6f63616c686f7374000b000403000102000a00160014001d0017001e00190018010001010102010301040010000e000c02683208687474702f312e31001600000017000000310000000d0030002e04030503060308070808081a081b081c0809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d00208f0de8a643605177c1d9b09b5e65325d3834da5b7d608d2d27f4ffe784ce883b001500b200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
JA3 fingerprint: 0149f47eabf9a20d0893e2a44e5a6323
JA4 fingerprint: t13d3112h2_e8f1e7e78f70_6bebaf5329ac
HTTP2 fingerprint: 3:100;4:10485760;2:0|1048510465|0|m,s,a,p
```
</details>

### GET `/json`

Get the fingerprints in JSON format.

<details>
<summary>Example</summary>

```bash
$ curl https://localhost:8443/json --insecure | jq
```

Response:

```json
{
  "ja3": "0149f47eabf9a20d0893e2a44e5a6323",
  "ja4": "t13d3112h2_e8f1e7e78f70_6bebaf5329ac",
  "http2": "3:100;4:10485760;2:0|1048510465|0|m,s,a,p"
}
```
</details>

### GET `/json/detail`

Get the fingerprints, as well as the detailed raw data that has been used for creating fingerprints.

<details>
<summary>Example</summary>

```bash
$ curl https://localhost:8443/json/detail --insecure | jq
```

Response:

```json
{
  "detail": {
    "metadata": {
      "ClientHelloRecord": "FgMBAgABAAH8AwPz9vlIElIYMFW/b8YdGNPpSH1f23HqsIo77l0x7x7X6SDSErd5AuwakOQG59gMX2UVmQDD/MU3Y7C3GQ2bCglrKQA+EwITAxMBwCzAMACfzKnMqMyqwCvALwCewCTAKABrwCPAJwBnwArAFAA5wAnAEwAzAJ0AnAA9ADwANQAvAP8BAAF1AAAADgAMAAAJbG9jYWxob3N0AAsABAMAAQIACgAWABQAHQAXAB4AGQAYAQABAQECAQMBBAAQAA4ADAJoMghodHRwLzEuMQAWAAAAFwAAADEAAAANADAALgQDBQMGAwgHCAgIGggbCBwICQgKCAsIBAgFCAYEAQUBBgEDAwMBAwIEAgUCBgIAKwAFBAMEAwMALQACAQEAMwAmACQAHQAgJVr45fQu/Scp1rR44ICssKYhbqJ/ebI+Mrqz5ezxrnAAFQCyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
      "ConnectionState": {
        "Version": 772,
        "HandshakeComplete": true,
        "DidResume": false,
        "CipherSuite": 4865,
        "NegotiatedProtocol": "h2",
        "NegotiatedProtocolIsMutual": true,
        "ServerName": "localhost",
        "PeerCertificates": null,
        "VerifiedChains": null,
        "SignedCertificateTimestamps": null,
        "OCSPResponse": null,
        "TLSUnique": null
      },
      "HTTP2Frames": {
        "Settings": [
          {
            "Id": 3,
            "Val": 100
          },
          {
            "Id": 4,
            "Val": 10485760
          },
          {
            "Id": 2,
            "Val": 0
          }
        ],
        "WindowUpdateIncrement": 1048510465,
        "Priorities": null,
        "Headers": [
          {
            "Name": ":method",
            "Value": "GET",
            "Sensitive": false
          },
          {
            "Name": ":scheme",
            "Value": "https",
            "Sensitive": false
          },
          {
            "Name": ":authority",
            "Value": "localhost:8443",
            "Sensitive": false
          },
          {
            "Name": ":path",
            "Value": "/json/detail",
            "Sensitive": false
          },
          {
            "Name": "user-agent",
            "Value": "curl/8.6.0",
            "Sensitive": false
          },
          {
            "Name": "accept",
            "Value": "*/*",
            "Sensitive": false
          }
        ]
      }
    },
    "user_agent": "curl/8.6.0",
    "ja3": {
      "Type": 22,
      "Version": 769,
      "MessageLen": 0,
      "HandshakeType": 1,
      "HandshakeLen": 0,
      "HandshakeVersion": 771,
      "SessionIDLen": 32,
      "CipherSuiteLen": 62,
      "CipherSuites": [
        4866,
        4867,
        4865,
        49196,
        49200,
        159,
        52393,
        52392,
        52394,
        49195,
        49199,
        158,
        49188,
        49192,
        107,
        49187,
        49191,
        103,
        49162,
        49172,
        57,
        49161,
        49171,
        51,
        157,
        156,
        61,
        60,
        53,
        47,
        255
      ],
      "ExtensionLen": 373,
      "SNI": "localhost",
      "SupportedGroups": [
        29,
        23,
        30,
        25,
        24,
        256,
        257,
        258,
        259,
        260
      ],
      "SupportedPoints": "AAEC",
      "AllExtensions": [
        0,
        11,
        10,
        16,
        22,
        23,
        49,
        13,
        43,
        45,
        51,
        21
      ],
      "ReadableCipherSuites": [
        "TLS_AES_256_GCM_SHA384 (0x1302)",
        "TLS_CHACHA20_POLY1305_SHA256 (0x1303)",
        "TLS_AES_128_GCM_SHA256 (0x1301)",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)",
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (0x9f)",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)",
        "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xccaa)",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)",
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (0x9e)",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 (0xc024)",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xc028)",
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (0x6b)",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (0xc023)",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xc027)",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 (0x67)",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)",
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x39)",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x33)",
        "TLS_RSA_WITH_AES_256_GCM_SHA384 (0x9d)",
        "TLS_RSA_WITH_AES_128_GCM_SHA256 (0x9c)",
        "TLS_RSA_WITH_AES_256_CBC_SHA256 (0x3d)",
        "TLS_RSA_WITH_AES_128_CBC_SHA256 (0x3c)",
        "TLS_RSA_WITH_AES_256_CBC_SHA (0x35)",
        "TLS_RSA_WITH_AES_128_CBC_SHA (0x2f)",
        "TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0xff)"
      ],
      "ReadableAllExtensions": [
        "server_name (0x0)",
        "ec_point_formats (0xb)",
        "supported_groups (0xa)",
        "application_layer_protocol_negotiation (0x10)",
        "encrypt_then_mac (0x16)",
        "extended_master_secret (0x17)",
        "post_handshake_auth (0x31)",
        "signature_algorithms (0xd)",
        "supported_versions (0x2b)",
        "psk_key_exchange_modes (0x2d)",
        "key_share (0x33)",
        "padding (0x15)"
      ],
      "ReadableSupportedGroups": [
        "x25519 (0x1d)",
        "secp256r1 (0x17)",
        "x448 (0x1e)",
        "secp521r1 (0x19)",
        "secp384r1 (0x18)",
        "ffdhe2048 (0x100)",
        "ffdhe3072 (0x101)",
        "ffdhe4096 (0x102)",
        "ffdhe6144 (0x103)",
        "ffdhe8192 (0x104)"
      ]
    },
    "ja3_raw": "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-16-22-23-49-13-43-45-51-21,29-23-30-25-24-256-257-258-259-260,0-1-2",
    "ja4": {
      "Protocol": 116,
      "TLSVersion": 772,
      "SNI": 100,
      "NumberOfCipherSuites": 31,
      "NumberOfExtensions": 12,
      "FirstALPN": "h2",
      "CipherSuites": [
        47,
        51,
        53,
        57,
        60,
        61,
        103,
        107,
        156,
        157,
        158,
        159,
        255,
        4865,
        4866,
        4867,
        49161,
        49162,
        49171,
        49172,
        49187,
        49188,
        49191,
        49192,
        49195,
        49196,
        49199,
        49200,
        52392,
        52393,
        52394
      ],
      "Extensions": [
        10,
        11,
        13,
        21,
        22,
        23,
        43,
        45,
        49,
        51
      ],
      "SignatureAlgorithms": [
        1027,
        1283,
        1539,
        2055,
        2056,
        2074,
        2075,
        2076,
        2057,
        2058,
        2059,
        2052,
        2053,
        2054,
        1025,
        1281,
        1537,
        771,
        769,
        770,
        1026,
        1282,
        1538
      ],
      "ReadableCipherSuites": [
        "TLS_RSA_WITH_AES_128_CBC_SHA (0x2f)",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x33)",
        "TLS_RSA_WITH_AES_256_CBC_SHA (0x35)",
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x39)",
        "TLS_RSA_WITH_AES_128_CBC_SHA256 (0x3c)",
        "TLS_RSA_WITH_AES_256_CBC_SHA256 (0x3d)",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 (0x67)",
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (0x6b)",
        "TLS_RSA_WITH_AES_128_GCM_SHA256 (0x9c)",
        "TLS_RSA_WITH_AES_256_GCM_SHA384 (0x9d)",
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (0x9e)",
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (0x9f)",
        "TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0xff)",
        "TLS_AES_128_GCM_SHA256 (0x1301)",
        "TLS_AES_256_GCM_SHA384 (0x1302)",
        "TLS_CHACHA20_POLY1305_SHA256 (0x1303)",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (0xc023)",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 (0xc024)",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xc027)",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xc028)",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)",
        "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xccaa)"
      ],
      "ReadableExtensions": [
        "supported_groups (0xa)",
        "ec_point_formats (0xb)",
        "signature_algorithms (0xd)",
        "padding (0x15)",
        "encrypt_then_mac (0x16)",
        "extended_master_secret (0x17)",
        "supported_versions (0x2b)",
        "psk_key_exchange_modes (0x2d)",
        "post_handshake_auth (0x31)",
        "key_share (0x33)"
      ],
      "ReadableSignatureAlgorithms": [
        "ecdsa (0x403)",
        "ecdsa (0x503)",
        "ecdsa (0x603)",
        "ed25519 (0x807)",
        "ed448 (0x808)",
        "unknown (0x81a)",
        "unknown (0x81b)",
        "unknown (0x81c)",
        "unknown (0x809)",
        "unknown (0x80a)",
        "unknown (0x80b)",
        "unknown (0x804)",
        "unknown (0x805)",
        "unknown (0x806)",
        "rsa (0x401)",
        "rsa (0x501)",
        "rsa (0x601)",
        "ecdsa (0x303)",
        "rsa (0x301)",
        "dsa (0x302)",
        "dsa (0x402)",
        "dsa (0x502)",
        "dsa (0x602)"
      ]
    }
  },
  "ja3": "0149f47eabf9a20d0893e2a44e5a6323",
  "ja4": "t13d3112h2_e8f1e7e78f70_6bebaf5329ac",
  "http2": "3:100;4:10485760;2:0|1048510465|0|m,s,a,p"
}
```
</details>
