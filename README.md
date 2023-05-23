# shadowsocks-go

[![Go Reference](https://pkg.go.dev/badge/github.com/database64128/shadowsocks-go.svg)](https://pkg.go.dev/github.com/database64128/shadowsocks-go)
[![Test](https://github.com/database64128/shadowsocks-go/actions/workflows/test.yml/badge.svg)](https://github.com/database64128/shadowsocks-go/actions/workflows/test.yml)
[![Release](https://github.com/database64128/shadowsocks-go/actions/workflows/release.yml/badge.svg)](https://github.com/database64128/shadowsocks-go/actions/workflows/release.yml)
[![shadowsocks-go AUR package](https://img.shields.io/aur/version/shadowsocks-go?label=shadowsocks-go)](https://aur.archlinux.org/packages/shadowsocks-go)
[![shadowsocks-go-git AUR package](https://img.shields.io/aur/version/shadowsocks-go-git?label=shadowsocks-go-git)](https://aur.archlinux.org/packages/shadowsocks-go-git)
[![shadowsocks-go-domain-sets-git AUR package](https://img.shields.io/aur/version/shadowsocks-go-domain-sets-git?label=shadowsocks-go-domain-sets-git)](https://aur.archlinux.org/packages/shadowsocks-go-domain-sets-git)
[![shadowsocks-go-geolite2-country-git AUR package](https://img.shields.io/aur/version/shadowsocks-go-geolite2-country-git?label=shadowsocks-go-geolite2-country-git)](https://aur.archlinux.org/packages/shadowsocks-go-geolite2-country-git)

A versatile and efficient proxy platform for secure communications.

## Features

- Reference Go implementation of Shadowsocks 2022 and later editions.
- Client and server implementation of SOCKS5, HTTP proxy, and Shadowsocks "none" method.
- Transparent proxy support for Linux.
- Built-in router and DNS resolver with support for extensible routing rules.
- RESTful API for server user management and traffic statistics.
- TCP relay fast path on Linux with `splice(2)`.
- UDP relay fast path on Linux with `recvmmsg(2)` and `sendmmsg(2)`.

## Configuration Examples

All configuration examples and systemd unit files can be found in the [docs](docs) directory.

### 1. Shadowsocks 2022 Server

The `clients` field can be omitted or left empty. A default "direct" client will be automatically added.

On production servers, you may want to set `udpRelayBatchSize` to a lower value like 8 to reduce memory usage while still benefiting from `recvmmsg(2)` and `sendmmsg(2)`.

UDP packets may be padded to up to the maximum packet size calculated from `mtu`. If the server may be used from a PPPoE connection, `mtu` should be reduced to 1492. If the client-to-server PMTU is unknown, padding can be completely disabled by setting `paddingPolicy` to `NoPadding`.

For servers without any user PSKs (single-user mode), the `psk` field specifies the PSK, and the `uPSKStorePath` field can be omitted or left empty. When one or more user PSKs are specified in the uPSK store file, the `psk` field specifies the identity PSK.

To add/update/remove users without restarting the server, modify the uPSK store file and send a `SIGUSR1` signal to the server process, or use the RESTful API. Updates from the RESTful API will be saved to the uPSK store file automatically.

```json
{
    "servers": [
        {
            "name": "ss-2022",
            "listen": ":20220",
            "protocol": "2022-blake3-aes-128-gcm",
            "enableTCP": true,
            "listenerTFO": true,
            "enableUDP": true,
            "mtu": 1500,
            "psk": "qQln3GlVCZi5iJUObJVNCw==",
            "uPSKStorePath": "/etc/shadowsocks-go/upsks.json"
        }
    ]
}
```

```json
{
    "Steve": "oE/s2z9Q8EWORAB8B3UCxw==",
    "Alex": "hWXLOSW/r/LtNKynrA3S8Q=="
}
```

### 2. Shadowsocks 2022 Client

By default, the router uses the configured DNS server to resolve domain names and match IP rules. The resolved IP addresses are only used for matching IP rules. Requests are made using the original domain name. To disable IP rule matching for domain names, set `disableNameResolutionForIPRules` to true.

```json
{
    "servers": [
        {
            "name": "socks5",
            "listen": ":1080",
            "protocol": "socks5",
            "enableTCP": true,
            "listenerTFO": true,
            "enableUDP": true,
            "mtu": 1500
        },
        {
            "name": "http",
            "listen": ":8080",
            "protocol": "http",
            "enableTCP": true,
            "listenerTFO": true
        }
    ],
    "clients": [
        {
            "name": "ss-2022",
            "protocol": "2022-blake3-aes-128-gcm",
            "endpoint": "[2001:db8:bd63:362c:2071:a0f6:827:ab6a]:20220",
            "enableTCP": true,
            "dialerTFO": true,
            "enableUDP": true,
            "mtu": 1500,
            "psk": "oE/s2z9Q8EWORAB8B3UCxw==",
            "iPSKs": [
                "qQln3GlVCZi5iJUObJVNCw=="
            ]
        },
        {
            "name": "direct",
            "protocol": "direct",
            "enableTCP": true,
            "dialerTFO": true,
            "enableUDP": true,
            "mtu": 1500
        }
    ],
    "dns": [
        {
            "name": "cf-v6",
            "addrPort": "[2606:4700:4700::1111]:53",
            "tcpClientName": "ss-2022",
            "udpClientName": "ss-2022"
        },
        {
            "name": "systemd-resolved",
            "addrPort": "127.0.0.53:53",
            "tcpClientName": "direct",
            "udpClientName": "direct"
        }
    ],
    "router": {
        "defaultTCPClientName": "ss-2022",
        "defaultUDPClientName": "ss-2022",
        "geoLite2CountryDbPath": "/usr/share/shadowsocks-go/Country.mmdb",
        "domainSets": [
            {
                "name": "category-ads-all",
                "type": "gob",
                "path": "/usr/share/shadowsocks-go/ss-go-gob-category-ads-all"
            },
            {
                "name": "private",
                "type": "gob",
                "path": "/usr/share/shadowsocks-go/ss-go-gob-private"
            },
            {
                "name": "cn",
                "type": "gob",
                "path": "/usr/share/shadowsocks-go/ss-go-gob-cn"
            },
            {
                "name": "geolocation-!cn@cn",
                "type": "gob",
                "path": "/usr/share/shadowsocks-go/ss-go-gob-geolocation-!cn@cn"
            }
        ],
        "routes": [
            {
                "name": "ads",
                "client": "reject",
                "toDomainSets": [
                    "category-ads-all"
                ]
            },
            {
                "name": "direct",
                "client": "direct",
                "resolver": "cf-v6",
                "toDomainSets": [
                    "private",
                    "cn"
                ],
                "toPrefixes": [
                    "0.0.0.0/8",
                    "10.0.0.0/8",
                    "100.64.0.0/10",
                    "127.0.0.0/8",
                    "169.254.0.0/16",
                    "172.16.0.0/12",
                    "192.0.0.0/24",
                    "192.0.2.0/24",
                    "192.88.99.0/24",
                    "192.168.0.0/16",
                    "198.18.0.0/15",
                    "198.51.100.0/24",
                    "203.0.113.0/24",
                    "224.0.0.0/3",
                    "::1/128",
                    "fc00::/7",
                    "fe80::/10"
                ],
                "toGeoIPCountries": [
                    "CN"
                ]
            },
            {
                "name": "cn-verify-ip",
                "client": "direct",
                "resolver": "systemd-resolved",
                "toDomainSets": [
                    "geolocation-!cn@cn"
                ],
                "toMatchedDomainExpectedGeoIPCountries": [
                    "CN"
                ]
            }
        ]
    }
}
```

### 3. Feature Showcase

See [docs/config.json](docs/config.json).

## Domain Sets and IP Geolocation Database

shadowsocks-go has its own domain set file format, because other formats I've seen are all horrible!

And don't worry, we have a simple conversion tool to convert between different formats: [shadowsocks-go-domain-set-converter](cmd/shadowsocks-go-domain-set-converter/main.go)

A domain set text file optionally starts with a capacity hint comment. The conversion tool can automatically generate a capacity hint for you. There are 4 types of domain matching rules:

- `domain:` Match the domain.
- `suffix:` Match the domain and its subdomains.
- `keyword:` Match if the domain contains the keyword.
- `regexp:` Match if the domain matches the regular expression.

Example of a domain set text file:

```
# shadowsocks-go domain set capacity hint 1 6 1 1 DSKR
domain:www.example.net
suffix:example.com
suffix:github.com
suffix:cube64128.xyz
suffix:api.ipify.org
suffix:api6.ipify.org
suffix:archlinux.org
keyword:dev
regexp:^adservice\.google\.([a-z]{2}|com?)(\.[a-z]{2})?$
```

When loading a domain set text file, shadowsocks-go loads all suffixes as-is into a single map. This achieves the best balance between startup speed, memory usage and match speed. If you want better performance, you can use the conversion tool to convert the text file to the gob format.

The gob format is basically the same thing, but has everything binary serialized and uses a trie to store and match suffixes. The conversion tool loads the suffixes to build a suffix trie, and then serializes the trie and the other rules to a gob file. Quite neat, isn't it?

Of course, I'm not an algorithm guru, so the whole process still has a lot of inefficiencies. But it's good enough for me. If you have brilliant new ideas, please let me know!

### Commonly Used Domain Sets

A set of commonly used domain sets are updated weekly at [shadowsocks-go-domain-sets](https://github.com/database64128/shadowsocks-go-domain-sets) in the release branch. Arch Linux users can install the [shadowsocks-go-domain-sets-git](https://aur.archlinux.org/packages/shadowsocks-go-domain-sets-git/) package from the AUR.

### Manually Generate Domain Sets

To generate domain sets using https://github.com/v2fly/domain-list-community as the source, clone the repository and build the generator, then generate plaintext lists:

```bash
./domain-list-community -exportlists 'google,netflix'
```

Use `shadowsocks-go-domain-set-converter` to convert the plaintext lists to domain set files:

```bash
shadowsocks-go-domain-set-converter -inDlc google.txt -outGob ss-go-gob-google
shadowsocks-go-domain-set-converter -inDlc netflix.txt -outGob ss-go-gob-netflix
```

### IP Geolocation Database

shadowsocks-go uses the MaxMind GeoLite2 Country database for IP geolocation. The database can be downloaded from https://github.com/Dreamacro/maxmind-geoip. Arch Linux users can install the [shadowsocks-go-geolite2-country-git](https://aur.archlinux.org/packages/shadowsocks-go-geolite2-country-git/) package from the AUR.

## Security

### 1. Packet Padding Policy

Packet padding policies are implemented for the Shadowsocks 2022 protocol. A packet padding policy controls whether to add padding to outgoing packets.

When adding padding, the MTU is taken into account, so the size of the padded packet won't exceed the MTU. Therefore it is important to set the MTU correctly.

The padding policy can be configured individually for each Shadowsocks 2022 client and server.

- `PadPlainDNS`: Add padding if the destination port is 53. (Default)
- `PadAll`: Pad all packets.
- `NoPadding`: No padding.

### 2. TCP Reject Policy

Reject policies are implemented for all TCP servers. A TCP server's reject policy is invoked when an accepted connection fails the protocol's handshake process. Each protocol has its own default reject policy. Custom reject policies can be useful for censorship circumvention servers to evade active probing.

- `JustClose`: Just close the connection. (Default for cleartext protocols)
- `ForceReset`: Forcibly reset the connection. Many protocols behave this way when invalid data is received. (Default for Shadowsocks 2022)
- `CloseWriteDrain`: Send FIN and keep reading until EOF. This is typically how legacy Shadowsocks servers handle replay.
- `ReplyWithGibberish`: Keep reading and send random garbage after each read returns. This emulates how a legacy Shadowsocks server without replay protection behaves, except it doesn't actually relay the replayed payload.

### 3. Unsafe Fallback

A Shadowsocks 2022 server can be configured to forward TCP connections to a fallback address when the handshake fails. Add the `unsafeFallbackAddress` field to the server block to specify the fallback address. On startup a warning message will be printed to tell you that using this feature "taints" the server. Unsafe fallback only works for TCP connections.

This feature might be useful when your threat model only includes off-path attackers, and you want to reuse the port or trick probes into thinking the server is something else. An on-path attacker (e.g. a typical censor) can easily tell that the regular traffic does not match the fallback traffic.

### 4. Unsafe Stream Prefix

The unsafe stream prefix feature allows you to configure a pair of pre-shared cleartext prefixes for Shadowsocks 2022 streams. The prefixes are prepended to the request and response streams to trick simple firewalls.

To use this feature, add `unsafeRequestStreamPrefix` and `unsafeResponseStreamPrefix` to both client and server blocks, and specify the prefixes in base64 encoding. The client and server must agree on the same pair of prefixes. On startup a warning message will be printed to tell you that using this feature "taints" the client and server.

## License

[AGPLv3](LICENSE)
