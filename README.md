# shadowsocks-go

[![Go Reference](https://pkg.go.dev/badge/github.com/database64128/shadowsocks-go.svg)](https://pkg.go.dev/github.com/database64128/shadowsocks-go)
[![Test](https://github.com/database64128/shadowsocks-go/actions/workflows/test.yml/badge.svg)](https://github.com/database64128/shadowsocks-go/actions/workflows/test.yml)
[![Release](https://github.com/database64128/shadowsocks-go/actions/workflows/release.yml/badge.svg)](https://github.com/database64128/shadowsocks-go/actions/workflows/release.yml)
[![AUR version](https://img.shields.io/aur/version/shadowsocks-go?label=shadowsocks-go)](https://aur.archlinux.org/packages/shadowsocks-go)
[![AUR version](https://img.shields.io/aur/version/shadowsocks-go-git?label=shadowsocks-go-git)](https://aur.archlinux.org/packages/shadowsocks-go-git)

A versatile and efficient proxy platform for secure communications.

## Features

- Reference Go implementation of Shadowsocks 2022 and later editions.
- Client and server implementation of SOCKS5, HTTP proxy, and Shadowsocks "none" method.
- Built-in router and DNS with support for extensible routing rules.
- TCP relay fast path on Linux with `splice(2)`.
- UDP relay fast path on Linux with `recvmmsg(2)` and `sendmmsg(2)`.

## Configuration Examples

### 1. Shadowsocks 2022 Server

The `clients` field can be left empty. A default "direct" client will be automatically added.

The `dns` field is required if you want IP routes to work on domain targets.

To allow access to private IP prefixes, omit the `dns` and `router` fields.

```jsonc
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
            "uPSKs": [
                "oE/s2z9Q8EWORAB8B3UCxw=="
            ]
        }
    ],
    "dns": [
        {
            "name": "systemd-resolved",
            "addrPort": "127.0.0.53:53",
            "tcpClientName": "direct",
            "udpClientName": "direct"
        }
    ],
    "router": {
        "routes": [
            {
                "name": "private",
                "clientName": "reject",
                "prefixes": [
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
                    "224.0.0.0/4",
                    "240.0.0.0/4",
                    "255.255.255.255/32",
                    "::1/128",
                    "fc00::/7",
                    "fe80::/10"
                ]
            }
        ]
    },
    "udpBatchMode": "",
    "udpPreferIPv6": true
}
```

### 2. Shadowsocks 2022 Client

By default, the router uses the configured DNS server to resolve domain names and match IP rules. The resolved IP addresses are only used for matching IP rules. Requests are made using the original domain name. To disable IP rule matching for domain names, set `disableNameResolutionForIPRules` to true.

```jsonc
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
            "endpoint": "[2001:db8:bd63:362c:2071:a0f6:827:ab6a]:20220",
            "protocol": "2022-blake3-aes-128-gcm",
            "enableTCP": true,
            "dialerTFO": true,
            "enableUDP": true,
            "mtu": 1500,
            "psk": "qQln3GlVCZi5iJUObJVNCw==",
            "iPSKs": [
                "oE/s2z9Q8EWORAB8B3UCxw=="
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
        }
    ],
    "router": {
        "defaultTCPClientName": "ss-2022",
        "defaultUDPClientName": "ss-2022",
        "geoLite2CountryDbPath": "Country.mmdb",
        "domainSets": [
            {
                "name": "category-ads-all",
                "path": "ss-go-category-ads-all.txt"
            },
            {
                "name": "private",
                "path": "ss-go-private.txt"
            },
            {
                "name": "cn",
                "path": "ss-go-cn.txt"
            },
            {
                "name": "geolocation-!cn@cn",
                "path": "ss-go-geolocation-!cn@cn.txt"
            }
        ],
        "routes": [
            {
                "name": "ads",
                "clientName": "reject",
                "domainSets": [
                    "category-ads-all"
                ]
            },
            {
                "name": "direct",
                "clientName": "direct",
                "domainSets": [
                    "private",
                    "cn",
                    "geolocation-!cn@cn"
                ],
                "prefixes": [
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
                    "224.0.0.0/4",
                    "240.0.0.0/4",
                    "255.255.255.255/32",
                    "::1/128",
                    "fc00::/7",
                    "fe80::/10"
                ],
                "geoIPCountries": [
                    "CN"
                ]
            }
        ]
    },
    "udpBatchMode": "",
    "udpPreferIPv6": true
}
```

### 3. Feature Showcase

```jsonc
{
    "servers": [
        {
            "name": "socks5",
            "listen": ":1080",
            "protocol": "socks5",
            "listenerFwmark": 52140,
            "enableTCP": true,
            "listenerTFO": true,
            "enableUDP": true,
            "mtu": 1500
        },
        {
            "name": "http",
            "listen": ":8080",
            "protocol": "http",
            "listenerFwmark": 52140,
            "enableTCP": true,
            "listenerTFO": true
        },
        {
            "name": "tunnel",
            "listen": ":53",
            "protocol": "direct",
            "listenerFwmark": 52140,
            "enableTCP": true,
            "listenerTFO": true,
            "enableUDP": true,
            "mtu": 1500,
            "tunnelRemoteAddress": "[2606:4700:4700::1111]:53"
        },
        {
            "name": "ss-2022",
            "listen": ":20220",
            "protocol": "2022-blake3-aes-128-gcm",
            "listenerFwmark": 52140,
            "enableTCP": true,
            "listenerTFO": true,
            "enableUDP": true,
            "mtu": 1500,
            "psk": "qQln3GlVCZi5iJUObJVNCw==",
            "uPSKs": [
                "oE/s2z9Q8EWORAB8B3UCxw=="
            ],
            "paddingPolicy": "",
            "rejectPolicy": ""
        }
    ],
    "clients": [
        {
            "name": "ss-2022-a",
            "endpoint": "[2001:db8:bd63:362c:2071:a0f6:827:ab6a]:20220",
            "protocol": "2022-blake3-aes-128-gcm",
            "dialerFwmark": 52140,
            "enableTCP": true,
            "dialerTFO": true,
            "enableUDP": true,
            "mtu": 1500,
            "psk": "qQln3GlVCZi5iJUObJVNCw==",
            "iPSKs": [
                "oE/s2z9Q8EWORAB8B3UCxw=="
            ],
            "paddingPolicy": ""
        },
        {
            "name": "ss-2022-b",
            "endpoint": "[2001:db8:a2bf:f3ef:903a:4fd1:f986:5934]:20220",
            "protocol": "2022-blake3-aes-128-gcm",
            "dialerFwmark": 52140,
            "enableTCP": true,
            "dialerTFO": true,
            "enableUDP": true,
            "mtu": 1500,
            "psk": "QzhDwx0lKZ+0Sustgwtjtw==",
            "iPSKs": [
                "McxLxNcqHUb01ZedJfp55g=="
            ],
            "paddingPolicy": ""
        },
        {
            "name": "direct",
            "protocol": "direct",
            "dialerFwmark": 52140,
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
            "tcpClientName": "ss-2022-a",
            "udpClientName": "ss-2022-a"
        }
    ],
    "router": {
        "disableNameResolutionForIPRules": false,
        "defaultTCPClientName": "ss-2022-a",
        "defaultUDPClientName": "ss-2022-a",
        "geoLite2CountryDbPath": "Country.mmdb",
        "domainSets": [
            {
                "name": "example",
                "path": "ss-go-example.txt"
            }
        ],
        "routes": [
            {
                "name": "example",
                "network": "udp",
                "clientName": "ss-2022-b",
                "resolverName": "cf-v6",
                "serverNames": [
                    "socks5",
                    "tunnel"
                ],
                "domains": [
                    "example.com"
                ],
                "domainSets": [
                    "example"
                ],
                "prefixes": [
                    "::/0"
                ],
                "sourcePrefixes": [
                    "127.0.0.1/32",
                    "::1/128"
                ],
                "ports": [
                    "443"
                ],
                "sourcePorts": [
                    12345,
                    54321
                ],
                "geoIPCountries": [
                    "US"
                ],
                "invertDomains": false,
                "invertPrefixes": false,
                "invertPorts": false,
                "invertSourcePrefixes": false,
                "invertSourcePorts": false,
                "invertGeoIPCountries": false
            }
        ]
    },
    "udpBatchMode": "",
    "udpPreferIPv6": true
}
```

## License

[AGPLv3](LICENSE)
