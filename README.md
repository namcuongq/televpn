# ﻿TeleVPN
A VPN implementation written in Go.

## How it works
| Your computer |<---------->TUN interface<--------->| websocket  |<----------->VPN server<----------->|  internet  |

## Features

- Hide Everything: Handle all your network traffic sent by the device through a vpn and encrypt them.
- VPN Protocols: HTTP/HTTPS.
- OS Support: Linux/macOS/Windows multi-platform support.
- IPv6 Support: All functions work in IPv6.
- Bypass firewalls: bypass firewalls if they allow http traffic
- Very Fast: use FastHTTP for high performance
- Network Stack: Powered by user-space TCP/IP stack from Google **[gVisor](https://github.com/google/gvisor)**.

## Quickstart
Download precompiled binary from [Releases](https://github.com/namcuongq/televpn/releases)

### Usage
#### On VPN server
Config example `config.toml`
```
Server         = "192.168.10.210:443"
Address        = "172.16.0.1"
MTU            = 1500
TTL            = 30
Users = [
        {Username = "user00", Password = "pass00", Ipaddress = "172.16.0.10"},
        {Username = "user01", Password = "pass01", Ipaddress = "172.16.0.9"},
]

# enable https
SSL            = true
SSLKey         = "server.key"
SSLCrt         = "server.crt"
```
Command
```
./televpn -S
```

#### On Client Machine 
Config example `config.toml`
```
Server         = "192.168.10.210:443"
Address        = "172.16.0.10"
DefaultGateway = "172.16.0.1"
MTU            = 1500
TTL            = 30
User           = "user00"
Pass           = "pass00"
HostHeader     = "fake.com"
DNSServer      = ["1.1.1.1"]
Whitelist 	   = ["10.10.0.1"]
Blacklist 	   = []
Public         = true # if set = true require SSL is enabled (SSL = true)

# enable https
SSL            = true
SSLCrt         = "server.crt"

# route specific additional networks through the VPN, set empty if you want to route all traffic through the VPN
RedirectGateway= ""
```
Command
```
./televpn
```

## Thanks

- [google/gvisor](https://github.com/google/gvisor)
- [wireguard-go](https://git.zx2c4.com/wireguard-go)
- [go-tun2socks](https://github.com/eycorsican/go-tun2socks)

## Donation

A GitHub star is always appreciated!
