# TeleVPN
A VPN implementation written in Go.

## How it works
| Your computer |<---------->TUN interface<--------->| (websocket|tls)  |<----------->VPN server<----------->|  internet  |

## Features

- Hide Everything: Handle all your network traffic sent by the device through a vpn and encrypt them.
- VPN Protocols: TCP TLS, HTTPS.
- OS Support: Linux/macOS/Windows multi-platform support.
- IPv6 Support: All functions work in IPv6.
- Bypass firewalls: bypass firewalls if they allow https traffic
- Very Fast: use FastHTTP in websocket(10x faster than net/http) and raw tcp tls for high performance
- Network Stack: Powered by user-space TCP/IP stack from Google **[gVisor](https://github.com/google/gvisor)**.

## Quickstart
Download precompiled binary from [Releases](https://github.com/namcuongq/televpn/releases)

### Make certs

Create file `google.com.ext` with content:
```
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = google.com
```

And run
```
openssl genrsa -des3 -out myCA.key 2048
openssl req -x509 -new -nodes -key myCA.key -sha256 -days 1825 -out myCA.pem

openssl genrsa -out google.com.key 2048
openssl req -new -key google.com.key -out google.com.csr
openssl x509 -req -in google.com.csr -CA myCA.pem -CAkey myCA.key -CAcreateserial -out google.com.crt -days 825 -sha256 -extfile google.com.ext
```

### Usage

```
Usage of televpn.exe:
  -S    server mode
  -config string
        location of the config file (default "config.toml")
  -l int
        log level: [1-DEBUG 2-INFO 3-ERROR] (default 2)
```

#### On VPN server
Config example `config.toml`
```
Server         = "192.168.10.210:443"
Address        = "172.16.0.1"
MTU            = 1500
TTL            = 30
Mode           = "ws" # support "tcp" - "ws"
Users = [
        {Username = "user00", Password = "pass00", Ipaddress = "172.16.0.10"},
        {Username = "user01", Password = "pass01", Ipaddress = "172.16.0.9"},
]

# ssl
SSLKey         = "google.com.key"
SSLCrt         = "google.com.crt"

# auto on off vpn server  
Auto           = "08:00-18:00" # Ex: 08:00-18:00 => stat at 08:00 and stop at 18:00
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
HostHeader     = "google.com"
DNSServer      = ["1.1.1.1"]
Whitelist      = ["10.10.0.1"]
Public         = true # if set = true require SSL is enabled (SSL = true)
Mode           = "ws" # support "tcp" - "ws"

# ssl
SSLCrt         = "myCA.pem"

# route specific additional networks through the VPN, set empty if you want to route all traffic through the VPN
RedirectGateway= ""
```
Command
```
./televpn
```

## TODO

* [ ] icmp

## Thanks

- [google/gvisor](https://github.com/google/gvisor)
- [wireguard-go](https://git.zx2c4.com/wireguard-go)
- [go-tun2socks](https://github.com/dosgo/go-tun2socks)

## Donation

A GitHub star is always appreciated!
