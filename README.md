# STunnel

Simple SOCKS5/HTTP tunnel. SOCKS5 on client side provides NO AUTHENTICATION TCP/UDP proxy. Version 2.0 based on QUIC and TLS-TCP.

```
                .                      |                     .
                .                      f                     .
                .                      i                     .
      HTTP -----|                      r                     |------ outbound1
                |                      e                     |
                |                      |                     |
             client---------------- tunnel ----------------server--- outbound2
                |                      |                     |
                |                      w                     |
    SOCKS5 -----|                      a                     |------ outbound3
                .                      l                     .
                .                      l                     .
                .                      |                     .
```

## Version 2.0 status

### Proxy type

- [x] HTTP proxy
- [x] SOCKS5 TCP proxy
- [x] SOCKS5 UDP proxy

### Tunnel type

- [x] QUIC
- [x] TLS-TCP(based on TLS on TCP)

## Usage

1. `./certgen` generates cert and private key
2. modify `config/client.toml` and `config/server.toml`
3. start server(`./stunnel_server --config config/server.toml`) and client(`./stunnel_client --config config/client.toml`) with the same cert

Browser connect client address(`127.0.0.1:1080`) via SOCKS5 or connect client address(`127.0.0.1:8080`) via HTTP.

## Reverse proxy(`quic`/`s2n-quic`)

The client can register reverse TCP listeners on the server: the server listens
on the configured address, and every connection is forwarded through the tunnel
back to the client, which connects to the local `target`.

```toml
# client.toml
reverse_proxy = [
    { listen = "0.0.0.0:8081", target = "127.0.0.1:3000" },
    { listen = "0.0.0.0:8082", target = "127.0.0.1:22" },
]
```

Multiple entries are supported. The client registers the listeners on the
server when the tunnel connects and re-registers after reconnects. The server
opens streams on the same QUIC connection.

## Work with autoproxy and gatewaysocks

* [autoproxy](https://github.com/airtrack/autoproxy)
* [gatewaysocks](https://github.com/airtrack/gatewaysocks)

```
    ----------------                 -------------                        -------------
    |              |                 |           |                        |           |
    | gatewaysocks | --- TCP/UDP --> | autoproxy | ------- TCP/UDP -----> |  stunnel  |
    |              |                 |           |    |                   |           |
    ----------------                 -------------    |                   -------------
           ^                               ^          |
           |                               |          |                   -------------
           |                               |          |                   |           |
           |                               |          |--- TCP/UDP -----> |  direct   |
           |                               |                              |           |
           |                               |                              -------------
    -----------------             ------------------
    |    devices    |             |   set system   |
    |  in the same  |             | proxy settings |
    |    router     |             |  to autoproxy  |
    -----------------             ------------------
```
