# STunnel

Simple SOCKS5/HTTP tunnel. SOCKS5 on client side provides NO AUTHENTICATION TCP/UDP proxy. Version 2.0 based on QUIC.

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
3. start server(`./stunnel_server config/server.toml`) and client(`./stunnel_client config/client.toml`) with the same cert

Browser connect client address(`127.0.0.1:1080`) through SOCKS5 or connect client address(`127.0.0.1:8080`) through HTTP.

## Work with autoproxy and gatewaysocks

* [autoproxy](https://github.com/airtrack/autoproxy)
* [gatewaysocks](https://github.com/airtrack/gatewaysocks)

```
    ----------------                 -------------                     -----------
    | gatewaysocks | === TCP/UDP ==> | autoproxy | ===== TCP/UDP ====> | stunnel |
    ----------------                 -------------   |                 -----------
           ^                               ^         |                 -----------
           |                               |         |== TCP/UDP ====> | direct  |
           |                               |                           -----------
    -----------------             ------------------
    | other devices |             |   set system   |
    |  in the same  |             | proxy settings |
    |    router     |             |  to autoproxy  |
    -----------------             ------------------
```
