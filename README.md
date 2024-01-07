STunnel
=======

Simple SOCKS5/HTTP tunnel. SOCKS5 on client side provides NO AUTHENTICATION TCP/UDP proxy.

	            .                      |                     .
	            .                      f                     .
	            .                      i                     .
	port1 ------|                      r                     |------ port1
	            |                      e                     |
	            |                      |                     |
	port2 ---client---------------- tunnel ----------------server--- port2
	            |                      |                     |
	            |                      w                     |
	port3 ------|                      a                     |------ port3
	            .                      l                     .
	            .                      l                     .
	            .                      |                     .

Build
-----

Build by [Cargo](https://crates.io/):

	Cargo build --release

Usage
-----

	./stunnel_server <OPTIONS>
	Options:
	    -l, --listen <IP:PORT>
	    -k, --key <STRING>
	        --log <PATH>
	        --ucp-metrics-path <PATH>

	./stunnel_client <OPTIONS>
	Options:
	    -s, --server <IP:PORT>
	    -k, --key <STRING>
	        --enable-ucp
	        --socks5-proxy <IP:PORT>
	        --http-proxy <IP:PORT>
	        --log <PATH>
	        --ucp-metrics-path <PATH>
	        --tcp-tunnel-count <NUMBER>

Browser connect client address(`127.0.0.1:1080`) through SOCKS5 or connect client address(`127.0.0.1:8888`) through HTTP.

`--enable-ucp` option on client side to enable UCP tunnel instead of TCP tunnel, UCP tunnel is much faster than TCP tunnel in some cases.

UCP
---

UCP is an ARQ protocol implementation, which is based on UDP and inspired by [KCP](https://github.com/skywind3000/kcp).

Work with autoproxy and gatewaysocks
----------------------------------

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
