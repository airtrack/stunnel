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

	./stunnel_server -l listen-address -k key [--log log-path] [--ucp-metrics-path path]
	./stunnel_client -s server-address -k key [-c tcp-tunnel-count] [--socks5-proxy socks5-proxy-address] [--http-proxy http-proxy-address] [--log log-path] [--ucp-metrics-path path] [--enable-ucp]

Browser connect client address(`127.0.0.1:1080`) through SOCKS5 or connect client address(`127.0.0.1:8888`) through HTTP.

`--enable-ucp` option on client side to enable UCP tunnel instead of TCP tunnel, UCP tunnel is much faster than TCP tunnel in most cases.

UCP
---

UCP is an ARQ protocol implementation, which is based on UDP and inspired by [KCP](https://github.com/skywind3000/kcp).
