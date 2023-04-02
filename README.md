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

	./stunnel_server
	Options:
	    -l, --listen ip:port
	    -k, --key key string
	        --log log path
	        --ucp-metrics-path metrics path

	./stunnel_client
	Options:
	    -s, --server ip:port
	    -k, --key key string
	        --enable-ucp
	        --socks5-proxy ip:port
	        --http-proxy ip:port
	        --log log path
	        --ucp-metrics-path metrics path
	        --tcp-tunnel-count number of tunnels

Browser connect client address(`127.0.0.1:1080`) through SOCKS5 or connect client address(`127.0.0.1:8888`) through HTTP.

`--enable-ucp` option on client side to enable UCP tunnel instead of TCP tunnel, UCP tunnel is much faster than TCP tunnel in most cases.

UCP
---

UCP is an ARQ protocol implementation, which is based on UDP and inspired by [KCP](https://github.com/skywind3000/kcp).
