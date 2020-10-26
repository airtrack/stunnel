STunnel
=======

Simple SOCKS5 tunnel. Client only provide NO AUTHENTICATION TCP method.

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

	./stunnel_server -l listen-address -k key [--log log-path]
	./stunnel_client -s server-address -k key [-c tunnel-count] [-l listen-address] [--log log-path] [--enable-ucp]

Browser connect client listen address(`127.0.0.1:1080`) through SOCKS5.

UCP
---

UCP is an ARQ protocol implementation, which is base on UDP and inspired by [KCP](https://github.com/skywind3000/kcp).
