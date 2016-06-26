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

Requires nightly build compiler, because it depends on several unstable functions, e.g. `lookup_host`.

Build by [Cargo](https://crates.io/):

	Cargo build --release

Usage
-----

	./server listenip:port key
	./client serverip:port key tunnel-count

Browser connect client(`127.0.0.1:1080`) through SOCKS5.

See also
--------

C++ version of [stunnel](https://github.com/airtrack/snet/tree/master/test/stunnel).
