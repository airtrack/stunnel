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

	Cargo build

Usage
-----

	./server listenip:port key
	./client serverip:port key

Browser connect client(`127.0.0.1:1080`) through SOCKS5.