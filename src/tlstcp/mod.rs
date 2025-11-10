use tokio::{
    io::{self, ReadHalf, WriteHalf},
    net::TcpStream,
};

pub mod client;
pub mod server;

pub use client::Connector;
pub use server::Acceptor;

pub type TlsStream = tokio_rustls::TlsStream<TcpStream>;
pub type TlsReadStream = ReadHalf<TlsStream>;
pub type TlsWriteStream = WriteHalf<TlsStream>;

pub fn split(stream: TlsStream) -> (TlsReadStream, TlsWriteStream) {
    io::split(stream)
}
