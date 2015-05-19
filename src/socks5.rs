use std::net::{Ipv4Addr, SocketAddrV4, SocketAddr};
use std::io::Error;
use super::tcp::Tcp;

const VER: u8 = 5;
const METHOD_NO_AUTH: u8 = 0;
const METHOD_NO_ACCEPT: u8 = 0xFF;

const CMD_CONNECT: u8 = 1;
const RSV: u8 = 0;
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAINNAME: u8 = 3;
const ATYP_IPV6: u8 = 4;

const REP_SUCCESS: u8 = 0;
const REP_FAILURE: u8 = 1;

pub enum ConnectDest {
    Addr(SocketAddr),
    DomainName(Vec<u8>, u16),
    Unknown,
}

fn select_method(stream: &mut Tcp) -> u8 {
    match stream.read_u8() {
        Ok(VER) => {},
        _ => return METHOD_NO_ACCEPT
    }

    let method_num = match stream.read_u8() {
        Ok(method_num) => method_num,
        Err(_) => return METHOD_NO_ACCEPT
    };

    if method_num == 1 {
        match stream.read_u8() {
            Ok(METHOD_NO_AUTH) => {},
            _ => return METHOD_NO_ACCEPT
        }
    } else {
        let methods = match stream.read_exact(method_num as usize) {
            Ok(methods) => methods,
            Err(_) => return METHOD_NO_ACCEPT
        };

        if !methods.into_iter().any(|method| method == METHOD_NO_AUTH) {
            return METHOD_NO_ACCEPT
        }
    }

    METHOD_NO_AUTH
}

fn reply_method(stream: &mut Tcp, method: u8) -> bool {
    let reply = [VER, method];
    match stream.write(&reply) {
        Ok(_) => true,
        Err(_) => false
    }
}

pub fn get_connect_dest(stream: &mut Tcp) -> ConnectDest {
    let method = select_method(stream);
    if !reply_method(stream, method) {
        return ConnectDest::Unknown
    }

    if method != METHOD_NO_AUTH {
        return ConnectDest::Unknown
    }

    let buf = match stream.read_exact(4) {
        Ok(buf) => buf,
        Err(_) => return ConnectDest::Unknown
    };

    if buf[1] != CMD_CONNECT {
        return ConnectDest::Unknown
    }

    match buf[3] {
        ATYP_IPV4 => {
            let ipv4 = match stream.read_exact(4) {
                Ok(ipv4) => ipv4,
                Err(_) => return ConnectDest::Unknown
            };

            let port = match stream.read_u16() {
                Ok(port) => port,
                Err(_) => return ConnectDest::Unknown
            };

            ConnectDest::Addr(
                SocketAddr::V4(
                    SocketAddrV4::new(
                        Ipv4Addr::new(ipv4[3], ipv4[2], ipv4[1], ipv4[0]),
                        port)))
        },

        ATYP_IPV6 => {
            ConnectDest::Unknown
        },

        ATYP_DOMAINNAME => {
            let len = match stream.read_u8() {
                Ok(len) => len,
                Err(_) => return ConnectDest::Unknown
            };

            let domain_name = match stream.read_exact(len as usize) {
                Ok(domain_name) => domain_name,
                Err(_) => return ConnectDest::Unknown
            };

            let port = match stream.read_u16() {
                Ok(port) => port,
                Err(_) => return ConnectDest::Unknown
            };

            ConnectDest::DomainName(domain_name, port)
        },

        _ => ConnectDest::Unknown
    }
}

pub fn reply_connect_success(stream: &mut Tcp,
                             addr: SocketAddr) -> Result<(), Error> {
    reply_result(stream, addr, REP_SUCCESS)
}

pub fn reply_failure(stream: &mut Tcp) -> Result<(), Error> {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));
    reply_result(stream, addr, REP_FAILURE)
}

fn reply_result(stream: &mut Tcp,
                addr: SocketAddr, rep: u8) -> Result<(), Error> {
    let buf = [VER, rep, RSV];
    try!(stream.write(&buf));

    match addr {
        SocketAddr::V4(ipv4) => {
            let bytes = ipv4.ip().octets();
            let buf = [ATYP_IPV4, bytes[3], bytes[2], bytes[1], bytes[0]];
            try!(stream.write(&buf));
            try!(stream.write_u16(ipv4.port()));
        },
        SocketAddr::V6(ipv6) => {
            let segments = ipv6.ip().segments();
            try!(stream.write_u8(ATYP_IPV6));

            let mut n = segments.len();
            while n >= 1 {
                n -= 1;
                try!(stream.write_u16(segments[n]));
            }

            try!(stream.write_u16(ipv6.port()));
        }
    }

    Ok(())
}
