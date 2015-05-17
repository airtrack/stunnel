use super::tcp::Tcp;
use std::net::{Ipv4Addr, SocketAddrV4, SocketAddr};

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
        Some(VER) => {},
        _ => return METHOD_NO_ACCEPT
    }

    let method_num = match stream.read_u8() {
        Some(method_num) => method_num,
        None => return METHOD_NO_ACCEPT
    };

    if method_num == 1 {
        match stream.read_u8() {
            Some(METHOD_NO_AUTH) => {},
            _ => return METHOD_NO_ACCEPT
        }
    } else {
        let methods = stream.read_exact(method_num as usize);
        if !methods.into_iter().any(|method| method == METHOD_NO_AUTH) {
            return METHOD_NO_ACCEPT
        }
    }

    METHOD_NO_AUTH
}

fn reply_method(stream: &mut Tcp, method: u8) -> bool {
    let reply = [VER, method];
    stream.write(&reply)
}

pub fn get_connect_dest(stream: &mut Tcp) -> ConnectDest {
    let method = select_method(stream);
    if !reply_method(stream, method) {
        return ConnectDest::Unknown
    }

    if method != METHOD_NO_AUTH {
        return ConnectDest::Unknown
    }

    let buf = stream.read_exact(4);
    if buf.len() == 0 {
        return ConnectDest::Unknown
    }

    if buf[1] != CMD_CONNECT {
        return ConnectDest::Unknown
    }

    match buf[3] {
        ATYP_IPV4 => {
            let ipv4 = stream.read_exact(4);
            if ipv4.len() == 0 {
                return ConnectDest::Unknown
            }

            let port = match stream.read_u16() {
                Some(port) => port,
                None => return ConnectDest::Unknown
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
                Some(len) => len,
                None => return ConnectDest::Unknown
            };

            let domain_name = stream.read_exact(len as usize);
            if domain_name.len() == 0 {
                return ConnectDest::Unknown
            }

            let port = match stream.read_u16() {
                Some(port) => port,
                None => return ConnectDest::Unknown
            };

            ConnectDest::DomainName(domain_name, port)
        },

        _ => ConnectDest::Unknown
    }
}

pub fn reply_connect_success(stream: &mut Tcp, addr: SocketAddr) -> bool {
    reply_result(stream, addr, REP_SUCCESS)
}

pub fn reply_failure(stream: &mut Tcp) -> bool {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));
    reply_result(stream, addr, REP_FAILURE)
}

fn reply_result(stream: &mut Tcp, addr: SocketAddr, rep: u8) -> bool {
    let buf = [VER, rep, RSV];
    if !stream.write(&buf) { return false }

    match addr {
        SocketAddr::V4(ipv4) => {
            let bytes = ipv4.ip().octets();
            let buf = [ATYP_IPV4, bytes[3], bytes[2], bytes[1], bytes[0]];
            if !stream.write(&buf) { return false }
            if !stream.write_u16(ipv4.port()) { return false }
        },
        SocketAddr::V6(ipv6) => {
            let segments = ipv6.ip().segments();
            if !stream.write_u8(ATYP_IPV6) { return false }

            let mut n = segments.len();
            while n >= 1 {
                n -= 1;
                if !stream.write_u16(segments[n]) { return false }
            }

            if !stream.write_u16(ipv6.port()) { return false }
        }
    }

    true
}
