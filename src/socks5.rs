use std::io::TcpStream;
use std::io::net::ip::{IpAddr, SocketAddr};
use std::iter::IteratorExt;

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

fn select_method(mut stream: TcpStream) -> u8 {
    match stream.read_u8() {
        Ok(VER) => {},
        _ => return METHOD_NO_ACCEPT
    }

    let method_num = match stream.read_u8() {
        Ok(method_num) => method_num as uint,
        _ => return METHOD_NO_ACCEPT
    };

    if method_num == 1 {
        match stream.read_u8() {
            Ok(METHOD_NO_AUTH) => {},
            _ => return METHOD_NO_ACCEPT
        }
    } else {
        match stream.read_exact(method_num) {
            Ok(methods) => {
                if !methods.into_iter().any(|method| method == METHOD_NO_AUTH) {
                    return METHOD_NO_ACCEPT
                }
            },
            _ => return METHOD_NO_ACCEPT
        }
    }

    METHOD_NO_AUTH
}

fn reply_method(mut stream: TcpStream, method: u8) {
    let reply = [VER, method];
    let _ = stream.write(reply.as_slice());
}

pub fn get_connect_dest(mut stream: TcpStream) -> ConnectDest {
    let method = select_method(stream.clone());
    reply_method(stream.clone(), method);

    if method != METHOD_NO_AUTH {
        return ConnectDest::Unknown
    }

    let mut buf = [0, ..4];
    if stream.read_at_least(buf.len(), &mut buf).is_err() {
        return ConnectDest::Unknown
    }

    if buf[1] != CMD_CONNECT {
        return ConnectDest::Unknown
    }

    match buf[3] {
        ATYP_IPV4 => {
            let mut ipv4 = [0, ..4];
            if stream.read_at_least(ipv4.len(), &mut ipv4).is_err() {
                return ConnectDest::Unknown
            }

            match stream.read_be_u16() {
                Ok(port) => ConnectDest::Addr(SocketAddr {
                    ip: IpAddr::Ipv4Addr(ipv4[3], ipv4[2], ipv4[1], ipv4[0]),
                    port: port
                }),
                Err(_) => ConnectDest::Unknown
            }
        },
        ATYP_IPV6 => {
            ConnectDest::Unknown
        },
        ATYP_DOMAINNAME => {
            let domain_name = match stream.read_u8().ok().and_then(
                |len| stream.read_exact(len as uint).ok()) {
                Some(buf) => buf,
                None => return ConnectDest::Unknown
            };

            match stream.read_be_u16() {
                Ok(port) => ConnectDest::DomainName(domain_name, port),
                Err(_) => ConnectDest::Unknown
            }
        },
        _ => ConnectDest::Unknown
    }
}

pub fn reply_connect_success(stream: TcpStream, addr: SocketAddr) {
    reply_result(stream, addr, REP_SUCCESS);
}

pub fn reply_failure(stream: TcpStream) {
    let addr = SocketAddr {
        ip: IpAddr::Ipv4Addr(0, 0, 0, 0),
        port: 0
    };
    reply_result(stream, addr, REP_FAILURE);
}

fn reply_result(mut stream: TcpStream, addr: SocketAddr, rep: u8) {
    let buf = [VER, rep, RSV];
    let _ = stream.write(&buf);

    match addr {
        SocketAddr { ip: IpAddr::Ipv4Addr(n1, n2, n3, n4), port } => {
            let buf = [ATYP_IPV4, n4, n3, n2, n1];
            let _ = stream.write(&buf);
            let _ = stream.write_be_u16(port);
        },
        SocketAddr { ip: IpAddr::Ipv6Addr(n1, n2, n3, n4, n5, n6, n7, n8), port } => {
            let _ = stream.write_u8(ATYP_IPV6);
            let _ = stream.write_be_u16(n8);
            let _ = stream.write_be_u16(n7);
            let _ = stream.write_be_u16(n6);
            let _ = stream.write_be_u16(n5);
            let _ = stream.write_be_u16(n4);
            let _ = stream.write_be_u16(n3);
            let _ = stream.write_be_u16(n2);
            let _ = stream.write_be_u16(n1);
            let _ = stream.write_be_u16(port);
        }
    }
}
