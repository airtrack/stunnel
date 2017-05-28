use std::thread;
use std::cell::RefCell;
use std::collections::HashMap;
use std::str::from_utf8;
use std::rc::Rc;
use std::vec::Vec;
use std::io::{Error, Write};
use std::net::{lookup_host, TcpStream};
use std::sync::mpsc::{
    sync_channel, channel,
    SyncSender, Sender, Receiver
};

use time::{get_time, Timespec};
use super::ucp::{UcpServer, UcpStream};
use super::tcp::{Tcp, TcpError};
use super::timer::Timer;
use super::cryptor::*;
use super::protocol::*;

enum TunnelMsg {
    CSHeartbeat,
    CSOpenPort(u32),
    CSClosePort(u32),
    CSShutdownWrite(u32),
    CSConnectDN(u32, Vec<u8>, u16),
    CSData(u8, u32, Vec<u8>),

    SCClosePort(u32),
    SCShutdownWrite(u32),
    SCConnectOk(u32, Vec<u8>),
    SCData(u32, Vec<u8>),

    TunnelPortDrop(u32),
    CloseTunnel,
}

enum TunnelPortMsg {
    ConnectDN(Vec<u8>, u16),
    Data(u8, Vec<u8>),
    ShutdownWrite,
    ClosePort,
}

pub struct TcpTunnel;
pub struct UcpTunnel;

struct TunnelWritePort {
    id: u32,
    tx: SyncSender<TunnelMsg>,
}

struct TunnelReadPort {
    id: u32,
    tx: SyncSender<TunnelMsg>,
    rx: Receiver<TunnelPortMsg>,
}

struct TunnelError;

struct PortMapValue {
    count: u32,
    tx: Sender<TunnelPortMsg>,
}

type PortMap = HashMap<u32, PortMapValue>;

impl TcpTunnel {
    pub fn new(key: Vec<u8>, stream: TcpStream) {
        thread::spawn(move || {
            tcp_tunnel_core_task(key, stream);
        });
    }
}

impl Copy for TcpTunnel {
}

impl Clone for TcpTunnel {
    fn clone(&self) -> Self {
        *self
    }
}

impl UcpTunnel {
    pub fn new(key: Vec<u8>, listen_addr: String) {
        thread::spawn(move || {
            ucp_tunnel_core_task(key, listen_addr);
        });
    }
}

impl TunnelWritePort {
    fn connect_ok(&self, buf: Vec<u8>) {
        let _ = self.tx.send(TunnelMsg::SCConnectOk(self.id, buf));
    }

    fn write(&self, buf: Vec<u8>) {
        let _ = self.tx.send(TunnelMsg::SCData(self.id, buf));
    }

    fn shutdown_write(&self) {
        let _ = self.tx.send(TunnelMsg::SCShutdownWrite(self.id));
    }

    fn close(&self) {
        let _ = self.tx.send(TunnelMsg::SCClosePort(self.id));
    }
}

impl Drop for TunnelWritePort {
    fn drop(&mut self) {
        let _ = self.tx.send(TunnelMsg::TunnelPortDrop(self.id));
    }
}

impl TunnelReadPort {
    fn read(&self) -> TunnelPortMsg {
        self.rx.recv().unwrap()
    }
}

impl Drop for TunnelReadPort {
    fn drop(&mut self) {
        let _ = self.tx.send(TunnelMsg::TunnelPortDrop(self.id));
    }
}

fn tunnel_port_write(s: TcpStream, write_port: TunnelWritePort) {
    let mut stream = Tcp::new(s);

    loop {
        match stream.read_at_most(1024) {
            Ok(buf) => {
                write_port.write(buf);
            },
            Err(TcpError::Eof) => {
                stream.shutdown_read();
                write_port.shutdown_write();
                break
            },
            Err(_) => {
                stream.shutdown();
                write_port.close();
                break
            }
        }
    }
}

fn tunnel_port_read(s: TcpStream, read_port: TunnelReadPort) {
    let mut stream = Tcp::new(s);

    loop {
        match read_port.read() {
            TunnelPortMsg::Data(cs::DATA, buf) => {
                match stream.write(&buf[..]) {
                    Ok(_) => {},
                    Err(_) => {
                        stream.shutdown();
                        break
                    }
                }
            },
            TunnelPortMsg::ShutdownWrite => {
                stream.shutdown_write();
                break
            },
            _ => {
                stream.shutdown();
                break
            }
        }
    }
}

fn tunnel_port_task(read_port: TunnelReadPort, write_port: TunnelWritePort) {
    let os = match read_port.read() {
        TunnelPortMsg::Data(cs::CONNECT, buf) => {
            TcpStream::connect(from_utf8(&buf[..]).unwrap()).ok()
        },

        TunnelPortMsg::ConnectDN(domain_name, port) => {
            lookup_host(from_utf8(&domain_name[..]).unwrap())
                .and_then(|hosts| {
                    hosts.filter_map(|host| {
                        TcpStream::connect((host.ip().clone(), port)).ok()
                    }).next().ok_or(Error::last_os_error())
                }).ok()
        },

        _ => None
    };

    let s = match os {
        Some(s) => s,
        None => {
            return write_port.close();
        }
    };

    match s.local_addr() {
        Ok(addr) => {
            let mut buf = Vec::new();
            let _ = write!(&mut buf, "{}", addr);
            write_port.connect_ok(buf);
        },
        Err(_) => {
            return write_port.close();
        }
    }

    let receiver = s.try_clone().unwrap();
    thread::spawn(move || {
        tunnel_port_write(receiver, write_port);
    });

    tunnel_port_read(s, read_port);
}

struct UcpTask {
    key: Vec<u8>,
    buffer: Vec<u8>,
    alive_time: Timespec,
    encryptor: Option<Cryptor>,
    decryptor: Option<Cryptor>,
    port_map: PortMap,
    core_tx: SyncSender<TunnelMsg>,
    core_rx: Receiver<TunnelMsg>
}

impl UcpTask {
    fn new(key: Vec<u8>) -> UcpTask {
        let (core_tx, core_rx) = sync_channel(10000);

        UcpTask {
            key: key,
            buffer: Vec::new(),
            alive_time: get_time(),
            encryptor: None,
            decryptor: None,
            port_map: PortMap::new(),
            core_tx: core_tx,
            core_rx: core_rx
        }
    }

    fn update(&mut self, ucp: &mut UcpStream) -> bool {
        if !self.check_if_alive() {
            self.destroy();
            return false
        }

        match self.make_cryptor(ucp) {
            Ok(true) => {
                self.read_data_and_process(ucp);
                self.process_pending_tunnel_messages(ucp);
            },

            Ok(false) => { },

            Err(_) => return false
        }

        true
    }

    fn destroy(&self) {
        for (_, value) in self.port_map.iter() {
            let _ = value.tx.send(TunnelPortMsg::ClosePort);
        }
    }

    fn check_if_alive(&self) -> bool {
        let duration = get_time() - self.alive_time;
        duration.num_milliseconds() < ALIVE_TIMEOUT_TIME_MS
    }

    fn make_cryptor(&mut self, ucp: &mut UcpStream)
        -> Result<bool, TunnelError> {
        if self.encryptor.is_none() {
            self.encryptor = Some(Cryptor::new(&self.key[..]));
            let encryptor = self.encryptor.as_mut().unwrap();

            ucp.send(encryptor.ctr_as_slice());
        }

        if self.decryptor.is_none() {
            let size = CTR_SIZE + VERIFY_DATA.len();
            let mut buf = vec![0u8; size];
            let len = ucp.recv(&mut buf[..]);
            buf.truncate(len);
            self.buffer.append(&mut buf);

            if self.buffer.len() >= size {
                let ctr = self.buffer[0..CTR_SIZE].to_vec();
                self.decryptor = Some(Cryptor::with_ctr(&self.key[..], ctr));

                let decryptor = self.decryptor.as_mut().unwrap();
                let data = decryptor.decrypt(&self.buffer[CTR_SIZE..size]);
                if &data[..] != &VERIFY_DATA {
                    return Err(TunnelError {})
                }

                self.buffer.drain(0..size);
            }
        }

        Ok(self.encryptor.is_some() && self.decryptor.is_some())
    }

    fn read_data_and_process(&mut self, ucp: &mut UcpStream) {
        loop {
            let mut buf = vec![0u8; 1024];
            let len = ucp.recv(&mut buf[..]);
            match len {
                0 => { break },
                _ => {
                    buf.truncate(len);
                    self.buffer.append(&mut buf);
                }
            }
        }

        while let Some(msg) = self.parse_buffer_msg() {
            self.process_tunnel_msg(ucp, msg);
        }
    }

    fn parse_buffer_msg(&mut self) -> Option<TunnelMsg> {
        if self.buffer.is_empty() {
            return None
        }

        let mut msg = None;
        let mut consumed_bytes = 0;

        match read_cmd(&self.buffer[..]) {
            cs::HEARTBEAT => {
                msg = Some(TunnelMsg::CSHeartbeat);
                consumed_bytes = 1;
            },

            cs::OPEN_PORT => if self.buffer.len() >= 5 {
                let id = read_id(&self.buffer[..]);
                msg = Some(TunnelMsg::CSOpenPort(id));
                consumed_bytes = 5;
            },

            cs::CLOSE_PORT => if self.buffer.len() >= 5 {
                let id = read_id(&self.buffer[..]);
                msg = Some(TunnelMsg::CSClosePort(id));
                consumed_bytes = 5;
            },

            cs::SHUTDOWN_WRITE => if self.buffer.len() >= 5 {
                let id = read_id(&self.buffer[..]);
                msg = Some(TunnelMsg::CSShutdownWrite(id));
                consumed_bytes = 5;
            },

            cs::CONNECT_DOMAIN_NAME => if self.buffer.len() >= 9 {
                let total_len = get_total_packet_len(&self.buffer[..]);
                if self.buffer.len() >= total_len {
                    let (id, len) = read_id_len(&self.buffer[..]);
                    let domain = self.decryptor.as_mut().unwrap()
                        .decrypt(&self.buffer[9..(9 + len - 2)]);
                    let port = read_domain_port(&self.buffer[..]);

                    msg = Some(TunnelMsg::CSConnectDN(id, domain, port));
                    consumed_bytes = total_len;
                }
            },

            _ => if self.buffer.len() >= 9 {
                let total_len = get_total_packet_len(&self.buffer[..]);
                if self.buffer.len() >= total_len {
                    let cmd = read_cmd(&self.buffer[..]);
                    let (id, len) = read_id_len(&self.buffer[..]);
                    let data = self.decryptor.as_mut().unwrap()
                        .decrypt(&self.buffer[9..(9 + len)]);

                    msg = Some(TunnelMsg::CSData(cmd, id, data));
                    consumed_bytes = total_len;
                }
            }
        }

        if consumed_bytes > 0 {
            self.buffer.drain(0..consumed_bytes);
        }

        msg
    }

    fn process_pending_tunnel_messages(&mut self, ucp: &mut UcpStream) {
        while let Ok(msg) = self.core_rx.try_recv() {
            self.process_tunnel_msg(ucp, msg);
        }
    }

    fn process_tunnel_msg(&mut self, ucp: &mut UcpStream, msg: TunnelMsg) {
        let _ = process_tunnel_msg(
            msg, &self.core_tx,
            &mut self.alive_time,
            &mut self.port_map,
            self.encryptor.as_mut().unwrap(),
            |buf| { ucp.send(buf); Ok(()) });
    }
}

fn ucp_tunnel_core_task(key: Vec<u8>, listen_addr: String) {
    let mut ucp_server = UcpServer::listen(&listen_addr[..]).unwrap();

    ucp_server.set_on_new_ucp_stream(move |ucp| {
        let u_ucp_task = Rc::new(RefCell::new(UcpTask::new(key.clone())));
        let b_ucp_task = u_ucp_task.clone();

        ucp.set_on_update(move |u| {
            u_ucp_task.borrow_mut().update(u)
        });
        ucp.set_on_broken(move |_| {
            b_ucp_task.borrow_mut().destroy()
        });
    });

    ucp_server.run();
}

fn tcp_tunnel_core_task(key: Vec<u8>, sender: TcpStream) {
    let (core_tx, core_rx) = sync_channel(10000);
    let receiver = sender.try_clone().unwrap();
    let core_tx2 = core_tx.clone();
    let key2 = key.clone();

    thread::spawn(move || {
        tcp_tunnel_recv_task(key2, receiver, core_tx2);
    });

    let mut stream = Tcp::new(sender);
    let mut port_map = PortMap::new();

    let _ = tcp_tunnel_loop(&key, &core_tx, &core_rx,
                            &mut stream, &mut port_map);

    stream.shutdown();
    for (_, value) in port_map.iter() {
        let _ = value.tx.send(TunnelPortMsg::ClosePort);
    }
}

fn tcp_tunnel_loop(key: &Vec<u8>,
                   core_tx: &SyncSender<TunnelMsg>,
                   core_rx: &Receiver<TunnelMsg>,
                   stream: &mut Tcp, port_map: &mut PortMap)
    -> Result<(), TunnelError> {
    let mut alive_time = get_time();
    let mut encryptor = Cryptor::new(&key[..]);
    let timer = Timer::new(HEARTBEAT_INTERVAL_MS as u32);

    try!(stream.write(encryptor.ctr_as_slice()).map_err(|_| TunnelError {}));

    loop {
        select! {
            _ = timer.recv() => {
                let duration = get_time() - alive_time;
                if duration.num_milliseconds() > ALIVE_TIMEOUT_TIME_MS {
                    break
                }
            },

            msg = core_rx.recv() => match msg.unwrap() {
                TunnelMsg::CloseTunnel => break,

                message => {
                    try!(process_tunnel_msg(
                            message, core_tx, &mut alive_time,
                            port_map, &mut encryptor,
                            |buf| stream.write(buf).map_err(|_| TunnelError {})));
                }
            }
        }
    }

    Ok(())
}

fn tcp_tunnel_recv_task(key: Vec<u8>, receiver: TcpStream,
                        core_tx: SyncSender<TunnelMsg>) {
    let mut stream = Tcp::new(receiver);
    let _ = tcp_tunnel_recv_loop(&key, &core_tx, &mut stream);

    stream.shutdown();
    let _ = core_tx.send(TunnelMsg::CloseTunnel);
}

fn tcp_tunnel_recv_loop(key: &Vec<u8>, core_tx: &SyncSender<TunnelMsg>,
                        stream: &mut Tcp) -> Result<(), TcpError> {
    let ctr = try!(stream.read_exact(Cryptor::ctr_size()));
    let mut decryptor = Cryptor::with_ctr(&key[..], ctr);

    let buf = try!(stream.read_exact(VERIFY_DATA.len()));
    let data = decryptor.decrypt(&buf[..]);
    if &data[..] != &VERIFY_DATA {
        return Err(TcpError::ErrorData);
    }

    loop {
        let op = try!(stream.read_u8());
        if op == cs::HEARTBEAT {
            let _ = core_tx.send(TunnelMsg::CSHeartbeat);
            continue
        }

        let id = try!(stream.read_u32());
        match op {
            cs::OPEN_PORT => {
                let _ = core_tx.send(TunnelMsg::CSOpenPort(id));
            },

            cs::CLOSE_PORT => {
                let _ = core_tx.send(TunnelMsg::CSClosePort(id));
            },

            cs::SHUTDOWN_WRITE => {
                let _ = core_tx.send(TunnelMsg::CSShutdownWrite(id));
            },

            cs::CONNECT_DOMAIN_NAME => {
                let len = try!(stream.read_u32());
                let buf = try!(stream.read_exact((len - 2) as usize));
                let port = try!(stream.read_u16());
                let domain_name = decryptor.decrypt(&buf[..]);
                let _ = core_tx.send(TunnelMsg::CSConnectDN(id, domain_name, port));
            },

            _ => {
                let len = try!(stream.read_u32());
                let buf = try!(stream.read_exact(len as usize));
                let data = decryptor.decrypt(&buf[..]);
                let _ = core_tx.send(TunnelMsg::CSData(op, id, data));
            }
        }
    }
}

fn process_tunnel_msg<F>(msg: TunnelMsg,
                         core_tx: &SyncSender<TunnelMsg>,
                         alive_time: &mut Timespec,
                         port_map: &mut PortMap,
                         encryptor: &mut Cryptor,
                         send: F)
    -> Result<(), TunnelError>
    where F: FnOnce(&[u8]) -> Result<(), TunnelError> {
    match msg {
        TunnelMsg::CSHeartbeat => {
            *alive_time = get_time();
            try!(send(&pack_sc_heartbeat_rsp_msg()));
        },

        TunnelMsg::CSOpenPort(id) => {
            *alive_time = get_time();
            let (tx, rx) = channel();
            port_map.insert(id, PortMapValue { count: 2, tx: tx });

            let read_port = TunnelReadPort {
                id: id, tx: core_tx.clone(), rx: rx
            };
            let write_port = TunnelWritePort {
                id: id, tx: core_tx.clone()
            };

            thread::spawn(move || {
                tunnel_port_task(read_port, write_port);
            });
        },

        TunnelMsg::CSClosePort(id) => {
            *alive_time = get_time();
            port_map.get(&id).map(|value| {
                let _ = value.tx.send(TunnelPortMsg::ClosePort);
            });

            port_map.remove(&id);
        },

        TunnelMsg::CSShutdownWrite(id) => {
            *alive_time = get_time();
            port_map.get(&id).map(|value| {
                let _ = value.tx.send(TunnelPortMsg::ShutdownWrite);
            });
        }

        TunnelMsg::CSConnectDN(id, domain_name, port) => {
            *alive_time = get_time();
            port_map.get(&id).map(move |value| {
                let _ = value.tx.send(
                    TunnelPortMsg::ConnectDN(domain_name, port));
            });
        },

        TunnelMsg::CSData(op, id, buf) => {
            *alive_time = get_time();
            port_map.get(&id).map(move |value| {
                let _ = value.tx.send(TunnelPortMsg::Data(op, buf));
            });
        },

        TunnelMsg::SCClosePort(id) => {
            let res = port_map.get(&id).map(|value| {
                let _ = value.tx.send(TunnelPortMsg::ClosePort);

                try!(send(&pack_sc_close_port_msg(id)));
                Ok(())
            });

            match res {
                Some(Err(e)) => return Err(e),
                _ => {}
            }

            port_map.remove(&id);
        },

        TunnelMsg::SCShutdownWrite(id) => {
            try!(send(&pack_sc_shutdown_write_msg(id)));
        },

        TunnelMsg::SCConnectOk(id, buf) => {
            let data = encryptor.encrypt(&buf[..]);
            try!(send(&pack_sc_connect_ok_msg(id, &data[..])[..]));
        },

        TunnelMsg::SCData(id, buf) => {
            let data = encryptor.encrypt(&buf[..]);
            try!(send(&pack_sc_data_msg(id, &data[..])[..]));
        },

        TunnelMsg::TunnelPortDrop(id) => {
            let remove = if let Some(value)
                = port_map.get_mut(&id) {
                    value.count = value.count - 1;
                    value.count == 0
                } else {
                    false
                };

            if remove {
                port_map.remove(&id);
            }
        },

        _ => {}
    }

    Ok(())
}
