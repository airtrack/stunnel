use async_std::io::{self, Read, Write};
use async_std::net::UdpSocket;
use async_std::task;
use crc::crc32;
use crossbeam_utils::Backoff;
use rand::random;
use std::cell::Cell;
use std::cmp::min;
use std::collections::{HashMap, VecDeque};
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};
use std::vec::Vec;

const CMD_SYN: u8 = 128;
const CMD_SYN_ACK: u8 = 129;
const CMD_ACK: u8 = 130;
const CMD_DATA: u8 = 131;
const CMD_HEARTBEAT: u8 = 132;
const CMD_HEARTBEAT_ACK: u8 = 133;
const UCP_PACKET_META_SIZE: usize = 29;
const DEFAULT_WINDOW: u32 = 512;
const DEFAULT_RTO: u32 = 100;
const HEARTBEAT_INTERVAL_MILLIS: u128 = 2500;
const UCP_STREAM_BROKEN_MILLIS: u128 = 20000;
const SKIP_RESEND_TIMES: u32 = 2;

#[derive(Clone)]
struct UcpPacket {
    buf: [u8; 1400],
    size: usize,
    payload: u16,
    read_pos: usize,
    skip_times: u32,

    session_id: u32,
    timestamp: u32,
    window: u32,
    xmit: u32,
    una: u32,
    seq: u32,
    cmd: u8,
}

impl UcpPacket {
    fn new() -> UcpPacket {
        UcpPacket {
            buf: [0; 1400],
            size: 0,
            payload: 0,
            read_pos: 0,
            skip_times: 0,
            session_id: 0,
            timestamp: 0,
            window: 0,
            xmit: 0,
            una: 0,
            seq: 0,
            cmd: 0,
        }
    }

    fn parse(&mut self) -> bool {
        if !self.is_legal() {
            return false;
        }

        self.payload = (self.size - UCP_PACKET_META_SIZE) as u16;
        self.read_pos = UCP_PACKET_META_SIZE;

        let mut offset = 4;
        self.session_id = self.parse_u32(&mut offset);
        self.timestamp = self.parse_u32(&mut offset);
        self.window = self.parse_u32(&mut offset);
        self.xmit = self.parse_u32(&mut offset);
        self.una = self.parse_u32(&mut offset);
        self.seq = self.parse_u32(&mut offset);
        self.cmd = self.parse_u8(&mut offset);

        self.cmd >= CMD_SYN && self.cmd <= CMD_HEARTBEAT_ACK
    }

    fn pack(&mut self) {
        let mut offset = 4;
        let session_id = self.session_id;
        let timestamp = self.timestamp;
        let window = self.window;
        let xmit = self.xmit;
        let una = self.una;
        let seq = self.seq;
        let cmd = self.cmd;

        self.write_u32(&mut offset, session_id);
        self.write_u32(&mut offset, timestamp);
        self.write_u32(&mut offset, window);
        self.write_u32(&mut offset, xmit);
        self.write_u32(&mut offset, una);
        self.write_u32(&mut offset, seq);
        self.write_u8(&mut offset, cmd);

        offset = 0;
        self.size = self.payload as usize + UCP_PACKET_META_SIZE;

        let digest = crc32::checksum_ieee(&self.buf[4..self.size]);
        self.write_u32(&mut offset, digest);
    }

    fn packed_buffer(&self) -> &[u8] {
        &self.buf[..self.size]
    }

    fn parse_u32(&self, offset: &mut isize) -> u32 {
        let u = unsafe { *(self.buf.as_ptr().offset(*offset) as *const u32) };

        *offset += 4;
        u32::from_be(u)
    }

    fn parse_u8(&self, offset: &mut isize) -> u8 {
        let u = self.buf[*offset as usize];
        *offset += 1;
        u
    }

    fn write_u32(&mut self, offset: &mut isize, u: u32) {
        unsafe {
            *(self.buf.as_ptr().offset(*offset) as *mut u32) = u.to_be();
        }

        *offset += 4;
    }

    fn write_u8(&mut self, offset: &mut isize, u: u8) {
        self.buf[*offset as usize] = u;
        *offset += 1;
    }

    fn is_legal(&self) -> bool {
        self.size >= UCP_PACKET_META_SIZE && self.is_crc32_correct()
    }

    fn is_crc32_correct(&self) -> bool {
        let mut offset = 0;
        let digest = self.parse_u32(&mut offset);
        crc32::checksum_ieee(&self.buf[4..self.size]) == digest
    }

    fn is_syn(&self) -> bool {
        self.cmd == CMD_SYN
    }

    fn remaining_load(&self) -> usize {
        self.buf.len() - self.payload as usize - UCP_PACKET_META_SIZE
    }

    fn payload_offset(&self) -> isize {
        (self.payload as usize + UCP_PACKET_META_SIZE) as isize
    }

    fn payload_write_u32(&mut self, u: u32) -> bool {
        if self.remaining_load() >= 4 {
            let mut offset = self.payload_offset();
            self.write_u32(&mut offset, u);
            self.payload += 4;
            true
        } else {
            false
        }
    }

    fn payload_write_slice(&mut self, buf: &[u8]) -> bool {
        if self.remaining_load() >= buf.len() {
            let offset = self.payload_offset() as usize;
            let end = offset + buf.len();
            self.buf[offset..end].copy_from_slice(buf);
            self.payload += buf.len() as u16;
            true
        } else {
            false
        }
    }

    fn payload_remaining(&self) -> usize {
        self.size - self.read_pos
    }

    fn payload_read_u32(&mut self) -> u32 {
        if self.read_pos + 4 > self.size {
            panic!("Out of range when read u32 from {}", self.read_pos);
        }

        let mut offset = self.read_pos as isize;
        let u = self.parse_u32(&mut offset);
        self.read_pos = offset as usize;
        u
    }

    fn payload_read_slice(&mut self, buf: &mut [u8]) -> usize {
        let size = min(self.payload_remaining(), buf.len());
        let end_pos = self.read_pos + size;

        if size > 0 {
            buf[0..size].copy_from_slice(&self.buf[self.read_pos..end_pos]);
            self.read_pos = end_pos;
        }

        size
    }
}

type UcpPacketQueue = VecDeque<Box<UcpPacket>>;

pub struct UcpStreamMetrics {
    send_queue: AtomicUsize,
    recv_queue: AtomicUsize,
    send_buffer: AtomicUsize,
    rto: AtomicU32,
    srtt: AtomicU32,
}

impl UcpStreamMetrics {
    pub fn new() -> Self {
        Self {
            send_queue: AtomicUsize::new(0),
            recv_queue: AtomicUsize::new(0),
            send_buffer: AtomicUsize::new(0),
            rto: AtomicU32::new(0),
            srtt: AtomicU32::new(0),
        }
    }

    pub fn get_send_queue(&self) -> usize {
        self.send_queue.load(Ordering::Relaxed)
    }

    pub fn get_recv_queue(&self) -> usize {
        self.recv_queue.load(Ordering::Relaxed)
    }

    pub fn get_send_buffer(&self) -> usize {
        self.send_buffer.load(Ordering::Relaxed)
    }

    pub fn get_rto(&self) -> u32 {
        self.rto.load(Ordering::Relaxed)
    }

    pub fn get_srtt(&self) -> u32 {
        self.srtt.load(Ordering::Relaxed)
    }
}

#[derive(Clone, Copy)]
enum UcpState {
    NONE,
    ACCEPTING,
    CONNECTING,
    ESTABLISHED,
}

struct InnerStream {
    lock: AtomicUsize,
    alive: AtomicBool,
    metrics: Arc<UcpStreamMetrics>,
    socket: Arc<UdpSocket>,
    remote_addr: SocketAddr,
    initial_time: Instant,
    alive_time: Cell<Instant>,
    heartbeat: Cell<Instant>,
    state: Cell<UcpState>,

    send_queue: Cell<UcpPacketQueue>,
    recv_queue: Cell<UcpPacketQueue>,
    send_buffer: Cell<UcpPacketQueue>,

    read_waker: Cell<Option<Waker>>,
    write_waker: Cell<Option<Waker>>,

    ack_list: Cell<Vec<(u32, u32)>>,
    session_id: Cell<u32>,
    local_window: Cell<u32>,
    remote_window: Cell<u32>,
    seq: Cell<u32>,
    una: Cell<u32>,
    rto: Cell<u32>,
    srtt: Cell<u32>,
    rttvar: Cell<u32>,
}

unsafe impl Send for InnerStream {}
unsafe impl Sync for InnerStream {}

struct Lock<'a> {
    inner: &'a InnerStream,
}

impl Drop for Lock<'_> {
    #[inline]
    fn drop(&mut self) {
        self.inner.unlock();
    }
}

impl InnerStream {
    fn new(
        socket: Arc<UdpSocket>,
        remote_addr: SocketAddr,
        metrics: Arc<UcpStreamMetrics>,
    ) -> Self {
        InnerStream {
            lock: AtomicUsize::new(0),
            alive: AtomicBool::new(true),
            metrics: metrics,
            socket: socket,
            remote_addr: remote_addr,
            initial_time: Instant::now(),
            alive_time: Cell::new(Instant::now()),
            heartbeat: Cell::new(Instant::now()),
            state: Cell::new(UcpState::NONE),

            send_queue: Cell::new(UcpPacketQueue::new()),
            recv_queue: Cell::new(UcpPacketQueue::new()),
            send_buffer: Cell::new(UcpPacketQueue::new()),

            read_waker: Cell::new(None),
            write_waker: Cell::new(None),

            ack_list: Cell::new(Vec::new()),
            session_id: Cell::new(0),
            local_window: Cell::new(DEFAULT_WINDOW),
            remote_window: Cell::new(DEFAULT_WINDOW),
            seq: Cell::new(0),
            una: Cell::new(0),
            rto: Cell::new(DEFAULT_RTO),
            srtt: Cell::new(0),
            rttvar: Cell::new(0),
        }
    }

    async fn input(&self, packet: Box<UcpPacket>, remote_addr: SocketAddr) {
        if self.remote_addr != remote_addr {
            error!(
                "unexpect packet from {}, expect from {}",
                remote_addr, self.remote_addr
            );
            return;
        }

        let _l = self.lock();

        let state = self.state.get();
        match state {
            UcpState::NONE => {
                if packet.is_syn() {
                    self.accepting(packet);
                } else {
                    error!("not syn packet in UcpState::NONE");
                }
            }
            _ => {
                self.processing(packet).await;
            }
        }
    }

    async fn output(&self) {
        let _l = self.lock();

        if self.check_if_alive() {
            self.do_heartbeat().await;
            self.send_ack_list().await;
            self.timeout_resend().await;
            self.send_pending_packets().await;
        } else {
            self.die();
        }

        self.update_metrics();
    }

    fn poll_read(&self, cx: &mut Context, buf: &mut [u8]) -> Poll<std::io::Result<usize>> {
        let _l = self.lock();

        if !self.alive() {
            return Poll::Ready(Err(Error::from(ErrorKind::Other)));
        }

        let n = self.recv(buf);
        if n == 0 {
            self.read_waker.set(Some(cx.waker().clone()));
            Poll::Pending
        } else {
            Poll::Ready(Ok(n))
        }
    }

    fn poll_write(&self, cx: &mut Context, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let _l = self.lock();

        if !self.alive() {
            return Poll::Ready(Err(Error::from(ErrorKind::Other)));
        }

        if self.is_send_buffer_overflow() {
            self.write_waker.set(Some(cx.waker().clone()));
            Poll::Pending
        } else {
            self.send(buf);
            Poll::Ready(Ok(buf.len()))
        }
    }

    fn shutdown(&self) {
        info!(
            "shutdown {}, session: {}",
            self.remote_addr,
            self.session_id.get()
        );
        let _l = self.lock();
        self.die();
    }

    fn alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    fn die(&self) {
        self.alive.store(false, Ordering::Relaxed);

        if let Some(w) = self.read_waker.take() {
            w.wake()
        }

        if let Some(w) = self.write_waker.take() {
            w.wake()
        }
    }

    fn lock(&self) -> Lock<'_> {
        let backoff = Backoff::new();
        while self.lock.compare_and_swap(0, 1, Ordering::Acquire) != 0 {
            backoff.snooze();
        }
        Lock { inner: self }
    }

    fn unlock(&self) {
        self.lock.store(0, Ordering::SeqCst);
    }

    fn recv(&self, buf: &mut [u8]) -> usize {
        let mut size = 0;
        let una = self.una.get();
        let recv_queue = unsafe { &mut *self.recv_queue.as_ptr() };

        while size < buf.len() && !recv_queue.is_empty() {
            if let Some(packet) = recv_queue.front_mut() {
                let diff = (packet.seq - una) as i32;
                if diff >= 0 {
                    break;
                }

                size += packet.payload_read_slice(&mut buf[size..]);
            }

            let no_remain_payload = recv_queue
                .front()
                .map(|packet| packet.payload_remaining() == 0)
                .unwrap();

            if no_remain_payload {
                recv_queue.pop_front();
            }
        }

        size
    }

    fn send(&self, buf: &[u8]) {
        let mut pos = 0;
        let send_buffer = unsafe { &mut *self.send_buffer.as_ptr() };

        if let Some(packet) = send_buffer.back_mut() {
            if packet.cmd == CMD_DATA {
                let remain = min(packet.remaining_load(), buf.len());
                if remain > 0 {
                    packet.payload_write_slice(&buf[0..remain]);
                }

                pos = remain;
            }
        }

        if pos < buf.len() {
            self.make_packet_send(&buf[pos..]);
        }
    }

    fn try_wake_reader(&self) {
        let recv_queue = unsafe { &*self.recv_queue.as_ptr() };

        if let Some(packet) = recv_queue.front() {
            let diff = (packet.seq - self.una.get()) as i32;
            if diff < 0 {
                if let Some(w) = self.read_waker.take() {
                    w.wake();
                }
            }
        }
    }

    fn try_wake_writer(&self) {
        if !self.is_send_buffer_overflow() {
            if let Some(w) = self.write_waker.take() {
                w.wake();
            }
        }
    }

    fn update_metrics(&self) {
        let send_queue = unsafe { &mut *self.send_queue.as_ptr() };
        let recv_queue = unsafe { &mut *self.recv_queue.as_ptr() };
        let send_buffer = unsafe { &mut *self.send_buffer.as_ptr() };
        let rto = self.rto.get();
        let srtt = self.srtt.get();

        self.metrics
            .send_queue
            .store(send_queue.len(), Ordering::Relaxed);
        self.metrics
            .recv_queue
            .store(recv_queue.len(), Ordering::Relaxed);
        self.metrics
            .send_buffer
            .store(send_buffer.len(), Ordering::Relaxed);
        self.metrics.rto.store(rto, Ordering::Relaxed);
        self.metrics.srtt.store(srtt, Ordering::Relaxed);
    }

    fn is_send_buffer_overflow(&self) -> bool {
        let remote_window = self.remote_window.get();
        let send_buffer = unsafe { &mut *self.send_buffer.as_ptr() };
        send_buffer.len() >= remote_window as usize
    }

    fn check_if_alive(&self) -> bool {
        let now = Instant::now();
        let interval = (now - self.alive_time.get()).as_millis();
        let alive = interval < UCP_STREAM_BROKEN_MILLIS;

        if !alive {
            error!(
                "ucp alive timeout, remote address: {}, session: {}",
                self.remote_addr,
                self.session_id.get()
            );
        }

        alive
    }

    async fn do_heartbeat(&self) {
        let now = Instant::now();
        let interval = (now - self.heartbeat.get()).as_millis();

        if interval >= HEARTBEAT_INTERVAL_MILLIS {
            let mut heartbeat = self.new_noseq_packet(CMD_HEARTBEAT);
            self.send_packet_directly(&mut heartbeat).await;
            self.heartbeat.set(now);
        }
    }

    async fn send_ack_list(&self) {
        let ack_list = self.ack_list.take();
        if ack_list.is_empty() {
            return;
        }

        let mut packet = self.new_noseq_packet(CMD_ACK);

        for &(seq, timestamp) in ack_list.iter() {
            if packet.remaining_load() < 8 {
                self.send_packet_directly(&mut packet).await;
                packet = self.new_noseq_packet(CMD_ACK);
            }

            packet.payload_write_u32(seq);
            packet.payload_write_u32(timestamp);
        }

        self.send_packet_directly(&mut packet).await;
    }

    async fn timeout_resend(&self) {
        let now = self.timestamp();
        let una = self.una.get();
        let rto = self.rto.get();
        let mut resend = Vec::new();

        {
            let send_queue = unsafe { &mut *self.send_queue.as_ptr() };

            for packet in send_queue.iter_mut() {
                let interval = now - packet.timestamp;
                let skip_resend = packet.skip_times >= SKIP_RESEND_TIMES;

                if interval >= rto || skip_resend {
                    packet.skip_times = 0;
                    packet.window = self.local_window.get();
                    packet.una = una;
                    packet.timestamp = now;
                    packet.xmit += 1;

                    resend.push(packet.clone());
                }
            }
        }

        for packet in resend.iter_mut() {
            self.send_packet_directly(packet).await;
        }
    }

    async fn send_pending_packets(&self) {
        let now = self.timestamp();
        let una = self.una.get();
        let window = self.remote_window.get() as usize;
        let mut pending = Vec::new();

        {
            let send_queue = unsafe { &mut *self.send_queue.as_ptr() };
            let send_buffer = unsafe { &mut *self.send_buffer.as_ptr() };

            while send_queue.len() < window {
                if let Some(q) = send_queue.front() {
                    if let Some(p) = send_buffer.front() {
                        let seq_diff = (p.seq - q.seq) as usize;
                        if seq_diff >= window {
                            break;
                        }
                    }
                }

                if let Some(mut packet) = send_buffer.pop_front() {
                    packet.window = self.local_window.get();
                    packet.una = una;
                    packet.timestamp = now;

                    pending.push(packet.clone());
                    send_queue.push_back(packet);
                } else {
                    break;
                }
            }
        }

        for packet in pending.iter_mut() {
            self.send_packet_directly(packet).await;
        }

        self.try_wake_writer();
    }

    fn connecting(&self) {
        self.state.set(UcpState::CONNECTING);
        self.session_id.set(random::<u32>());

        let syn = self.new_packet(CMD_SYN);
        self.send_packet(syn);
        info!(
            "connecting ucp server {}, session: {}",
            self.remote_addr,
            self.session_id.get()
        );
    }

    fn accepting(&self, packet: Box<UcpPacket>) {
        self.state.set(UcpState::ACCEPTING);
        self.session_id.set(packet.session_id);
        self.una.set(packet.seq + 1);
        self.remote_window.set(packet.window);

        let mut syn_ack = self.new_packet(CMD_SYN_ACK);
        syn_ack.payload_write_u32(packet.seq);
        syn_ack.payload_write_u32(packet.timestamp);
        self.send_packet(syn_ack);
        info!(
            "accepting ucp client {}, session: {}",
            self.remote_addr,
            self.session_id.get()
        );
    }

    async fn processing(&self, packet: Box<UcpPacket>) {
        if self.session_id.get() != packet.session_id {
            error!(
                "unexpect session_id: {}, expect {}",
                packet.session_id,
                self.session_id.get()
            );
            return;
        }

        self.alive_time.set(Instant::now());
        self.remote_window.set(packet.window);

        let state = self.state.get();
        match state {
            UcpState::ACCEPTING => {
                self.process_state_accepting(packet);
            }
            UcpState::CONNECTING => {
                self.process_state_connecting(packet).await;
            }
            UcpState::ESTABLISHED => {
                self.process_state_established(packet).await;
            }
            UcpState::NONE => {
                error!("unexpect UcpState::NONE");
            }
        }
    }

    fn process_state_accepting(&self, mut packet: Box<UcpPacket>) {
        if packet.cmd == CMD_ACK && packet.payload == 8 {
            let seq = packet.payload_read_u32();
            let timestamp = packet.payload_read_u32();

            if self.process_an_ack(seq, timestamp) {
                self.state.set(UcpState::ESTABLISHED);
                info!(
                    "{} established, session: {}",
                    self.remote_addr,
                    self.session_id.get()
                );
            }
        } else {
            error!(
                "unexpect packet.cmd: {}, packet.payload: {}",
                packet.cmd, packet.payload
            );
        }
    }

    async fn process_state_connecting(&self, packet: Box<UcpPacket>) {
        self.process_syn_ack(packet).await;
    }

    async fn process_state_established(&self, packet: Box<UcpPacket>) {
        self.process_una(packet.una);

        match packet.cmd {
            CMD_ACK => {
                self.process_ack(packet);
            }
            CMD_DATA => {
                self.process_data(packet);
            }
            CMD_SYN_ACK => {
                self.process_syn_ack(packet).await;
            }
            CMD_HEARTBEAT => {
                self.process_heartbeat().await;
            }
            CMD_HEARTBEAT_ACK => {
                self.process_heartbeat_ack();
            }
            _ => {
                error!("unexpect packet.cmd: {}", packet.cmd);
            }
        }
    }

    fn process_una(&self, una: u32) {
        let send_queue = unsafe { &mut *self.send_queue.as_ptr() };

        while !send_queue.is_empty() {
            let diff = send_queue
                .front()
                .map(|packet| (packet.seq - una) as i32)
                .unwrap();

            if diff < 0 {
                send_queue.pop_front();
            } else {
                break;
            }
        }
    }

    fn process_ack(&self, mut packet: Box<UcpPacket>) {
        if packet.cmd == CMD_ACK && packet.payload % 8 == 0 {
            while packet.payload_remaining() > 0 {
                let seq = packet.payload_read_u32();
                let timestamp = packet.payload_read_u32();
                self.process_an_ack(seq, timestamp);
            }
        }
    }

    fn process_data(&self, packet: Box<UcpPacket>) {
        let ack_list = unsafe { &mut *self.ack_list.as_ptr() };
        ack_list.push((packet.seq, packet.timestamp));
        let una = self.una.get();

        let una_diff = (packet.seq - una) as i32;
        if una_diff < 0 {
            return;
        }

        let mut pos = 0;
        let recv_queue = unsafe { &mut *self.recv_queue.as_ptr() };
        for i in 0..recv_queue.len() {
            let seq_diff = (packet.seq - recv_queue[i].seq) as i32;

            if seq_diff == 0 {
                return;
            } else if seq_diff < 0 {
                break;
            } else {
                pos += 1;
            }
        }

        recv_queue.insert(pos, packet);

        for i in pos..recv_queue.len() {
            let una = self.una.get();
            if recv_queue[i].seq == una {
                self.una.set(una + 1);
            } else {
                break;
            }
        }

        self.try_wake_reader();
    }

    async fn process_syn_ack(&self, mut packet: Box<UcpPacket>) {
        if packet.cmd == CMD_SYN_ACK && packet.payload == 8 {
            let seq = packet.payload_read_u32();
            let timestamp = packet.payload_read_u32();

            let mut ack = self.new_noseq_packet(CMD_ACK);
            ack.payload_write_u32(packet.seq);
            ack.payload_write_u32(packet.timestamp);
            self.send_packet_directly(&mut ack).await;

            match self.state.get() {
                UcpState::CONNECTING => {
                    if self.process_an_ack(seq, timestamp) {
                        self.state.set(UcpState::ESTABLISHED);
                        self.una.set(packet.seq + 1);
                        info!(
                            "{} established, session: {}",
                            self.remote_addr,
                            self.session_id.get()
                        );
                    }
                }
                _ => {}
            }
        } else {
            error!(
                "unexpect packet.cmd: {}, packet.payload: {}",
                packet.cmd, packet.payload
            );
        }
    }

    async fn process_heartbeat(&self) {
        let mut heartbeat_ack = self.new_noseq_packet(CMD_HEARTBEAT_ACK);
        self.send_packet_directly(&mut heartbeat_ack).await;
    }

    fn process_heartbeat_ack(&self) {
        self.alive_time.set(Instant::now());
    }

    fn process_an_ack(&self, seq: u32, timestamp: u32) -> bool {
        let rtt = self.timestamp() - timestamp;
        self.update_rto(rtt);

        let send_queue = unsafe { &mut *self.send_queue.as_ptr() };
        for i in 0..send_queue.len() {
            if send_queue[i].seq == seq {
                send_queue.remove(i);
                return true;
            } else {
                if send_queue[i].timestamp <= timestamp {
                    send_queue[i].skip_times += 1;
                }
            }
        }

        false
    }

    fn update_rto(&self, rtt: u32) {
        // The calculation accuracy is milliseconds
        let mut srtt = self.srtt.get();
        if srtt == 0 {
            srtt = rtt;
        }
        srtt = (srtt * 9 + rtt) / 10;

        let mut rttvar = self.rttvar.get();
        let delta = if rtt > srtt { rtt - srtt } else { srtt - rtt };
        rttvar = (rttvar * 3 + delta) / 4;

        let rto = srtt + 4 * rttvar;

        self.rto.set(rto);
        self.srtt.set(srtt);
        self.rttvar.set(rttvar);
    }

    fn new_packet(&self, cmd: u8) -> Box<UcpPacket> {
        let mut packet = Box::new(UcpPacket::new());

        packet.session_id = self.session_id.get();
        packet.timestamp = self.timestamp();
        packet.window = self.local_window.get();
        packet.seq = self.next_seq();
        packet.una = self.una.get();
        packet.cmd = cmd;

        packet
    }

    fn new_noseq_packet(&self, cmd: u8) -> Box<UcpPacket> {
        let mut packet = Box::new(UcpPacket::new());

        packet.session_id = self.session_id.get();
        packet.timestamp = self.timestamp();
        packet.window = self.local_window.get();
        packet.una = self.una.get();
        packet.cmd = cmd;

        packet
    }

    fn timestamp(&self) -> u32 {
        (Instant::now() - self.initial_time).as_millis() as u32
    }

    fn next_seq(&self) -> u32 {
        let seq = unsafe { &mut *self.seq.as_ptr() };
        *seq += 1;
        *seq
    }

    fn make_packet_send(&self, buf: &[u8]) {
        let buf_len = buf.len();

        let mut pos = 0;
        while pos < buf_len {
            let mut packet = self.new_packet(CMD_DATA);
            let size = min(packet.remaining_load(), buf_len - pos);
            let end_pos = pos + size;

            packet.payload_write_slice(&buf[pos..end_pos]);
            self.send_packet(packet);

            pos = end_pos;
        }
    }

    fn send_packet(&self, packet: Box<UcpPacket>) {
        let send_buffer = unsafe { &mut *self.send_buffer.as_ptr() };
        send_buffer.push_back(packet);
    }

    async fn send_packet_directly(&self, packet: &mut Box<UcpPacket>) {
        packet.pack();
        let _ = self
            .socket
            .send_to(packet.packed_buffer(), self.remote_addr)
            .await;
    }
}

pub struct UcpStream {
    inner: Arc<InnerStream>,
}

impl UcpStream {
    pub async fn connect(server_addr: &str, metrics: Arc<UcpStreamMetrics>) -> Self {
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
        let remote_addr = SocketAddr::from_str(server_addr).unwrap();

        let inner = Arc::new(InnerStream::new(socket, remote_addr, metrics));
        inner.connecting();

        let sender = inner.clone();
        task::spawn(async move {
            UcpStream::send(sender).await;
        });

        let receiver = inner.clone();
        task::spawn(async move {
            UcpStream::recv(receiver).await;
        });

        UcpStream { inner: inner }
    }

    pub fn shutdown(&self) {
        self.inner.shutdown();
    }

    async fn send(inner: Arc<InnerStream>) {
        loop {
            task::sleep(Duration::from_millis(10)).await;
            inner.output().await;

            if !inner.alive() {
                break;
            }
        }
    }

    async fn recv(inner: Arc<InnerStream>) {
        loop {
            let mut packet = Box::new(UcpPacket::new());
            let result = io::timeout(
                Duration::from_secs(5),
                inner.socket.recv_from(&mut packet.buf),
            )
            .await;

            if !inner.alive() {
                break;
            }

            if let Ok((size, remote_addr)) = result {
                packet.size = size;

                if packet.parse() {
                    inner.input(packet, remote_addr).await;
                } else {
                    error!("recv illgal packet from {}", remote_addr);
                }
            }
        }
    }
}

impl Read for &UcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        self.inner.poll_read(cx, buf)
    }
}

impl Write for &UcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

type UcpStreamMap = HashMap<SocketAddr, Arc<InnerStream>>;

pub struct UcpListener {
    socket: Arc<UdpSocket>,
    stream_map: UcpStreamMap,
    timestamp: Instant,
}

impl UcpListener {
    pub async fn bind(listen_addr: &str) -> Self {
        let socket = Arc::new(UdpSocket::bind(listen_addr).await.unwrap());
        UcpListener {
            socket: socket,
            stream_map: UcpStreamMap::new(),
            timestamp: Instant::now(),
        }
    }

    pub async fn incoming(&mut self) -> UcpStream {
        loop {
            let mut packet = Box::new(UcpPacket::new());
            let result = io::timeout(
                Duration::from_secs(1),
                self.socket.recv_from(&mut packet.buf),
            )
            .await;

            if let Ok((size, remote_addr)) = result {
                packet.size = size;

                if packet.parse() {
                    if let Some(inner) = self.stream_map.get(&remote_addr) {
                        inner.input(packet, remote_addr).await;
                    } else if packet.is_syn() {
                        return self.new_stream(packet, remote_addr).await;
                    } else {
                        error!("unknown ucp session packet from {}", remote_addr);
                    }
                } else {
                    error!("recv illgal packet from {}", remote_addr);
                }
            }

            self.remove_dead_stream();
        }
    }

    async fn new_stream(&mut self, packet: Box<UcpPacket>, remote_addr: SocketAddr) -> UcpStream {
        info!("new ucp client from {}", remote_addr);
        let metrics = Arc::new(UcpStreamMetrics::new());
        let inner = Arc::new(InnerStream::new(self.socket.clone(), remote_addr, metrics));
        inner.input(packet, remote_addr).await;

        let sender = inner.clone();
        task::spawn(async move {
            UcpStream::send(sender).await;
        });

        self.stream_map.insert(remote_addr, inner.clone());
        UcpStream { inner: inner }
    }

    fn remove_dead_stream(&mut self) {
        let now = Instant::now();
        if (now - self.timestamp).as_millis() < 1000 {
            return;
        }

        let mut keys = Vec::new();

        for (addr, stream) in self.stream_map.iter() {
            if !stream.alive() {
                keys.push(addr.clone());
            }
        }

        for addr in keys.iter() {
            self.stream_map.remove(addr);
        }

        self.timestamp = now;
    }
}
