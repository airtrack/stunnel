use async_std::net::UdpSocket;

use crossbeam_utils::Backoff;
use rand::random;

use std::cell::Cell;
use std::cmp::min;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Instant;
use std::vec::Vec;

use crate::ucp::packet::*;
use crate::ucp::*;

pub struct UcpStreamMetrics {
    send_queue: AtomicUsize,
    recv_queue: AtomicUsize,
    send_buffer: AtomicUsize,
    una: AtomicU32,
    rto: AtomicU32,
    srtt: AtomicU32,
    rttvar: AtomicU32,
    rx_seq: AtomicU32,
}

impl UcpStreamMetrics {
    pub fn new() -> Self {
        Self {
            send_queue: AtomicUsize::new(0),
            recv_queue: AtomicUsize::new(0),
            send_buffer: AtomicUsize::new(0),
            una: AtomicU32::new(0),
            rto: AtomicU32::new(0),
            srtt: AtomicU32::new(0),
            rttvar: AtomicU32::new(0),
            rx_seq: AtomicU32::new(0),
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

    pub fn get_una(&self) -> u32 {
        self.una.load(Ordering::Relaxed)
    }

    pub fn get_rto(&self) -> u32 {
        self.rto.load(Ordering::Relaxed)
    }

    pub fn get_srtt(&self) -> u32 {
        self.srtt.load(Ordering::Relaxed)
    }

    pub fn get_rttvar(&self) -> u32 {
        self.rttvar.load(Ordering::Relaxed)
    }

    pub fn get_rx_seq(&self) -> u32 {
        self.rx_seq.load(Ordering::Relaxed)
    }
}

#[derive(Clone, Copy)]
enum UcpState {
    NONE,
    ACCEPTING,
    CONNECTING,
    ESTABLISHED,
}

pub(super) struct InnerStream {
    pub(super) socket: Arc<UdpSocket>,
    lock: AtomicUsize,
    alive: AtomicBool,
    metrics: Arc<UcpStreamMetrics>,
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
    pub(super) fn new(
        socket: Arc<UdpSocket>,
        remote_addr: SocketAddr,
        metrics: Arc<UcpStreamMetrics>,
    ) -> Self {
        InnerStream {
            socket: socket,
            lock: AtomicUsize::new(0),
            alive: AtomicBool::new(true),
            metrics: metrics,
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

    pub(super) async fn input(&self, packet: Box<UcpPacket>, remote_addr: SocketAddr) {
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

    pub(super) async fn output(&self) {
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

    pub(super) fn poll_read(
        &self,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
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

    pub(super) fn poll_write(&self, cx: &mut Context, buf: &[u8]) -> Poll<std::io::Result<usize>> {
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

    pub(super) fn shutdown(&self) {
        info!(
            "shutdown {}, session: {}",
            self.remote_addr,
            self.session_id.get()
        );
        let _l = self.lock();
        self.die();
    }

    pub(super) fn alive(&self) -> bool {
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
        let una = self.una.get();
        let rto = self.rto.get();
        let srtt = self.srtt.get();
        let rttvar = self.rttvar.get();
        let rx_seq = if let Some(packet) = recv_queue.front() {
            packet.seq
        } else {
            0
        };

        self.metrics
            .send_queue
            .store(send_queue.len(), Ordering::Relaxed);
        self.metrics
            .recv_queue
            .store(recv_queue.len(), Ordering::Relaxed);
        self.metrics
            .send_buffer
            .store(send_buffer.len(), Ordering::Relaxed);
        self.metrics.una.store(una, Ordering::Relaxed);
        self.metrics.rto.store(rto, Ordering::Relaxed);
        self.metrics.srtt.store(srtt, Ordering::Relaxed);
        self.metrics.rttvar.store(rttvar, Ordering::Relaxed);
        self.metrics.rx_seq.store(rx_seq, Ordering::Relaxed);
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

    pub(super) fn connecting(&self) {
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
