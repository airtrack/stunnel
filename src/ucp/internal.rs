use async_std::net::UdpSocket;
use chrono::prelude::*;
use crossbeam_utils::Backoff;
use rand::random;

use std::cell::Cell;
use std::cmp::min;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Instant;
use std::vec::Vec;

use crate::ucp::packet::*;
use crate::ucp::*;

#[derive(Clone, Copy)]
enum UcpState {
    NONE,
    ACCEPTING,
    CONNECTING,
    ESTABLISHED,
}

pub(super) struct InnerStream {
    pub(super) socket: Arc<UdpSocket>,
    lock: AtomicBool,
    alive: AtomicBool,
    metrics_reporter: Box<dyn metrics::MetricsReporter>,
    remote_addr: SocketAddr,
    initial_time: Instant,
    congestion_time: Cell<Instant>,
    metrics_time: Cell<Instant>,
    pacing_time: Cell<Instant>,
    alive_time: Cell<Instant>,
    heartbeat: Cell<Instant>,
    state: Cell<UcpState>,

    send_queue: Cell<UcpPacketQueue>,
    recv_queue: Cell<UcpPacketQueue>,
    send_buffer: Cell<UcpPacketQueue>,

    read_waker: Cell<Option<Waker>>,
    write_waker: Cell<Option<Waker>>,

    ack_list: Cell<Vec<(u32, u32, u32)>>,
    session_id: Cell<u32>,
    local_window: Cell<u32>,
    remote_window: Cell<u32>,
    bandwidth: Cell<u32>,
    send_bps: Cell<u32>,
    recv_bps: Cell<u32>,
    skip_resend_bps: Cell<u32>,
    seq: Cell<u32>,
    una: Cell<u32>,
    rto: Cell<u32>,
    srtt: Cell<u32>,
    rttvar: Cell<u32>,
    pacing_credit: Cell<i32>,

    delay_slope: Cell<f64>,
    delay_base_time: Cell<Option<(u32, u32)>>,
    send_recv_time_list: Cell<Vec<(i32, i32)>>,
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
        metrics_reporter: Box<dyn metrics::MetricsReporter>,
    ) -> Self {
        let now = Instant::now();
        InnerStream {
            socket,
            lock: AtomicBool::new(false),
            alive: AtomicBool::new(true),
            metrics_reporter,
            remote_addr,
            initial_time: now,
            congestion_time: Cell::new(now),
            metrics_time: Cell::new(now),
            pacing_time: Cell::new(now),
            alive_time: Cell::new(now),
            heartbeat: Cell::new(now),
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
            bandwidth: Cell::new(BANDWIDTH),
            send_bps: Cell::new(0),
            recv_bps: Cell::new(0),
            skip_resend_bps: Cell::new(0),
            seq: Cell::new(0),
            una: Cell::new(0),
            rto: Cell::new(DEFAULT_RTO),
            srtt: Cell::new(0),
            rttvar: Cell::new(0),
            pacing_credit: Cell::new(0),
            delay_slope: Cell::new(0f64),
            delay_base_time: Cell::new(None),
            send_recv_time_list: Cell::new(Vec::new()),
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
        {
            let recv_bps = unsafe { &mut *self.recv_bps.as_ptr() };
            *recv_bps += packet.size() as u32 * 8;
        }

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
        let now = Instant::now();

        if self.check_if_alive(now) {
            self.update_delay_info(now);

            let (mut pacing_credit, new_credit) = self.calculate_pacing_credit(now);
            self.do_heartbeat(now).await;
            self.send_ack_list(&mut pacing_credit).await;
            self.timeout_resend(&mut pacing_credit).await;
            self.send_pending_packets(&mut pacing_credit).await;

            if pacing_credit > new_credit {
                pacing_credit = new_credit;
            }
            self.pacing_credit.set(pacing_credit);
        } else {
            self.die();
        }

        self.update_metrics(now);
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
        while self
            .lock
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            backoff.snooze();
        }
        Lock { inner: self }
    }

    fn unlock(&self) {
        self.lock.store(false, Ordering::Release);
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

    fn update_metrics(&self, now: Instant) {
        if now - self.metrics_time.get() < METRICS_INTERVAL {
            return;
        }

        let send_queue = unsafe { &*self.send_queue.as_ptr() };
        let recv_queue = unsafe { &*self.recv_queue.as_ptr() };
        let send_buffer = unsafe { &*self.send_buffer.as_ptr() };
        let rx_seq = if let Some(packet) = recv_queue.front() {
            packet.seq
        } else {
            0
        };

        let metrics = metrics::UcpMetrics {
            date_time: Utc::now(),
            session_id: self.session_id.get(),
            remote_addr: self.remote_addr,
            send_queue_size: send_queue.len(),
            recv_queue_size: recv_queue.len(),
            send_buffer_size: send_buffer.len(),
            bandwidth: self.bandwidth.get() * 8 / 1000,
            send_kbps: self.send_bps.get() / 1000,
            recv_kbps: self.recv_bps.get() / 1000,
            skip_resend_kbps: self.skip_resend_bps.get() / 1000,
            una: self.una.get(),
            rto: self.rto.get(),
            srtt: self.srtt.get(),
            rttvar: self.rttvar.get(),
            rx_seq,
            delay_slope: self.delay_slope.get(),
        };

        self.send_bps.set(0);
        self.recv_bps.set(0);
        self.skip_resend_bps.set(0);
        self.metrics_reporter.report_metrics(metrics);
        self.metrics_time.set(now);
    }

    fn is_send_buffer_overflow(&self) -> bool {
        let remote_window = self.remote_window.get();
        let send_buffer = unsafe { &mut *self.send_buffer.as_ptr() };
        send_buffer.len() >= remote_window as usize
    }

    fn check_if_alive(&self, now: Instant) -> bool {
        let alive = now - self.alive_time.get() < STREAM_BROKEN_DURATION;

        if !alive {
            error!(
                "ucp alive timeout, remote address: {}, session: {}",
                self.remote_addr,
                self.session_id.get()
            );
        }

        alive
    }

    fn calculate_pacing_credit(&self, now: Instant) -> (i32, i32) {
        let duration = (now - self.pacing_time.get()).as_micros() as f32;
        self.pacing_time.set(now);

        let new_credit = ((self.bandwidth.get() as f32 / 1000000f32) * duration) as i32;
        (new_credit + self.pacing_credit.get(), new_credit)
    }

    async fn do_heartbeat(&self, now: Instant) {
        if now - self.heartbeat.get() >= HEARTBEAT_INTERVAL {
            let mut heartbeat = self.new_noseq_packet(CMD_HEARTBEAT);
            self.send_packet_directly(&mut heartbeat).await;
            self.heartbeat.set(now);
        }
    }

    async fn send_ack_list(&self, pacing_credit: &mut i32) {
        let ack_list = self.ack_list.take();
        if ack_list.is_empty() {
            return;
        }

        let mut packet = self.new_noseq_packet(CMD_ACK);

        for &(seq, timestamp, local_timestamp) in ack_list.iter() {
            if packet.remaining_load() < 12 {
                *pacing_credit -= packet.size() as i32;
                self.send_packet_directly(&mut packet).await;
                packet = self.new_noseq_packet(CMD_ACK);
            }

            packet.payload_write_u32(seq);
            packet.payload_write_u32(timestamp);
            packet.payload_write_u32(local_timestamp);
        }

        *pacing_credit -= packet.size() as i32;
        self.send_packet_directly(&mut packet).await;
    }

    async fn timeout_resend(&self, pacing_credit: &mut i32) {
        let now = self.timestamp();
        let una = self.una.get();
        let rto = self.rto.get();
        let mut resend = Vec::new();

        {
            let send_queue = unsafe { &mut *self.send_queue.as_ptr() };

            for packet in send_queue.iter_mut() {
                if *pacing_credit <= 0 {
                    break;
                }

                let interval = now - packet.timestamp;
                let skip_resend = if packet.xmit >= 1 && packet.skip_times > 0 {
                    true
                } else {
                    packet.skip_times >= SKIP_RESEND_TIMES
                };

                if interval >= rto || skip_resend {
                    packet.skip_times = 0;
                    packet.window = self.local_window.get();
                    packet.una = una;
                    packet.timestamp = now;
                    packet.xmit += 1;

                    resend.push(packet.clone());
                    *pacing_credit -= packet.size() as i32;

                    if skip_resend && interval < rto {
                        let skip_resend_bps = unsafe { &mut *self.skip_resend_bps.as_ptr() };
                        *skip_resend_bps += packet.size() as u32 * 8;
                    }
                }
            }
        }

        for packet in resend.iter_mut() {
            self.send_packet_directly(packet).await;
        }
    }

    async fn send_pending_packets(&self, pacing_credit: &mut i32) {
        let now = self.timestamp();
        let una = self.una.get();
        let mut pending = Vec::new();

        {
            let send_queue = unsafe { &mut *self.send_queue.as_ptr() };
            let send_buffer = unsafe { &mut *self.send_buffer.as_ptr() };

            while *pacing_credit > 0 {
                if let Some(mut packet) = send_buffer.pop_front() {
                    *pacing_credit -= packet.size() as i32;

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
        syn_ack.payload_write_u32(self.timestamp());
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
        if packet.cmd == CMD_ACK && packet.payload == 12 {
            let seq = packet.payload_read_u32();
            let timestamp = packet.payload_read_u32();
            let remote_timestamp = packet.payload_read_u32();

            if self.process_an_ack(seq, timestamp, remote_timestamp) {
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
        if packet.cmd == CMD_ACK && packet.payload % 12 == 0 {
            while packet.payload_remaining() > 0 {
                let seq = packet.payload_read_u32();
                let timestamp = packet.payload_read_u32();
                let remote_timestamp = packet.payload_read_u32();
                self.process_an_ack(seq, timestamp, remote_timestamp);
            }
        }
    }

    fn process_data(&self, packet: Box<UcpPacket>) {
        let ack_list = unsafe { &mut *self.ack_list.as_ptr() };
        ack_list.push((packet.seq, packet.timestamp, self.timestamp()));
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
        if packet.cmd == CMD_SYN_ACK && packet.payload == 12 {
            let seq = packet.payload_read_u32();
            let timestamp = packet.payload_read_u32();
            let remote_timestamp = packet.payload_read_u32();

            let mut ack = self.new_noseq_packet(CMD_ACK);
            ack.payload_write_u32(packet.seq);
            ack.payload_write_u32(packet.timestamp);
            ack.payload_write_u32(self.timestamp());
            self.send_packet_directly(&mut ack).await;

            match self.state.get() {
                UcpState::CONNECTING => {
                    if self.process_an_ack(seq, timestamp, remote_timestamp) {
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

    fn process_an_ack(&self, seq: u32, timestamp: u32, remote_timestamp: u32) -> bool {
        let rtt = self.timestamp() - timestamp;
        self.update_rto(rtt);
        self.add_send_recv_time(timestamp, remote_timestamp);

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

    fn add_send_recv_time(&self, send_time: u32, recv_time: u32) {
        match self.delay_base_time.get() {
            Some((send_base, recv_base)) => {
                let x = (send_time - send_base) as i32;
                let y = (recv_time - recv_base) as i32;
                let send_recv_time_list = unsafe { &mut *self.send_recv_time_list.as_ptr() };
                send_recv_time_list.push((x, y));
            }

            None => {
                self.delay_base_time.set(Some((send_time, recv_time)));
            }
        }
    }

    fn update_delay_info(&self, now: Instant) {
        if now - self.congestion_time.get() < CONGESTION_INTERVAL {
            return;
        }

        let mut send_recv_time_list = self.send_recv_time_list.take();
        if send_recv_time_list.is_empty() {
            return;
        }

        send_recv_time_list.sort_by(|p1, p2| {
            if p1.0 != p2.0 {
                p1.0.cmp(&p2.0)
            } else {
                p1.1.cmp(&p2.1)
            }
        });

        let (mut sum_x, mut sum_y) = (0i64, 0i64);
        let _: Vec<_> = send_recv_time_list
            .iter()
            .map(|p| {
                sum_x += p.0 as i64;
                sum_y += p.1 as i64;
            })
            .collect();

        let len = send_recv_time_list.len() as i64;
        let (mean_x, mean_y) = (sum_x / len, sum_y / len);

        let s: Vec<_> = send_recv_time_list
            .iter()
            .map(|p| {
                let x = p.0 as i64;
                let y = p.1 as i64;
                ((x - mean_x) * (y - mean_y), (x - mean_x) * (x - mean_x))
            })
            .collect();

        let (mut sum_xy, mut sum_xx) = (0i64, 0i64);
        let _: Vec<_> = s
            .iter()
            .map(|(xy, xx)| {
                sum_xy += xy;
                sum_xx += xx;
            })
            .collect();

        if sum_xx != 0 {
            let slope = sum_xy as f64 / sum_xx as f64;
            self.delay_slope.set(slope);
        }

        self.congestion_time.set(now);
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
        let sent = self
            .socket
            .send_to(packet.packed_buffer(), self.remote_addr)
            .await;

        if let Ok(bytes) = sent {
            let send_bps = unsafe { &mut *self.send_bps.as_ptr() };
            *send_bps += bytes as u32 * 8;
        }
    }
}
