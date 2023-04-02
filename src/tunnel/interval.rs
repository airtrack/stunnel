use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_std::stream::Stream;
use futures_timer::Delay;

pub fn interval<T>(dur: Duration, val: T) -> Interval<T> {
    Interval {
        delay: Delay::new(dur),
        interval: dur,
        value: Box::new(val),
    }
}

pub struct Interval<T> {
    delay: Delay,
    interval: Duration,
    value: Box<T>,
}

impl<T: std::clone::Clone> Stream for Interval<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if Pin::new(&mut self.delay).poll(cx).is_pending() {
            return Poll::Pending;
        }
        let when = Instant::now();
        let next = next_interval(when, Instant::now(), self.interval);
        self.delay.reset(next);
        Poll::Ready(Some(*self.value.clone()))
    }
}

fn duration_to_nanos(dur: Duration) -> Option<u64> {
    dur.as_secs()
        .checked_mul(1_000_000_000)
        .and_then(|v| v.checked_add(u64::from(dur.subsec_nanos())))
}

fn next_interval(prev: Instant, now: Instant, interval: Duration) -> Instant {
    let new = prev + interval;
    if new > now {
        return new;
    }

    let spent_ns = duration_to_nanos(now.duration_since(prev)).expect("interval should be expired");
    let interval_ns =
        duration_to_nanos(interval).expect("interval is less that 427 thousand years");
    let mult = spent_ns / interval_ns + 1;
    assert!(
        mult < (1 << 32),
        "can't skip more than 4 billion intervals of {:?} \
         (trying to skip {})",
        interval,
        mult
    );
    prev + interval * (mult as u32)
}
