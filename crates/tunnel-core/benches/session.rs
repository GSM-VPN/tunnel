use std::hint::black_box;
use std::time::{Duration, Instant, SystemTime};

use tunnel_core::{FairByteRateLimiter, SessionId, SessionTable, ThroughputPolicy};

const ITERATIONS: usize = 10_000;
const CONCURRENT_SESSIONS: u32 = 216;
const PAYLOAD_BYTES: u64 = 1_024;

fn main() {
    measure_session_table();
    measure_fair_rate_limiter();
}

fn measure_session_table() {
    let started = Instant::now();
    let mut removed = 0usize;

    for _ in 0..ITERATIONS {
        let mut table = SessionTable::new(CONCURRENT_SESSIONS as usize).expect("capacity is valid");
        for session_id in 1..=CONCURRENT_SESSIONS {
            table
                .insert(
                    SessionId::new(session_id).expect("session ID is non-zero"),
                    session_id,
                )
                .expect("session fits in the table");
        }
        for session_id in 1..=CONCURRENT_SESSIONS {
            removed += table
                .remove(SessionId::new(session_id).expect("session ID is non-zero"))
                .expect("session exists") as usize;
        }
        black_box(table);
    }

    println!(
        "session_table_fill_remove sessions={CONCURRENT_SESSIONS} iterations={ITERATIONS} \
         removed_sum={removed} elapsed_ns={}",
        started.elapsed().as_nanos()
    );
}

fn measure_fair_rate_limiter() {
    let policy = ThroughputPolicy {
        target_bytes_per_second: 512_000_000,
        burst_bytes: 1_000_000,
        max_sessions: CONCURRENT_SESSIONS as usize,
    };
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
    let started = Instant::now();
    let mut admitted = 0usize;

    for _ in 0..ITERATIONS {
        let mut limiter = FairByteRateLimiter::new(policy);
        for session_id in 1..=u64::from(CONCURRENT_SESSIONS) {
            admitted += usize::from(limiter.allow(session_id, PAYLOAD_BYTES, now));
        }
        black_box(limiter);
    }

    println!(
        "fair_rate_limit sessions={CONCURRENT_SESSIONS} payload_bytes={PAYLOAD_BYTES} \
         iterations={ITERATIONS} admitted={admitted} elapsed_ns={}",
        started.elapsed().as_nanos()
    );
}
