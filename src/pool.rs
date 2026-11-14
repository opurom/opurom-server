//! Bounded, deterministic TCP connection admission.
//!
//! A pool owns at most `max_connections` active leases. Released slots are
//! reused in FIFO order; every lease has a monotonically increasing id. Idle
//! slots expire from caller-supplied integer millisecond ticks, so admission
//! decisions never read a clock. The server injects monotonic ticks and the
//! tests inject fixed values.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

/// Default maximum number of simultaneously active connections.
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;

/// Default idle timeout of a released slot, in integer milliseconds.
pub const DEFAULT_IDLE_TIMEOUT_MS: u64 = 30_000;

/// One admitted connection. `slot` is reused; `id` never repeats.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    pub id: u64,
    pub slot: usize,
}

/// Cumulative admission counters. All values saturate instead of wrapping.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PoolMetrics {
    pub accepted: u64,
    pub rejected: u64,
    pub reused: u64,
    pub peak: u64,
}

/// A typed admission or configuration failure with a stable reason code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PoolError {
    InvalidLimit {
        field: &'static str,
        value: String,
        reason: &'static str,
    },
    Full {
        max: usize,
        active: usize,
    },
    UnknownLease {
        id: u64,
    },
    IdExhausted,
    SlotExhausted,
}

impl PoolError {
    /// Stable machine-readable reason, also sent on the overload response.
    pub fn code(&self) -> &'static str {
        match self {
            PoolError::InvalidLimit { .. } => "invalid_pool_limit",
            PoolError::Full { .. } => "connection_pool_full",
            PoolError::UnknownLease { .. } => "unknown_pool_lease",
            PoolError::IdExhausted => "pool_id_exhausted",
            PoolError::SlotExhausted => "pool_slot_exhausted",
        }
    }
}

impl fmt::Display for PoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PoolError::InvalidLimit {
                field,
                value,
                reason,
            } => write!(f, "invalid {field} limit '{value}': {reason}"),
            PoolError::Full { max, active } => {
                write!(
                    f,
                    "connection pool is full: {active} active of max {max} connections"
                )
            }
            PoolError::UnknownLease { id } => {
                write!(f, "connection pool lease {id} is not active")
            }
            PoolError::IdExhausted => write!(f, "connection pool lease ids are exhausted"),
            PoolError::SlotExhausted => write!(f, "connection pool slot ids are exhausted"),
        }
    }
}

impl std::error::Error for PoolError {}

/// A thread-safe pool of bounded connection slots.
#[derive(Clone, Debug)]
pub struct ConnectionPool {
    state: Arc<Mutex<PoolState>>,
}

impl ConnectionPool {
    /// Build a pool from integer limits. Zero limits are rejected without panicking.
    pub fn new(
        max_connections: usize,
        idle_timeout_ticks: u64,
    ) -> Result<ConnectionPool, PoolError> {
        if max_connections == 0 {
            return Err(invalid_limit(
                "max_connections",
                max_connections,
                "must be greater than zero",
            ));
        }
        if idle_timeout_ticks == 0 {
            return Err(invalid_limit(
                "idle_timeout_ticks",
                idle_timeout_ticks,
                "must be greater than zero",
            ));
        }
        Ok(ConnectionPool {
            state: Arc::new(Mutex::new(PoolState::new(
                max_connections,
                idle_timeout_ticks,
            ))),
        })
    }

    /// Parse decimal configuration strings, rejecting malformed, zero and
    /// negative limits with a typed error.
    pub fn parse(
        max_connections: &str,
        idle_timeout_ticks: &str,
    ) -> Result<ConnectionPool, PoolError> {
        let max_raw = parse_limit(max_connections, "max_connections")?;
        let idle_raw = parse_limit(idle_timeout_ticks, "idle_timeout_ticks")?;
        let max = usize::try_from(max_raw).map_err(|_| {
            invalid_limit("max_connections", max_raw, "must fit the platform usize")
        })?;
        let idle = u64::try_from(idle_raw).map_err(|_| {
            invalid_limit(
                "idle_timeout_ticks",
                idle_raw,
                "must fit an unsigned 64-bit integer",
            )
        })?;
        ConnectionPool::new(max, idle)
    }

    /// Admit one connection at injected tick `now`.
    pub fn admit(&self, now: u64) -> Result<Lease, PoolError> {
        let mut state = lock(&self.state);
        state.admit(now)
    }

    /// Release one connection back to the pool at injected tick `now`.
    pub fn release(&self, lease: Lease, now: u64) -> Result<(), PoolError> {
        let mut state = lock(&self.state);
        state.release(lease, now)
    }

    /// A snapshot of cumulative counters.
    pub fn metrics(&self) -> PoolMetrics {
        lock(&self.state).metrics
    }
}

#[derive(Clone, Copy, Debug)]
struct IdleSlot {
    slot: usize,
    idle_since: u64,
}

#[derive(Debug)]
struct PoolState {
    max_connections: usize,
    idle_timeout_ticks: u64,
    idle: VecDeque<IdleSlot>,
    active: BTreeMap<u64, usize>,
    next_id: u64,
    next_slot: usize,
    metrics: PoolMetrics,
}

impl PoolState {
    fn new(max_connections: usize, idle_timeout_ticks: u64) -> PoolState {
        PoolState {
            max_connections,
            idle_timeout_ticks,
            idle: VecDeque::new(),
            active: BTreeMap::new(),
            next_id: 1,
            next_slot: 0,
            metrics: PoolMetrics::default(),
        }
    }

    // shortcut: idle slots are reclaimed on admission; no reaper thread, upgrade when proactive eviction is required.
    fn expire_idle(&mut self, now: u64) {
        while let Some(front) = self.idle.front().copied() {
            if now.saturating_sub(front.idle_since) < self.idle_timeout_ticks {
                break;
            }
            self.idle.pop_front();
        }
    }

    fn admit(&mut self, now: u64) -> Result<Lease, PoolError> {
        self.expire_idle(now);
        if self.active.len() >= self.max_connections {
            self.metrics.rejected = self.metrics.rejected.saturating_add(1);
            return Err(PoolError::Full {
                max: self.max_connections,
                active: self.active.len(),
            });
        }
        let id = self.next_id;
        let Some(next_id) = id.checked_add(1) else {
            self.metrics.rejected = self.metrics.rejected.saturating_add(1);
            return Err(PoolError::IdExhausted);
        };
        let (slot, reused) = if let Some(front) = self.idle.pop_front() {
            (front.slot, true)
        } else {
            let slot = self.next_slot;
            let Some(next_slot) = slot.checked_add(1) else {
                self.metrics.rejected = self.metrics.rejected.saturating_add(1);
                return Err(PoolError::SlotExhausted);
            };
            self.next_slot = next_slot;
            (slot, false)
        };
        self.active.insert(id, slot);
        self.next_id = next_id;
        self.metrics.accepted = self.metrics.accepted.saturating_add(1);
        if reused {
            self.metrics.reused = self.metrics.reused.saturating_add(1);
        }
        let peak = u64::try_from(self.active.len()).unwrap_or(u64::MAX);
        self.metrics.peak = self.metrics.peak.max(peak);
        Ok(Lease { id, slot })
    }

    fn release(&mut self, lease: Lease, now: u64) -> Result<(), PoolError> {
        if self.active.get(&lease.id) != Some(&lease.slot) {
            return Err(PoolError::UnknownLease { id: lease.id });
        }
        self.active.remove(&lease.id);
        self.idle.push_back(IdleSlot {
            slot: lease.slot,
            idle_since: now,
        });
        Ok(())
    }
}

fn parse_limit(raw: &str, field: &'static str) -> Result<i64, PoolError> {
    let value = raw.trim();
    let parsed = value
        .parse::<i64>()
        .map_err(|_| invalid_limit(field, value, "must be a base-10 integer"))?;
    if parsed <= 0 {
        return Err(invalid_limit(field, value, "must be greater than zero"));
    }
    Ok(parsed)
}

fn invalid_limit(field: &'static str, value: impl fmt::Display, reason: &'static str) -> PoolError {
    PoolError::InvalidLimit {
        field,
        value: value.to_string(),
        reason,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_is_bounded_and_typed() {
        let pool = ConnectionPool::new(2, 100).unwrap();
        let first = pool.admit(0).unwrap();
        let second = pool.admit(0).unwrap();
        let error = pool.admit(0).unwrap_err();
        assert_eq!(error, PoolError::Full { max: 2, active: 2 });
        assert_eq!(error.code(), "connection_pool_full");
        let metrics = pool.metrics();
        assert_eq!(metrics.accepted, 2);
        assert_eq!(metrics.rejected, 1);
        assert_eq!(metrics.peak, 2);
        pool.release(first, 10).unwrap();
        let third = pool.admit(10).unwrap();
        assert_eq!(third.slot, first.slot);
        assert!(third.id > second.id);
    }

    #[test]
    fn released_slots_are_reused_fifo_with_monotonic_ids() {
        let pool = ConnectionPool::new(2, 100).unwrap();
        let first = pool.admit(0).unwrap();
        let second = pool.admit(0).unwrap();
        pool.release(second, 1).unwrap();
        pool.release(first, 2).unwrap();
        let third = pool.admit(3).unwrap();
        let fourth = pool.admit(3).unwrap();
        assert_eq!(third.slot, second.slot);
        assert_eq!(fourth.slot, first.slot);
        assert!(third.id > second.id);
        assert!(fourth.id > third.id);
        assert_eq!(pool.metrics().reused, 2);
    }

    #[test]
    fn idle_slots_expire_with_injected_ticks() {
        let pool = ConnectionPool::new(1, 10).unwrap();
        let lease = pool.admit(0).unwrap();
        pool.release(lease, 5).unwrap();
        let soon = pool.admit(14).unwrap();
        assert_eq!(soon.slot, lease.slot);
        pool.release(soon, 20).unwrap();
        let late = pool.admit(31).unwrap();
        assert_ne!(late.slot, soon.slot);
        assert!(late.id > soon.id);
        assert_eq!(pool.metrics().reused, 1);
    }

    #[test]
    fn malformed_zero_and_negative_limits_are_rejected() {
        for raw in ["", "abc", "0", "-1", "1.5"] {
            let error = ConnectionPool::parse(raw, "10").unwrap_err();
            assert_eq!(error.code(), "invalid_pool_limit");
        }
        for raw in ["", "abc", "0", "-1"] {
            let error = ConnectionPool::parse("2", raw).unwrap_err();
            assert_eq!(error.code(), "invalid_pool_limit");
        }
        assert!(ConnectionPool::new(0, 10).is_err());
        assert!(ConnectionPool::new(2, 0).is_err());
    }
}
