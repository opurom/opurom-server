//! Deterministic, socket-free room membership and broadcast recipients.
//!
//! Member IDs keep their first-join order. Repeated joins do not change that
//! order and broadcasts return the exact ordered recipient list. Closed room
//! names stay reserved so a later join cannot recreate them; at most
//! [`MAX_ROOMS`] distinct names, open or closed, are retained.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Maximum room-name length, in ASCII bytes.
pub const MAX_ROOM_NAME_BYTES: usize = 64;

/// Maximum number of distinct room names retained by one registry.
pub const MAX_ROOMS: usize = 32;

/// Maximum number of members in one room.
pub const MAX_ROOM_MEMBERS: usize = 32;

/// A bounded, recoverable room operation failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoomError {
    InvalidName,
    RoomLimit { max: usize },
    MemberLimit { room: String, max: usize },
    Closed { room: String },
    UnknownRoom { room: String },
}

impl RoomError {
    /// Stable machine-readable code for a WebSocket error frame.
    pub fn code(&self) -> &'static str {
        match self {
            RoomError::InvalidName => "invalid_room",
            RoomError::RoomLimit { .. } => "room_limit",
            RoomError::MemberLimit { .. } => "member_limit",
            RoomError::Closed { .. } => "room_closed",
            RoomError::UnknownRoom { .. } => "unknown_room",
        }
    }
}

impl fmt::Display for RoomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RoomError::InvalidName => write!(
                f,
                "invalid room name: use 1-{} bytes of ASCII letters, digits, '.', '_' or '-'",
                MAX_ROOM_NAME_BYTES
            ),
            RoomError::RoomLimit { max } => write!(f, "room limit reached ({max} rooms)"),
            RoomError::MemberLimit { room, max } => {
                write!(
                    f,
                    "member limit reached for room \"{room}\" ({max} members)"
                )
            }
            RoomError::Closed { room } => write!(f, "room \"{room}\" is closed"),
            RoomError::UnknownRoom { room } => write!(f, "room \"{room}\" does not exist"),
        }
    }
}

impl std::error::Error for RoomError {}

/// Check the bounded room-name charset: ASCII letters, digits, `.`, `_` and `-`.
pub fn validate_room_name(name: &str) -> Result<(), RoomError> {
    let valid = !name.is_empty()
        && name.len() <= MAX_ROOM_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(RoomError::InvalidName)
    }
}

#[derive(Debug)]
struct Room<M> {
    members: Vec<M>,
    index: BTreeSet<M>,
    closed: bool,
}

impl<M: Clone + Ord> Room<M> {
    fn new() -> Room<M> {
        Room {
            members: Vec::new(),
            index: BTreeSet::new(),
            closed: false,
        }
    }

    fn insert(&mut self, member: M) {
        if self.index.insert(member.clone()) {
            self.members.push(member);
        }
    }

    fn remove(&mut self, member: &M) {
        if self.index.remove(member) {
            self.members.retain(|current| current != member);
        }
    }

    fn close(&mut self) -> Vec<M> {
        let removed = std::mem::take(&mut self.members);
        self.index.clear();
        self.closed = true;
        removed
    }
}

/// A pure, deterministic registry of bounded rooms and ordered members.
#[derive(Debug)]
pub struct RoomRegistry<M: Clone + Ord> {
    rooms: BTreeMap<String, Room<M>>,
}

impl<M: Clone + Ord> Default for RoomRegistry<M> {
    fn default() -> RoomRegistry<M> {
        RoomRegistry::new()
    }
}

impl<M: Clone + Ord> RoomRegistry<M> {
    pub fn new() -> RoomRegistry<M> {
        RoomRegistry {
            rooms: BTreeMap::new(),
        }
    }

    /// Join a room. Joining twice is idempotent and keeps the original order.
    pub fn join(&mut self, room: &str, member: M) -> Result<(), RoomError> {
        validate_room_name(room)?;
        if let Some(entry) = self.rooms.get_mut(room) {
            if entry.closed {
                return Err(RoomError::Closed {
                    room: room.to_string(),
                });
            }
            if !entry.index.contains(&member) && entry.members.len() >= MAX_ROOM_MEMBERS {
                return Err(RoomError::MemberLimit {
                    room: room.to_string(),
                    max: MAX_ROOM_MEMBERS,
                });
            }
            entry.insert(member);
            return Ok(());
        }
        if self.rooms.len() >= MAX_ROOMS {
            return Err(RoomError::RoomLimit { max: MAX_ROOMS });
        }
        let mut entry = Room::new();
        entry.insert(member);
        self.rooms.insert(room.to_string(), entry);
        Ok(())
    }

    /// Leave a room. Unknown rooms, closed rooms and repeated leaves are no-ops.
    pub fn leave(&mut self, room: &str, member: &M) -> Result<(), RoomError> {
        validate_room_name(room)?;
        if let Some(entry) = self.rooms.get_mut(room) {
            entry.remove(member);
        }
        Ok(())
    }

    /// Remove one member from every room, including rooms with no other members.
    pub fn leave_all(&mut self, member: &M) {
        for entry in self.rooms.values_mut() {
            entry.remove(member);
        }
    }

    /// Members in first-join order. A closed room has no members.
    pub fn members(&self, room: &str) -> Result<Vec<M>, RoomError> {
        let entry = self.entry(room)?;
        Ok(if entry.closed {
            Vec::new()
        } else {
            entry.members.clone()
        })
    }

    /// Exact ordered recipients for a broadcast, with no duplicates.
    pub fn broadcast(&self, room: &str) -> Result<Vec<M>, RoomError> {
        let entry = self.entry(room)?;
        if entry.closed {
            return Err(RoomError::Closed {
                room: room.to_string(),
            });
        }
        Ok(entry.members.clone())
    }

    /// Remove every member and reject later joins. Closing twice is a no-op.
    pub fn close(&mut self, room: &str) -> Result<Vec<M>, RoomError> {
        validate_room_name(room)?;
        if let Some(entry) = self.rooms.get_mut(room) {
            return Ok(entry.close());
        }
        if self.rooms.len() >= MAX_ROOMS {
            return Err(RoomError::RoomLimit { max: MAX_ROOMS });
        }
        let mut entry = Room::new();
        entry.closed = true;
        self.rooms.insert(room.to_string(), entry);
        Ok(Vec::new())
    }

    /// Number of distinct room names retained, including closed names.
    pub fn room_count(&self) -> usize {
        self.rooms.len()
    }

    fn entry(&self, room: &str) -> Result<&Room<M>, RoomError> {
        validate_room_name(room)?;
        self.rooms.get(room).ok_or_else(|| RoomError::UnknownRoom {
            room: room.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> RoomRegistry<u64> {
        RoomRegistry::new()
    }

    #[test]
    fn room_name_validation_is_bounded_and_strict() {
        assert_eq!(validate_room_name(""), Err(RoomError::InvalidName));
        assert_eq!(
            validate_room_name(&"a".repeat(MAX_ROOM_NAME_BYTES + 1)),
            Err(RoomError::InvalidName)
        );
        assert_eq!(validate_room_name("bad/room"), Err(RoomError::InvalidName));
        assert_eq!(validate_room_name("a.b_C-9"), Ok(()));
        let mut rooms = registry();
        assert_eq!(rooms.join("bad room", 1), Err(RoomError::InvalidName));
        assert_eq!(rooms.leave("bad room", &1), Err(RoomError::InvalidName));
        assert_eq!(RoomError::InvalidName.code(), "invalid_room");
        assert_eq!(RoomError::RoomLimit { max: MAX_ROOMS }.code(), "room_limit");
    }

    #[test]
    fn broadcast_returns_stable_first_join_order_without_duplicates() {
        let mut rooms = registry();
        for member in [7, 3, 9] {
            rooms.join("design", member).unwrap();
        }
        rooms.join("design", 3).unwrap();
        assert_eq!(rooms.members("design").unwrap(), vec![7, 3, 9]);
        assert_eq!(rooms.broadcast("design").unwrap(), vec![7, 3, 9]);
        rooms.leave("design", &3).unwrap();
        rooms.join("design", 3).unwrap();
        assert_eq!(rooms.broadcast("design").unwrap(), vec![7, 9, 3]);
    }

    #[test]
    fn leaving_twice_and_leaving_all_are_noops() {
        let mut rooms = registry();
        rooms.join("alpha", 1).unwrap();
        rooms.join("beta", 1).unwrap();
        rooms.join("alpha", 2).unwrap();
        rooms.leave("alpha", &1).unwrap();
        rooms.leave("alpha", &1).unwrap();
        rooms.leave("missing", &1).unwrap();
        assert_eq!(rooms.members("alpha").unwrap(), vec![2]);
        assert_eq!(rooms.members("beta").unwrap(), vec![1]);
        rooms.leave_all(&1);
        assert_eq!(rooms.members("beta").unwrap(), Vec::<u64>::new());
    }

    #[test]
    fn close_removes_members_and_rejects_later_joins() {
        let mut rooms = registry();
        rooms.join("design", 1).unwrap();
        rooms.join("design", 2).unwrap();
        assert_eq!(rooms.close("design").unwrap(), vec![1, 2]);
        assert_eq!(rooms.members("design").unwrap(), Vec::<u64>::new());
        assert_eq!(
            rooms.broadcast("design"),
            Err(RoomError::Closed {
                room: "design".to_string()
            })
        );
        assert_eq!(
            rooms.join("design", 3),
            Err(RoomError::Closed {
                room: "design".to_string()
            })
        );
        assert_eq!(rooms.close("design").unwrap(), Vec::<u64>::new());
    }

    #[test]
    fn closed_room_names_reserve_a_bounded_slot() {
        let mut rooms = registry();
        for index in 0..MAX_ROOMS {
            let room = format!("room-{index}");
            assert_eq!(rooms.close(&room).unwrap(), Vec::<u64>::new());
            assert_eq!(rooms.join(&room, 1), Err(RoomError::Closed { room }));
        }
        assert_eq!(rooms.room_count(), MAX_ROOMS);
        assert_eq!(
            rooms.join("overflow", 1),
            Err(RoomError::RoomLimit { max: MAX_ROOMS })
        );
        assert_eq!(
            rooms.close("late"),
            Err(RoomError::RoomLimit { max: MAX_ROOMS })
        );
    }

    #[test]
    fn unknown_room_broadcast_is_a_typed_error() {
        let rooms = registry();
        let expected = Err(RoomError::UnknownRoom {
            room: "missing".to_string(),
        });
        assert_eq!(rooms.broadcast("missing"), expected);
        assert_eq!(rooms.members("missing"), expected);
        assert_eq!(expected.unwrap_err().code(), "unknown_room");
    }

    #[test]
    fn room_count_cap_is_enforced() {
        let mut rooms = registry();
        for index in 0..MAX_ROOMS {
            rooms.join(&format!("room-{index}"), 1).unwrap();
        }
        assert_eq!(rooms.room_count(), MAX_ROOMS);
        assert_eq!(
            rooms.join("overflow", 1),
            Err(RoomError::RoomLimit { max: MAX_ROOMS })
        );
        rooms.join("room-0", 2).unwrap();
        assert_eq!(rooms.broadcast("room-0").unwrap(), vec![1, 2]);
    }

    #[test]
    fn member_count_cap_is_enforced() {
        let mut rooms = registry();
        for member in 0..MAX_ROOM_MEMBERS as u64 {
            rooms.join("full", member).unwrap();
        }
        assert_eq!(
            rooms.join("full", MAX_ROOM_MEMBERS as u64),
            Err(RoomError::MemberLimit {
                room: "full".to_string(),
                max: MAX_ROOM_MEMBERS
            })
        );
        rooms.join("full", 0).unwrap();
        assert_eq!(
            rooms.broadcast("full").unwrap(),
            (0..MAX_ROOM_MEMBERS as u64).collect::<Vec<_>>()
        );
    }
}
