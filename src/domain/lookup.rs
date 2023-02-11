use super::{Nip05ID, Pin};

#[derive(Debug, Clone)]
pub struct Lookup {
    pub nip_05_id: Nip05ID,
    pub pin: Pin,
}
