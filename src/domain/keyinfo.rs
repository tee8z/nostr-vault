use super::{Nip05ID, Pin, PrivateKeyHash};

#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub nip_05_id: Nip05ID,
    pub pin: Pin,
    pub private_key_hash: PrivateKeyHash,
}
