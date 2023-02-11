use chrono::{DateTime, Utc};
use secrecy::Secret;

#[derive(Debug, Clone)]
pub struct RowData {
    pub id: i64,
    pub created_at: DateTime<Utc>,
    pub nip_05_id: String,
    pub pin_hash: Secret<String>,
    pub private_key_hash: Secret<String>,
}
