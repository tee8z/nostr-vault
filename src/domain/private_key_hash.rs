use lazy_static::lazy_static;
use regex::Regex;
use secrecy::{ExposeSecret, Secret};

#[derive(Debug, Clone)]
pub struct PrivateKeyHash(Secret<String>);

impl AsRef<str> for PrivateKeyHash {
    fn as_ref(&self) -> &str {
        self.0.expose_secret().as_str()
    }
}

impl PrivateKeyHash {
    pub fn parse(secret: Secret<String>) -> Result<PrivateKeyHash, String> {
        let hash = secret.expose_secret().to_string();
        let is_empty_or_whitespace = hash.trim().is_empty();
        let is_valid_characters = is_valid_pk_hash(hash.as_str());
        if is_empty_or_whitespace || !is_valid_characters {
            Err(format!("{} is not a valid private key.", hash))
        } else {
            Ok(Self(Secret::new(hash)))
        }
    }
}

fn is_valid_pk_hash(text: &str) -> bool {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"^[a-fA-F0-9]{64}$").unwrap();
    }
    RE.is_match(text)
}

#[cfg(test)]
mod tests {
    use super::PrivateKeyHash;
    use claim::{assert_err, assert_ok};
    use easy_hasher::easy_hasher::sha256;
    use secrecy::Secret;

    #[test]
    fn a_too_long_key() {
        let private_key = Secret::new("d".repeat(1001));
        assert_err!(PrivateKeyHash::parse(private_key));
    }

    #[test]
    fn a_valid_key() {
        let fake_key =
            "npub1d4ed5x49d7p24xn63flj4985dc4gpfngdhtqcxpth0ywhm6czxcscfpcq8".to_string();
        let hash = sha256(&fake_key);
        let private_key = Secret::new(hash.to_hex_string());
        assert_ok!(PrivateKeyHash::parse(private_key));
    }
}
