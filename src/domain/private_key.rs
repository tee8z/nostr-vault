use secrecy::{ExposeSecret, Secret};
use unicode_segmentation::UnicodeSegmentation;

#[derive(Debug, Clone)]
pub struct PrivateKey(Secret<String>);

impl AsRef<str> for PrivateKey {
    fn as_ref(&self) -> &str {
        self.0.expose_secret().as_str()
    }
}

//TODO: come up with a better validation
impl PrivateKey {
    pub fn parse(secret: Secret<String>) -> Result<PrivateKey, String> {
        let s = secret.expose_secret().to_string();
        let is_empty_or_whitespace = s.trim().is_empty();
        let is_too_long = s.graphemes(true).count() > 1000;
        let forbidden_characters = ['/', '(', ')', '"', '<', '>', '\\', '{', '}'];
        let contains_forbidden_characters = s.chars().any(|g| forbidden_characters.contains(&g));

        if is_empty_or_whitespace || is_too_long || contains_forbidden_characters {
            Err(format!("{} is not a valid private key.", s))
        } else {
            Ok(Self(Secret::new(s)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PrivateKey;
    use claim::{assert_err, assert_ok};
    use easy_hasher::easy_hasher::sha256;
    use secrecy::Secret;

    #[test]
    fn a_too_long_key() {
        let private_key = Secret::new("d".repeat(1001));
        assert_err!(PrivateKey::parse(private_key));
    }

    #[test]
    fn a_valid_key() {
        let fake_key =
            "npub1d4ed5x49d7p24xn63flj4985dc4gpfngdhtqcxpth0ywhm6czxcscfpcq8".to_string();
        let hash = sha256(&fake_key);
        let private_key = Secret::new(hash.to_hex_string());
        assert_ok!(PrivateKey::parse(private_key));
    }
}
