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
        let encrytion_schema = secret.expose_secret().to_string();
        let is_empty_or_whitespace = encrytion_schema.trim().is_empty();
        let is_valid_characters = is_valid_pk_hash(encrytion_schema.as_str());
        if is_empty_or_whitespace || !is_valid_characters {
            Err(format!("{} is not a valid private key.", encrytion_schema))
        } else {
            Ok(Self(Secret::new(encrytion_schema)))
        }
    }
}

//Note: hexadecimal string with 64 characters.
fn is_valid_pk_hash(text: &str) -> bool {
    lazy_static! {
        static ref RE: Regex =
            Regex::new(r#"\$PBKDF2\$i=\d+,l=\d+,s=([\s\S]*?)\$(.+)\$(.+)"#).unwrap();
    }
    RE.is_match(text)
}

#[cfg(test)]
mod tests {
    use super::PrivateKeyHash;
    use claim::{assert_err, assert_ok};
    use secrecy::Secret;

    #[test]
    fn a_too_long_key() {
        let private_key = Secret::new("d".repeat(1001));
        assert_err!(PrivateKeyHash::parse(private_key));
    }

    #[test]
    fn a_valid_key() {
        //$PBKDF2$i=${iterations},l=${length},s=${saltBase64}$AESGM$${ivBase64}$${ciphertextBase64}
        let fake_encryption_private_key = "$PBKDF2$i=100000,l=256,s=nz1o4R8CHGKJb/bAl3Rvz9WNTXKA62WOmQLCwaj8PMs=$AESGM$pZjYGCw+JTYngYh8$35oVClmat9FnQsGOWostohY2UKcWPPqodTz6jrjHC/BMXuD6nLaT1+UgPp9CuSWjl++NeT9G6asiDOYbXqQSK0BSXTA3MgHp5zVE8o/szg==";
        let private_key = Secret::new(fake_encryption_private_key.to_string());
        assert_ok!(PrivateKeyHash::parse(private_key));
    }
}
