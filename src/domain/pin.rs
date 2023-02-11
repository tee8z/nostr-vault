use secrecy::{ExposeSecret, Secret};

#[derive(Debug, Clone)]
pub struct Pin(Secret<String>);

impl AsRef<str> for Pin {
    fn as_ref(&self) -> &str {
        self.0.expose_secret().as_str()
    }
}

//TODO: come up with a better validation
impl Pin {
    pub fn parse(secret: Secret<u64>) -> Result<Pin, String> {
        let s = *secret.expose_secret();
        let pin_str = s.to_string();
        //NOTE: size of allowed pin (need to determine if this is enough digits?)
        if !(100000..=999999).contains(&s) {
            Err(format!("{} is not a valid pin.", s))
        } else {
            Ok(Self(Secret::new(pin_str)))
        }
    }
}
