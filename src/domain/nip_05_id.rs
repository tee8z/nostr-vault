use validator::validate_email;

#[derive(Debug, Clone)]
pub struct Nip05ID(String);

impl Nip05ID {
    pub fn parse(s: String) -> Result<Nip05ID, String> {
        if validate_email(&s) {
            Ok(Self(s))
        } else {
            Err(format!("{} is not a valid nip 05 id", s))
        }
    }
}

impl std::fmt::Display for Nip05ID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl AsRef<str> for Nip05ID {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Nip05ID;
    use claim::assert_err;
    use fake::faker::internet::en::SafeEmail;
    use fake::Fake;

    #[derive(Debug, Clone)]
    struct ValidateEmailFixture(pub String);

    impl quickcheck::Arbitrary for ValidateEmailFixture {
        fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
            let nip05 = SafeEmail().fake_with_rng(g);
            Self(nip05)
        }
    }

    #[quickcheck_macros::quickcheck]
    fn valid_nip05s_are_parsed_successfully(valid_nip05: ValidateEmailFixture) -> bool {
        Nip05ID::parse(valid_nip05.0).is_ok()
    }

    #[test]
    fn empty_string_is_rejected() {
        let nip05 = "".to_string();
        assert_err!(Nip05ID::parse(nip05));
    }

    #[test]
    fn nip05_missing_at_symbol_is_rejected() {
        let nip05 = "ursuladomain.com".to_string();
        assert_err!(Nip05ID::parse(nip05));
    }

    #[test]
    fn nip05_missing_subject_is_rejected() {
        let nip05 = "@domain.com".to_string();
        assert_err!(Nip05ID::parse(nip05));
    }
}
