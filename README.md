# nostr-vault
Simple server to store private keys and to be used for logins from nostr clients



# pre-reqs to run
* install rust
* install docker
* install sqlx cli
    - `cargo install sqlx-cli --no-default-features --features rustls,postgres`

# dev tools pre-reqs
* `rustup toolchain install nightly`
* `rustup component add clippy`
* `rustup component add rustfmt`
* `cargo fmt`
* `cargo clippy`