# nostr-vault
Simple server to store private keys and to be used for logins from nostr clients



# pre-reqs to run
* install rust
* install docker
* install sqlx cli
    - `cargo install sqlx-cli --no-default-features --features rustls,postgres`

# dev tools pre-reqs
* install nix
    - https://nixos.org/download.html
* `cargo install cargo-audit`
* `cargo install cargo-tarpaulin`
* `rustup toolchain install nightly`
* `rustup component add clippy`
* `rustup component add rustfmt`
* `cargo fmt`
* `cargo clippy`
* `cargo audit`
* `cargo tarpaulin --all`