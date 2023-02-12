# pre-reqs to run
* install rust
    - https://www.rust-lang.org/tools/install
* install docker
    - https://docs.docker.com/engine/install/
* install sqlx cli
    - `cargo install sqlx-cli --no-default-features --features rustls,postgres`
* rename `example.env` to `.env`

# how to startup locally
* `./scripts/init_db.sh`
* `cargo run`
* click on the url that prints in the console to view the swagger docs

# dev tools pre-reqs
* `rustup toolchain install stable`
* `rustup component add clippy`
* `rustup component add rustfmt`
* `cargo fmt`
* `cargo clippy`

# To run code coverage locally
* `cargo install cargo-tarpaulin`
* `cargo tarpaulin --all --ignore-tests --ignore-config`

# To run code audit locally
* `cargo install cargo-audit`
* `cargo cargo-audit`

# To turn on trace logs when running tests
* `TEST_LOG=trace cargo test`