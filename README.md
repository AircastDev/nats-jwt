# NATS JWT (Rust)

![Crates.io](https://img.shields.io/crates/l/nats-jwt)
[![Crates.io](https://img.shields.io/crates/v/nats-jwt)](https://crates.io/crates/nats-jwt)
[![Docs.rs](https://docs.rs/nats-jwt/badge.svg)](https://docs.rs/nats-jwt)

<!-- cargo-sync-readme start -->

Generate JWTs signed using NKEYs for use with [NATS](https://nats.io)

Supports generating account and user JWTs, operator JWTs are not typically generated on the fly
and so aren't supported, although a PR adding support would be accepted.

## Example

```rust
use nats_jwt::{KeyPair, Token};

// You would probably load the operator's seed via a config and use KeyPair::from_seed
let operator_signing_key = KeyPair::new_operator();

let account_keypair = KeyPair::new_account();
let account_signing_key = KeyPair::new_account();
let account_token = Token::new_account(account_keypair.public_key())
    .name("My Account")
    .add_signing_key(account_signing_key.public_key())
    .max_connections(100)
    .sign(&operator_signing_key);
println!("account_token: {}", account_token);

let user_keypair = KeyPair::new_user();
let user_key_pub = user_keypair.public_key();
let user_token = Token::new_user(account_keypair.public_key(), user_key_pub)
    .bearer_token(true)
    .name("My User")
    .max_subscriptions(10)
    .max_payload(1024 * 1024) // 1MiB
    .allow_publish("service.hello.world")
    .allow_subscribe("_INBOX.>")
    .sign(&account_signing_key);
println!("user_token: {}", user_token);
```

## License

Licensed under either of

-   Apache License, Version 2.0
    ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
-   MIT license
    ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

<!-- cargo-sync-readme end -->
