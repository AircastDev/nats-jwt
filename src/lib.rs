#![warn(missing_docs)]

//! Generate JWTs signed using NKEYs for use with [NATS](https://nats.io)
//!
//! Supports generating account and user JWTs, operator JWTs are not typically generated on the fly
//! and so aren't supported, although a PR adding support would be accepted.
//!
//! ## Example
//!
//! ```
//! use nats_jwt::{KeyPair, Token};
//!
//! // You would probably load the operator's seed via a config and use KeyPair::from_seed
//! let operator_signing_key = KeyPair::new_operator();
//!
//! let account_keypair = KeyPair::new_account();
//! let account_signing_key = KeyPair::new_account();
//! let account_token = Token::new_account(account_keypair.public_key())
//!     .name("My Account")
//!     .add_signing_key(account_signing_key.public_key())
//!     .max_connections(100)
//!     .sign(&operator_signing_key);
//! println!("account_token: {}", account_token);
//!
//! let user_keypair = KeyPair::new_user();
//! let user_key_pub = user_keypair.public_key();
//! let user_token = Token::new_user(account_keypair.public_key(), user_key_pub)
//!     .bearer_token(true)
//!     .name("My User")
//!     .max_subscriptions(10)
//!     .max_payload(1024 * 1024) // 1MiB
//!     .allow_publish("service.hello.world")
//!     .allow_subscribe("_INBOX.>")
//!     .sign(&account_signing_key);
//! println!("user_token: {}", user_token);
//! ```
//!
//! ## License
//!
//! Licensed under either of
//!
//! -   Apache License, Version 2.0
//!     ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
//! -   MIT license
//!     ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)
//!
//! at your option.
//!
//! ## Contribution
//!
//! Unless you explicitly state otherwise, any contribution intentionally submitted
//! for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
//! dual licensed as above, without any additional terms or conditions.

use data_encoding::{BASE32HEX_NOPAD, BASE64URL_NOPAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{convert::TryInto, time::SystemTime};

/// Re-export of `KeyPair` from the nkeys crate.
///
pub use nkeys::KeyPair;

const JWT_HEADER: &str = r#"{"typ":"JWT","alg":"ed25519-nkey"}"#;

/// JWT claims for NATS compatible jwts
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Time when the token was issued in seconds since the unix epoch
    #[serde(rename = "iat")]
    pub issued_at: i64,

    /// Public key of the issuer signing nkey
    #[serde(rename = "iss")]
    pub issuer: String,

    /// Base32 hash of the claims where this is empty
    #[serde(rename = "jti")]
    pub jwt_id: String,

    /// Public key of the account or user the JWT is being issued to
    pub sub: String,

    /// Friendly name
    pub name: String,

    /// NATS claims
    pub nats: NatsClaims,

    /// Time when the token expires (in seconds since the unix epoch)
    #[serde(rename = "exp", skip_serializing_if = "Option::is_none")]
    pub expires: Option<i64>,
}

/// NATS claims describing settings for the user or account
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum NatsClaims {
    /// Claims for NATS users
    User {
        /// Publish and subscribe permissions for the user
        #[serde(flatten)]
        permissions: NatsPermissionsMap,

        /// Public key/id of the account that issued the JWT
        issuer_account: String,

        /// Maximum nuber of subscriptions the user can have
        subs: i64,

        /// Maximum size of the message data the user can send in bytes
        data: i64,

        /// Maximum size of the entire message payload the user can send in bytes
        payload: i64,

        /// If true, the user isn't challenged on connection. Typically used for websocket
        /// connections as the browser won't have/want to have the user's private key.
        bearer_token: bool,

        /// Version of the nats claims object, always 2 in this crate
        version: i64,
    },
    /// Claims for NATS accounts
    Account {
        /// Configuration for the limits for this account
        limits: NatsAccountLimits,

        /// List of signing keys (public key) this account uses
        #[serde(skip_serializing_if = "Vec::is_empty")]
        signing_keys: Vec<String>,

        /// Default publish and subscribe permissions users under this account will have if not
        /// specified otherwise
        default_permissions: NatsPermissionsMap,

        /// Version of the nats claims object, always 2 in this crate
        version: i64,
    },
}

/// List of subjects that are allowed and/or denied
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NatsPermissions {
    /// List of subject patterns that are allowed
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,

    /// List of subject patterns that are denied
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
}

impl NatsPermissions {
    /// Returns `true` if the allow and deny list are both empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }
}

/// Publish and subcribe permissons
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NatsPermissionsMap {
    /// Permissions for which subjects can be published to
    #[serde(rename = "pub", skip_serializing_if = "NatsPermissions::is_empty")]
    pub publish: NatsPermissions,

    /// Permissions for which subjects can be subscribed to
    #[serde(rename = "sub", skip_serializing_if = "NatsPermissions::is_empty")]
    pub subscribe: NatsPermissions,
}

/// Limits on what an account or users in the account can do
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatsAccountLimits {
    /// Maximum nuber of subscriptions the account
    pub subs: i64,

    /// Maximum size of the message data a user can send in bytes
    pub data: i64,

    /// Maximum size of the entire message payload a user can send in bytes
    pub payload: i64,

    /// Maxiumum number of imports for the account
    pub imports: i64,

    /// Maxiumum number of exports for the account
    pub exports: i64,

    /// If true, exports can contain wildcards
    pub wildcards: bool,

    /// Maximum number of active connections
    pub conn: i64,

    /// Maximum number of leaf node connections
    pub leaf: i64,
}

/// Nats claims shared by user and accounts
#[derive(Debug, Clone)]
pub struct CommonNatsClaims {
    /// Maximum number of subscriptions a user can have
    pub max_subscriptions: i64,
    /// Maximum size of the message data a user can send in bytes
    pub max_data: i64,
    /// Maximum size of the entire message payload a user can send in bytes
    pub max_payload: i64,
    /// Permissons for which subjects can be published/subscribed to
    pub permissions: NatsPermissionsMap,
}

/// Consume the input and return a `NatsClaims` struct
///
/// This is used by [`Token::sign`] to get the relevant claims for the token type
pub trait IntoNatsClaims {
    /// Performs the conversion
    fn into_nats_claims(self, common: CommonNatsClaims) -> NatsClaims;
}

/// Consume the input and return a public KKEY
///
/// This is used by [`Token::add_signing_key`] to allow taking either a String, &str, or a &`KeyPair`
pub trait IntoPublicKey {
    /// Performs the conversion
    fn into_public_key(self) -> String;
}

impl IntoPublicKey for &KeyPair {
    fn into_public_key(self) -> String {
        self.public_key()
    }
}

impl IntoPublicKey for String {
    fn into_public_key(self) -> String {
        self
    }
}

impl IntoPublicKey for &str {
    fn into_public_key(self) -> String {
        self.to_string()
    }
}

/// User token type.
///
/// Holds the user specific token configuration
pub struct User {
    bearer_token: bool,
    issuer_account_id: String,
}

impl IntoNatsClaims for User {
    fn into_nats_claims(self, common: CommonNatsClaims) -> NatsClaims {
        NatsClaims::User {
            permissions: common.permissions,
            issuer_account: self.issuer_account_id,
            subs: common.max_subscriptions,
            data: common.max_data,
            payload: common.max_payload,
            bearer_token: self.bearer_token,
            version: 2,
        }
    }
}

/// Account token type.
///
/// Holds the account specific token configuration
pub struct Account {
    signing_keys: Vec<String>,
    max_imports: i64,
    max_exports: i64,
    max_connections: i64,
    max_leaf_nodes: i64,
    allow_wildcards: bool,
}

impl IntoNatsClaims for Account {
    fn into_nats_claims(self, common: CommonNatsClaims) -> NatsClaims {
        NatsClaims::Account {
            default_permissions: common.permissions,
            limits: NatsAccountLimits {
                subs: common.max_subscriptions,
                data: common.max_data,
                payload: common.max_payload,
                imports: self.max_imports,
                exports: self.max_exports,
                wildcards: self.allow_wildcards,
                conn: self.max_connections,
                leaf: self.max_leaf_nodes,
            },
            signing_keys: self.signing_keys,
            version: 2,
        }
    }
}

/// JWT token builder.
///
/// # Example
/// ```
/// # use nats_jwt::{Token, KeyPair};
/// let account_id = "ADP75IYE4WXG23T546A2R3LIRRVBSC52RTJQIHO44CJIQRXSOPLZ5WBJ";
/// let account_signing_key = KeyPair::from_seed("SAAHCUHEQJUYBGWQKN7XUBDCDXKB6C7IQVBZ74DH3T4M2ZNNQOGGECIBDE").unwrap();
/// let user_key = KeyPair::new_user();
/// Token::new_user(account_id, user_key.public_key())
///     .name("My User")
///     .max_subscriptions(10)
///     .max_payload(1024 * 1024) // 1MiB
///     .allow_publish("service.hello.world")
///     .allow_subscribe("_INBOX.>")
///     .sign(&account_signing_key);
/// ```
#[derive(Debug, Clone)]
pub struct Token<T: IntoNatsClaims> {
    kind: T,
    subject: String,
    name: Option<String>,
    nats: CommonNatsClaims,
    expires: Option<i64>,
}

impl<T: IntoNatsClaims> Token<T> {
    fn new(kind: T, subject: String) -> Self {
        Self {
            kind,
            subject,
            name: None,
            nats: CommonNatsClaims {
                max_subscriptions: -1,
                max_payload: -1,
                max_data: -1,
                permissions: NatsPermissionsMap::default(),
            },
            expires: None,
        }
    }

    /// Set the friendly name for the token, can be anything, defaults to the token subject
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the maximum number of subscriptions this token will allow
    #[must_use]
    pub fn max_subscriptions(mut self, max_subscriptions: i64) -> Self {
        self.nats.max_subscriptions = max_subscriptions;
        self
    }

    /// Set the maximum payload size in bytes this token will allow
    #[must_use]
    pub fn max_payload(mut self, max_payload: i64) -> Self {
        self.nats.max_payload = max_payload;
        self
    }

    /// Set the maximum data size in bytes this token will allow
    #[must_use]
    pub fn max_data(mut self, max_data: i64) -> Self {
        self.nats.max_data = max_data;
        self
    }

    /// Allow a subject/pattern to be published to
    #[must_use]
    pub fn allow_publish(mut self, subject: impl Into<String>) -> Self {
        self.nats.permissions.publish.allow.push(subject.into());
        self
    }

    /// Deny a subject/pattern from being published to
    #[must_use]
    pub fn deny_publish(mut self, subject: impl Into<String>) -> Self {
        self.nats.permissions.publish.deny.push(subject.into());
        self
    }

    /// Allow a subject/pattern to be subcribe to
    #[must_use]
    pub fn allow_subscribe(mut self, subject: impl Into<String>) -> Self {
        self.nats.permissions.subscribe.allow.push(subject.into());
        self
    }

    /// Deny a subject/pattern from being subscribed to
    #[must_use]
    pub fn deny_subscribe(mut self, subject: impl Into<String>) -> Self {
        self.nats.permissions.subscribe.deny.push(subject.into());
        self
    }

    /// Set expiration
    #[must_use]
    pub fn expires(mut self, expires: i64) -> Self {
        self.expires = Some(expires);
        self
    }

    /// Sign the token with the given signing key, returning a JWT string.
    ///
    /// If this is a User token, this should be the Account signing key.
    /// If this is an Account token, this should be the Operator key
    ///
    /// # Panics
    ///
    /// - If system time is before UNIX epoch.
    /// - If the seconds from UNIX epoch cannot be represented in a i64.
    pub fn sign(self, signing_key: &KeyPair) -> String {
        let issued_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time is after the unix epoch")
            .as_secs()
            .try_into()
            .expect("seconds from UNIX epoch cannot be represented in a i64");
        let subject = self.subject.clone();
        let mut claims = Claims {
            issued_at,
            issuer: signing_key.public_key(),
            jwt_id: String::new(),
            name: self.name.unwrap_or_else(|| subject.clone()),
            sub: subject,
            nats: self.kind.into_nats_claims(self.nats),
            expires: self.expires,
        };
        let claims_str = serde_json::to_string(&claims).expect("claims serialisation cannot fail");
        let mut hasher = Sha256::new();
        hasher.update(claims_str);
        let claims_hash = hasher.finalize();
        claims.jwt_id = BASE32HEX_NOPAD.encode(claims_hash.as_slice());

        let claims_str = serde_json::to_string(&claims).expect("claims serialisation cannot fail");

        let b64_header = BASE64URL_NOPAD.encode(JWT_HEADER.as_bytes());
        let b64_body = BASE64URL_NOPAD.encode(claims_str.as_bytes());
        let jwt_half = format!("{}.{}", b64_header, b64_body);
        let sig = signing_key.sign(jwt_half.as_bytes()).unwrap();
        let b64_sig = BASE64URL_NOPAD.encode(&sig);

        format!("{}.{}", jwt_half, b64_sig)
    }
}

impl Token<User> {
    /// Start building a new user token.
    ///
    /// `issuer_account_id` is the public key of the Account that will issue this token. This is
    /// not the signing key's public key.
    ///
    /// `user_key_pub` is the public key of the User for which the token is being issued.
    pub fn new_user(issuer_account_id: impl Into<String>, user_key_pub: impl Into<String>) -> Self {
        Self::new(
            User {
                bearer_token: false,
                issuer_account_id: issuer_account_id.into(),
            },
            user_key_pub.into(),
        )
    }

    /// If true, the user isn't challenged on connection. Typically used for websocket
    /// connections as the browser won't have/want to have the user's private key.
    #[must_use]
    pub fn bearer_token(mut self, bearer_token: bool) -> Self {
        self.kind.bearer_token = bearer_token;
        self
    }
}

impl Token<Account> {
    /// Start building a new account token.
    ///
    /// `account_key_pub` is the public key of the Account for which the token is being issued.
    pub fn new_account(account_key_pub: impl Into<String>) -> Self {
        Self::new(
            Account {
                signing_keys: vec![],
                max_imports: -1,
                max_exports: -1,
                max_connections: -1,
                max_leaf_nodes: -1,
                allow_wildcards: true,
            },
            account_key_pub.into(),
        )
    }

    /// Add a signing key to the token. Takes anything that implements `IntoPublicKey`. This is
    /// implemented for `String`, `&str`, and [`&KeyPair`](nkeys::KeyPair)
    #[must_use]
    pub fn add_signing_key(mut self, signing_key: impl IntoPublicKey) -> Self {
        self.kind.signing_keys.push(signing_key.into_public_key());
        self
    }

    /// Set the maximum number of imports this account can have.
    #[must_use]
    pub fn max_imports(mut self, max_imports: i64) -> Self {
        self.kind.max_imports = max_imports;
        self
    }

    /// Set the maximum number of exports this account can have.
    #[must_use]
    pub fn max_exports(mut self, max_exports: i64) -> Self {
        self.kind.max_exports = max_exports;
        self
    }

    /// Set the maximum number of connections this account can have.
    #[must_use]
    pub fn max_connections(mut self, max_connections: i64) -> Self {
        self.kind.max_connections = max_connections;
        self
    }

    /// Set the maximum number of leaf nodes this account can have.
    #[must_use]
    pub fn max_leaf_nodes(mut self, max_leaf_nodes: i64) -> Self {
        self.kind.max_leaf_nodes = max_leaf_nodes;
        self
    }

    /// Allow exports to contain wildcards
    #[must_use]
    pub fn allow_wildcards(mut self, allow_wildcards: bool) -> Self {
        self.kind.allow_wildcards = allow_wildcards;
        self
    }
}
