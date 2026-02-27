pub const DEFAULT_PROXY_ADDR: &str = "127.0.0.1:9050";

/// Must be always 16 bytes for interoperability with implementations that use libsodium.
pub const ARGON2ID_SALT_SIZE: usize = 16;



/// Nonce size for XChaCha20Poly1305 (24 bytes)
pub const XCHACHA20POLY1305_NONCE_SIZE: usize = 24;

pub const XCHACHA20POLY1305_SIZE_LEN: usize = 2;

/// Default maximum random padding
pub const XCHACHA20POLY1305_MAX_RANDOM_PAD: usize = 64;
