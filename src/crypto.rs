use rand::{
    rngs::{OsRng},
    TryRngCore
};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce, Key
};
use zeroize::{Zeroize, Zeroizing};
use libcold;

use crate::consts;
use crate::error::Error;


// We couldn't use libcold's chacha20 implementation because a nonce collision is likely with many
// reads / writes in a filesystem context.
/// Encrypts plaintext with xChaCha20Poly1305, adding random padding and (optionally) using a random nonce.
///
/// Returns `(ciphertext, nonce)`.
pub fn encrypt_xchacha20poly1305(key_bytes: &Zeroizing<Vec<u8>>, plaintext: &[u8], nonce_bytes: Option<&[u8]>, max_padding: usize) -> Result<(Vec<u8>, XNonce), Error> {
    if key_bytes.len() != 32 {
        return Err(Error::InvalidXChaCha20KeyLength);
    }

    let key = Key::from_slice(key_bytes);

    // Check max_padding limits
    if max_padding > (2_usize.pow((consts::XCHACHA20POLY1305_SIZE_LEN * 8) as u32) - 1) {
        return Err(Error::InvalidXChaCha20PaddingLength);
    }


    // Generate nonce if not provided
    let nonce: XNonce = match nonce_bytes {
        Some(bytes) => {
            if bytes.len() != consts::XCHACHA20POLY1305_NONCE_SIZE {
                return Err(Error::InvalidXChaCha20NonceLength);
            }

            *XNonce::from_slice(bytes)
        },
        None => {
            // generate random nonce
            let nonce_bytes = libcold::crypto::generate_secure_random_bytes_whiten(consts::XCHACHA20POLY1305_NONCE_SIZE)
                .map_err(|_| Error::FailedToGenerateSecureRandomBytes)?;

            *XNonce::from_slice(nonce_bytes.as_slice())
        }
    };


    let padding_len = if max_padding > 0 {
        rand::random_range(0..=max_padding)
    } else {
        0
    };


    let padding = libcold::crypto::generate_secure_random_bytes(padding_len)
        .map_err(|_| Error::FailedToGenerateSecureRandomBytes)?;


    // Prepend padding length and append padding
    let mut padded_plaintext = Vec::with_capacity(consts::XCHACHA20POLY1305_SIZE_LEN + plaintext.len() + padding_len);
    padded_plaintext.extend_from_slice(&(padding_len as u16).to_be_bytes());
    padded_plaintext.extend_from_slice(plaintext);
    padded_plaintext.extend_from_slice(&padding);

    // Encrypt
    let cipher = XChaCha20Poly1305::new(key);
    let ciphertext = cipher.encrypt(&nonce, padded_plaintext.as_ref())
        .map_err(|_| Error::XChaCha20EncryptionFailed)?;

    Ok((ciphertext, nonce))
}

pub fn decrypt_xchacha20poly1305(key_bytes: &Zeroizing<Vec<u8>>, nonce_bytes: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if key_bytes.len() != 32 {
        return Err(Error::InvalidXChaCha20KeyLength);
    }

    if nonce_bytes.len() != consts::XCHACHA20POLY1305_NONCE_SIZE {
        return Err(Error::InvalidXChaCha20NonceLength);
    }

    let key = Key::from_slice(key_bytes);
    let nonce = XNonce::from_slice(nonce_bytes);

    let cipher = XChaCha20Poly1305::new(key);

    // Decrypt ciphertext
    let padded_plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| Error::XChaCha20DecryptionFailed)?;

    // Ensure we have enough bytes for padding length
    if padded_plaintext.len() < consts::XCHACHA20POLY1305_SIZE_LEN {
        return Err(Error::XChaCha20MalformedPadding);
    }

    // Read padding length
    let padding_length = u16::from_be_bytes([
        padded_plaintext[0],
        padded_plaintext[1],
    ]) as usize;

    if padding_length > padded_plaintext.len() - consts::XCHACHA20POLY1305_SIZE_LEN {
        return Err(Error::XChaCha20MalformedPadding);
    }

    // Strip padding and return plaintext
    let plaintext = padded_plaintext[..padded_plaintext.len() - padding_length]
        [consts::XCHACHA20POLY1305_SIZE_LEN..]
        .to_vec();

    Ok(Zeroizing::new(plaintext))
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

     #[test]
    fn test_encrypt_decrypt_roundtrip_no_padding() {
        let key = libcold::crypto::generate_secure_random_bytes(32).unwrap();
        let plaintext = b"Hello world!";
        let (ct, nonce) = encrypt_xchacha20poly1305(&key, plaintext, None, 0).unwrap();
        assert_ne!(ct, nonce.as_slice(), "Ciphertext and nonce are equal");
        assert_ne!(ct, plaintext, "Ciphertext and plaintext are equal");
        assert_ne!(nonce.as_slice(), plaintext, "Nonce and plaintext are equal");
        assert_ne!(ct, key.as_slice(), "Ciphertext and key are equal");
        assert_ne!(nonce.as_slice(), key.as_slice(), "Nonce and key are equal");

        let pt = decrypt_xchacha20poly1305(&key, &nonce, &ct).unwrap();
        assert_eq!(pt.as_slice(), plaintext, "Decrypted ciphertext is not equal to plaintext");

        for i in 0..ct.len() {
            let mut tampered = ct.clone();
            tampered[i] ^= 0xFF;

            // Decryption should fail
            assert!(
                decrypt_xchacha20poly1305(&key, &nonce, &tampered).is_err(),
                "Tampered ciphertext at byte {} decrypted successfully — integrity check failed",
                i
            );
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_with_padding() {
        let key = libcold::crypto::generate_secure_random_bytes(32).unwrap();
        let plaintext = b"Hello world!";
        let (ct, nonce) = encrypt_xchacha20poly1305(&key, plaintext, None, 60).unwrap();
        assert_ne!(ct, nonce.as_slice(), "Ciphertext and nonce are equal");
        assert_ne!(ct, plaintext, "Ciphertext and plaintext are equal");
        assert_ne!(nonce.as_slice(), plaintext, "Nonce and plaintext are equal");
        assert_ne!(ct, key.as_slice(), "Ciphertext and key are equal");
        assert_ne!(nonce.as_slice(), key.as_slice(), "Nonce and key are equal");

        let pt = decrypt_xchacha20poly1305(&key, &nonce, &ct).unwrap();
        assert_eq!(pt.as_slice(), plaintext, "Decrypted ciphertext is not equal to plaintext");


        for i in 0..ct.len() {
            let mut tampered = ct.clone();
            tampered[i] ^= 0xFF;

            // Decryption should fail
            assert!(
                decrypt_xchacha20poly1305(&key, &nonce, &tampered).is_err(),
                "Tampered ciphertext at byte {} decrypted successfully — integrity check failed",
                i
            );
        }
    }


    #[test]
    fn test_encrypt_invalid_nonce() {
        let key = libcold::crypto::generate_secure_random_bytes(32).unwrap();
        let plaintext = b"Hello world!";

        // Too short
        let short_nonce = libcold::crypto::generate_secure_random_bytes(consts::XCHACHA20POLY1305_NONCE_SIZE - 1).unwrap();
        let err = encrypt_xchacha20poly1305(&key, plaintext, Some(short_nonce.as_slice()), 0).unwrap_err();
        assert!(matches!(err, Error::InvalidXChaCha20NonceLength));

        // Too long
        let long_nonce = libcold::crypto::generate_secure_random_bytes(consts::XCHACHA20POLY1305_NONCE_SIZE + 1).unwrap();
        let err = encrypt_xchacha20poly1305(&key, plaintext, Some(long_nonce.as_slice()), 0).unwrap_err();
        assert!(matches!(err, Error::InvalidXChaCha20NonceLength));
    }



    #[test]
    fn test_encrypt_nonce_behaviour_no_padding() {
        let key = libcold::crypto::generate_secure_random_bytes(32).unwrap();
        let our_nonce = libcold::crypto::generate_secure_random_bytes(consts::XCHACHA20POLY1305_NONCE_SIZE).unwrap();
        let plaintext = b"Hello world!";
        let (_, nonce_1) = encrypt_xchacha20poly1305(&key, plaintext, Some(our_nonce.as_slice()), 0).unwrap();

        assert_eq!(nonce_1.as_slice(), our_nonce.as_slice(), "Nonce returned by function does not match nonce we supplied.");

        let (_, nonce_2) = encrypt_xchacha20poly1305(&key, plaintext, None, 0).unwrap();

        assert_ne!(nonce_2.as_slice(), our_nonce.as_slice(), "Nonce returned by function somehow matches our_nonce??");
        assert_ne!(nonce_2.as_slice(), nonce_1.as_slice(), "Nonce returned by function equals to nonce_1. Hardcoded nonce?");

    }

    #[test]
    fn test_encrypt_nonce_behaviour_with_padding() {
        let key = libcold::crypto::generate_secure_random_bytes(32).unwrap();
        let our_nonce = libcold::crypto::generate_secure_random_bytes(consts::XCHACHA20POLY1305_NONCE_SIZE).unwrap();
        let plaintext = b"Hello world!";
        let (_, nonce_1) = encrypt_xchacha20poly1305(&key, plaintext, Some(our_nonce.as_slice()), 60).unwrap();

        assert_eq!(nonce_1.as_slice(), our_nonce.as_slice(), "Nonce returned by function does not match nonce we supplied.");

        let (_, nonce_2) = encrypt_xchacha20poly1305(&key, plaintext, None, 60).unwrap();

        assert_ne!(nonce_2.as_slice(), our_nonce.as_slice(), "Nonce returned by function somehow matches our_nonce??");
        assert_ne!(nonce_2.as_slice(), nonce_1.as_slice(), "Nonce returned by function equals to nonce_1. Hardcoded nonce?");

    }

}
