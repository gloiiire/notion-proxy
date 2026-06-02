use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub const TIMESTAMP_WINDOW_SECS: i64 = 300;

#[derive(Debug, PartialEq)]
pub enum SignatureError {
    InvalidTimestamp,
    OutOfWindow,
    InvalidSignature,
}

pub fn verify(
    secret: &[u8],
    timestamp: &str,
    nonce: &str,
    signature: &[u8],
    body: &[u8],
    now_unix: i64,
) -> Result<(), SignatureError> {
    let ts: i64 = timestamp
        .parse()
        .map_err(|_| SignatureError::InvalidTimestamp)?;

    if (now_unix - ts).abs() > TIMESTAMP_WINDOW_SECS {
        return Err(SignatureError::OutOfWindow);
    }

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(timestamp.as_bytes());
    mac.update(b"\n");
    mac.update(nonce.as_bytes());
    mac.update(b"\n");
    mac.update(body);

    mac.verify_slice(signature)
        .map_err(|_| SignatureError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign(secret: &[u8], ts: &str, nonce: &str, body: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(ts.as_bytes());
        mac.update(b"\n");
        mac.update(nonce.as_bytes());
        mac.update(b"\n");
        mac.update(body);
        mac.finalize().into_bytes().to_vec()
    }

    #[test]
    fn accepts_valid_signature() {
        let secret = b"secret";
        let sig = sign(secret, "100", "n", b"body");
        assert_eq!(verify(secret, "100", "n", &sig, b"body", 100), Ok(()));
    }

    #[test]
    fn rejects_tampered_body() {
        let secret = b"secret";
        let sig = sign(secret, "100", "n", b"original");
        assert_eq!(
            verify(secret, "100", "n", &sig, b"tampered", 100),
            Err(SignatureError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_wrong_secret() {
        let sig = sign(b"good", "100", "n", b"body");
        assert_eq!(
            verify(b"bad", "100", "n", &sig, b"body", 100),
            Err(SignatureError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_expired_timestamp() {
        let secret = b"secret";
        let sig = sign(secret, "100", "n", b"body");
        assert_eq!(
            verify(secret, "100", "n", &sig, b"body", 100 + TIMESTAMP_WINDOW_SECS + 1),
            Err(SignatureError::OutOfWindow)
        );
    }

    #[test]
    fn rejects_future_timestamp() {
        let secret = b"secret";
        let sig = sign(secret, "1000", "n", b"body");
        assert_eq!(
            verify(secret, "1000", "n", &sig, b"body", 1000 - TIMESTAMP_WINDOW_SECS - 1),
            Err(SignatureError::OutOfWindow)
        );
    }

    #[test]
    fn accepts_timestamp_at_window_boundary() {
        let secret = b"secret";
        let sig = sign(secret, "100", "n", b"body");
        assert_eq!(
            verify(secret, "100", "n", &sig, b"body", 100 + TIMESTAMP_WINDOW_SECS),
            Ok(())
        );
    }

    #[test]
    fn rejects_malformed_timestamp() {
        assert_eq!(
            verify(b"secret", "not-a-number", "n", b"", b"", 100),
            Err(SignatureError::InvalidTimestamp)
        );
    }

    #[test]
    fn rejects_nonce_substitution() {
        // Nonce is part of the signed payload — swapping it must break verification.
        let secret = b"secret";
        let sig = sign(secret, "100", "nonce-a", b"body");
        assert_eq!(
            verify(secret, "100", "nonce-b", &sig, b"body", 100),
            Err(SignatureError::InvalidSignature)
        );
    }
}
