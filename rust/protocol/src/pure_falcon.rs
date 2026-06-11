// Thin wrapper over pqcrypto_falcon::falconpadded512 for detached signatures.
// Provides simple keypair/sign/verify using byte vectors.

use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

pub struct SecretKey(pub(crate) pqcrypto_falcon::falconpadded512::SecretKey);

pub fn keypair() -> (Vec<u8>, SecretKey) {
    let (pk, sk) = pqcrypto_falcon::falconpadded512::keypair();
    (pk.as_bytes().to_vec(), SecretKey(sk))
}

pub fn sign(sk: &SecretKey, msg: &[u8]) -> Vec<u8> {
    let sig = pqcrypto_falcon::falconpadded512::detached_sign(msg, &sk.0);
    sig.as_bytes().to_vec()
}

pub fn verify_bytes(pk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> bool {
    if let (Ok(pk), Ok(sig)) = (
        pqcrypto_falcon::falconpadded512::PublicKey::from_bytes(pk_bytes),
        pqcrypto_falcon::falconpadded512::DetachedSignature::from_bytes(sig_bytes),
    ) {
        // Verify detached signature against message and public key
        pqcrypto_falcon::falconpadded512::verify_detached_signature(&sig, msg, &pk).is_ok()
    } else {
        false
    }
}
