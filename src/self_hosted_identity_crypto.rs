use crate::{Result, fail};
use sha2::{Digest, Sha256};
use std::{ffi::{c_int, c_void}, ptr::{self, NonNull}};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[link(name = "libcrypto.so.3", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    fn EC_KEY_new_by_curve_name(nid: c_int) -> *mut c_void;
    fn EC_KEY_generate_key(key: *mut c_void) -> c_int;
    fn EC_KEY_get0_private_key(key: *const c_void) -> *const c_void;
    fn EC_KEY_get0_public_key(key: *const c_void) -> *const c_void;
    fn EC_KEY_get0_group(key: *const c_void) -> *const c_void;
    fn EC_POINT_point2oct(group: *const c_void, point: *const c_void, form: c_int,
        bytes: *mut u8, len: usize, context: *mut c_void) -> usize;
    fn EC_KEY_oct2priv(key: *mut c_void, bytes: *const u8, len: usize) -> c_int;
    fn EC_KEY_oct2key(key: *mut c_void, bytes: *const u8, len: usize, context: *mut c_void) -> c_int;
    fn EC_KEY_check_key(key: *const c_void) -> c_int;
    fn EC_KEY_free(key: *mut c_void);
    fn ECDSA_do_sign(digest: *const u8, len: c_int, key: *mut c_void) -> *mut c_void;
    fn ECDSA_SIG_get0(signature: *const c_void, r: *mut *const c_void, s: *mut *const c_void);
    fn ECDSA_SIG_free(signature: *mut c_void);
    fn ECDSA_verify(kind: c_int, digest: *const u8, len: c_int, signature: *const u8, sig_len: c_int, key: *mut c_void) -> c_int;
    fn d2i_RSA_PUBKEY(key: *mut *mut c_void, input: *mut *const u8, len: libc::c_long) -> *mut c_void;
    fn RSA_free(key: *mut c_void);
    fn RSA_verify(kind: c_int, digest: *const u8, len: libc::c_uint, signature: *const u8, sig_len: libc::c_uint, key: *mut c_void) -> c_int;
    fn BN_bn2binpad(number: *const c_void, bytes: *mut u8, len: c_int) -> c_int;
    fn EVP_PBE_scrypt(password: *const u8, password_len: usize, salt: *const u8, salt_len: usize,
        cost: u64, block_size: u64, parallelization: u64, max_memory: u64, output: *mut u8, output_len: usize) -> c_int;
}

struct EcKey(NonNull<c_void>);

impl EcKey {
    fn p256() -> Result<Self> {
        const PRIME256V1: c_int = 415;
        NonNull::new(unsafe { EC_KEY_new_by_curve_name(PRIME256V1) }).map(Self)
            .ok_or_else(|| fail("Cannot allocate the P-256 key"))
    }
}

impl Drop for EcKey {
    fn drop(&mut self) { unsafe { EC_KEY_free(self.0.as_ptr()) } }
}

struct Signature(NonNull<c_void>);

impl Drop for Signature {
    fn drop(&mut self) { unsafe { ECDSA_SIG_free(self.0.as_ptr()) } }
}

fn der(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    match bytes.len() {
        0..=127 => result.push(bytes.len() as u8),
        128..=255 => result.extend([0x81, bytes.len() as u8]),
        length => result.extend([0x82, (length >> 8) as u8, length as u8]),
    }
    result.extend_from_slice(bytes);
    result
}

fn der_integer(bytes: &[u8]) -> Vec<u8> {
    let significant = bytes.iter().position(|byte| *byte != 0).map_or(&[0][..], |start| &bytes[start..]);
    if significant[0] & 0x80 == 0 { return der(2, significant); }
    let mut positive = vec![0];
    positive.extend_from_slice(significant);
    der(2, &positive)
}

pub(super) fn verify_oidc_rsa(modulus: &[u8], exponent: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    // Bound public-key work before handing the DER record to OpenSSL.
    if modulus.is_empty() || modulus.len() > 2048 || exponent.is_empty() || exponent.len() > 8
        || modulus.iter().all(|byte| *byte == 0) || exponent.iter().all(|byte| *byte == 0) {
        return Err(fail("Invalid RSA public key"));
    }
    let key = der(0x30, &[der_integer(modulus), der_integer(exponent)].concat());
    let bit_string = der(3, &[vec![0], key].concat());
    let rsa_identifier = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
    let public_key = der(0x30, &[&rsa_identifier[..], &bit_string].concat());
    let mut cursor = public_key.as_ptr();
    let key = NonNull::new(unsafe { d2i_RSA_PUBKEY(ptr::null_mut(), &mut cursor, public_key.len() as libc::c_long) })
        .ok_or_else(|| fail("Invalid RSA public key"))?;
    let digest = Sha256::digest(message);
    const NID_SHA256: c_int = 672;
    let verified = unsafe {
        let matched = RSA_verify(NID_SHA256, digest.as_ptr(), 32, signature.as_ptr(),
            signature.len() as libc::c_uint, key.as_ptr()) == 1;
        RSA_free(key.as_ptr());
        matched
    };
    Ok(verified)
}

pub(super) fn verify_oidc_p256(x: &[u8], y: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    if x.len() != 32 || y.len() != 32 { return Err(fail("Invalid P-256 public key")); }
    let point = [&[4][..], x, y].concat();
    let key = EcKey::p256()?;
    let pointer = key.0.as_ptr();
    if unsafe { EC_KEY_oct2key(pointer, point.as_ptr(), point.len(), ptr::null_mut()) != 1 || EC_KEY_check_key(pointer) != 1 } {
        return Err(fail("Invalid P-256 public key"));
    }
    if signature.len() != 64 { return Ok(false); }
    let signature = der(0x30, &[der_integer(&signature[..32]), der_integer(&signature[32..])].concat());
    let digest = Sha256::digest(message);
    Ok(unsafe { ECDSA_verify(0, digest.as_ptr(), 32, signature.as_ptr(), signature.len() as c_int, pointer) == 1 })
}

pub(super) struct SigningKey {
    scalar: Zeroizing<[u8; 32]>,
    point: [u8; 65],
}

impl SigningKey {
    pub(super) fn generate() -> Result<Self> {
        let key = EcKey::p256()?;
        let pointer = key.0.as_ptr();
        let mut scalar = Zeroizing::new([0; 32]);
        let mut point = [0; 65];
        unsafe {
            if EC_KEY_generate_key(pointer) != 1 || EC_KEY_check_key(pointer) != 1 {
                return Err(fail("Cannot generate a P-256 signing key"));
            }
            let private = EC_KEY_get0_private_key(pointer);
            let group = EC_KEY_get0_group(pointer);
            let public = EC_KEY_get0_public_key(pointer);
            if private.is_null() || group.is_null() || public.is_null()
                || BN_bn2binpad(private, scalar.as_mut_ptr(), 32) != 32
                || EC_POINT_point2oct(group, public, 4, point.as_mut_ptr(), point.len(), ptr::null_mut()) != point.len() {
                return Err(fail("Cannot encode the P-256 signing key"));
            }
        }
        Ok(Self { scalar, point })
    }

    pub(super) fn private_parts(&self) -> (&[u8; 32], &[u8], &[u8]) {
        (&self.scalar, &self.point[1..33], &self.point[33..])
    }

    pub(super) fn new(scalar: Zeroizing<[u8; 32]>, x: [u8; 32], y: [u8; 32]) -> Result<Self> {
        let mut point = [0; 65];
        point[0] = 4;
        point[1..33].copy_from_slice(&x);
        point[33..].copy_from_slice(&y);
        let key = Self { scalar, point };
        key.open()?;
        Ok(key)
    }

    fn open(&self) -> Result<EcKey> {
        let key = EcKey::p256()?;
        let key_ptr = key.0.as_ptr();
        if unsafe { EC_KEY_oct2priv(key_ptr, self.scalar.as_ptr(), self.scalar.len()) != 1
            || EC_KEY_oct2key(key_ptr, self.point.as_ptr(), self.point.len(), ptr::null_mut()) != 1
            || EC_KEY_check_key(key_ptr) != 1 } {
            return Err(fail("Invalid P-256 private JWK"));
        }
        Ok(key)
    }

    pub(super) fn sign(&self, input: &[u8]) -> Result<[u8; 64]> {
        let digest = Sha256::digest(input);
        let key = self.open()?;
        let signature = Signature(NonNull::new(unsafe { ECDSA_do_sign(digest.as_ptr(), 32, key.0.as_ptr()) })
            .ok_or_else(|| fail("Cannot sign the ES256 assertion"))?);
        let (mut r, mut s) = (ptr::null(), ptr::null());
        let mut bytes = [0; 64];
        unsafe {
            ECDSA_SIG_get0(signature.0.as_ptr(), &mut r, &mut s);
            if r.is_null() || s.is_null() || BN_bn2binpad(r, bytes[..32].as_mut_ptr(), 32) != 32
                || BN_bn2binpad(s, bytes[32..].as_mut_ptr(), 32) != 32 {
                return Err(fail("Cannot encode the ES256 assertion signature"));
            }
        }
        Ok(bytes)
    }
}

pub(super) struct PasswordRecord {
    pub(super) salt: Vec<u8>,
    pub(super) digest: Zeroizing<Vec<u8>>,
    pub(super) cost: u64,
    pub(super) block_size: u64,
    pub(super) parallelization: u64,
}

impl PasswordRecord {
    pub(super) fn matches(&self, password: &[u8]) -> Result<bool> {
        let candidate = derive_password(password, &self.salt, self.cost, self.block_size, self.parallelization, self.digest.len())?;
        Ok(bool::from(candidate.as_slice().ct_eq(self.digest.as_slice())))
    }
}

pub(super) fn derive_password(password: &[u8], salt: &[u8], cost: u64, block_size: u64, parallelization: u64,
    output_length: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut candidate = Zeroizing::new(vec![0; output_length]);
    let memory_limit = (256 * cost * block_size).max(64 * 1024 * 1024);
    if unsafe { EVP_PBE_scrypt(password.as_ptr(), password.len(), salt.as_ptr(), salt.len(), cost, block_size,
        parallelization, memory_limit, candidate.as_mut_ptr(), candidate.len()) } != 1 {
        return Err(fail("Cannot derive the operator password verifier"));
    }
    Ok(candidate)
}
