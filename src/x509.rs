// Typed OpenSSL bindings for the managed certificate operations.
use crate::{Result, fail, rel};
use base64ct::{Base64, Encoding};
use serde_json::{Value, json};
use std::{ffi::{CStr, c_char, c_int, c_long, c_ulong, c_void}, ptr::{self, NonNull}};

#[link(name = "libcrypto.so.3", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    fn d2i_X509(target: *mut *mut c_void, data: *mut *const u8, length: c_long) -> *mut c_void;
    fn X509_free(cert: *mut c_void);
    fn X509_check_ca(cert: *mut c_void) -> c_int;
    fn X509_check_issued(issuer: *mut c_void, leaf: *mut c_void) -> c_int;
    fn X509_verify(cert: *mut c_void, key: *mut c_void) -> c_int;
    fn X509_get0_pubkey(cert: *mut c_void) -> *mut c_void;
    fn EVP_PKEY_get0_type_name(key: *const c_void) -> *const c_char;
    fn i2d_PUBKEY(key: *const c_void, output: *mut *mut u8) -> c_int;
    fn X509_get_subject_name(cert: *const c_void) -> *mut c_void;
    fn X509_get0_serialNumber(cert: *const c_void) -> *const c_void;
    fn X509_get0_notAfter(cert: *const c_void) -> *const c_void;
    fn X509_get0_notBefore(cert: *const c_void) -> *const c_void;
    fn X509_NAME_print_ex(bio: *mut c_void, name: *const c_void, indent: c_int, flags: c_ulong) -> c_int;
    fn BIO_s_mem() -> *const c_void;
    fn BIO_new(method: *const c_void) -> *mut c_void;
    fn BIO_ctrl_pending(bio: *mut c_void) -> usize;
    fn BIO_read(bio: *mut c_void, buffer: *mut u8, length: c_int) -> c_int;
    fn BIO_free(bio: *mut c_void) -> c_int;
    fn ASN1_INTEGER_to_BN(integer: *const c_void, target: *mut c_void) -> *mut c_void;
    fn BN_bn2hex(number: *const c_void) -> *mut c_char;
    fn BN_free(number: *mut c_void);
    fn CRYPTO_free(address: *mut c_void, file: *const c_char, line: c_int);
    fn ASN1_TIME_to_tm(time: *const c_void, result: *mut libc::tm) -> c_int;
    fn X509_new() -> *mut c_void;
    fn X509_set_version(cert: *mut c_void, version: c_long) -> c_int;
    fn X509_set_subject_name(cert: *mut c_void, name: *const c_void) -> c_int;
    fn X509_set_issuer_name(cert: *mut c_void, name: *const c_void) -> c_int;
    fn X509_set_pubkey(cert: *mut c_void, key: *mut c_void) -> c_int;
    fn X509_getm_notBefore(cert: *const c_void) -> *mut c_void;
    fn X509_getm_notAfter(cert: *const c_void) -> *mut c_void;
    fn ASN1_TIME_set(time: *mut c_void, unix_time: libc::time_t) -> *mut c_void;
    fn X509_get_serialNumber(cert: *mut c_void) -> *mut c_void;
    fn BN_bin2bn(bytes: *const u8, length: c_int, target: *mut c_void) -> *mut c_void;
    fn BN_to_ASN1_INTEGER(number: *const c_void, target: *mut c_void) -> *mut c_void;
    fn X509_check_private_key(cert: *const c_void, key: *const c_void) -> c_int;
    fn X509_sign(cert: *mut c_void, key: *mut c_void, digest: *const c_void) -> c_int;
    fn EVP_sha256() -> *const c_void;
    fn EVP_PKEY_free(key: *mut c_void);
    fn BIO_new_mem_buf(bytes: *const c_void, length: c_int) -> *mut c_void;
    fn PEM_read_bio_PrivateKey(bio: *mut c_void, key: *mut *mut c_void,
        password: Option<extern "C" fn(*mut c_char, c_int, c_int, *mut c_void) -> c_int>, context: *mut c_void) -> *mut c_void;
    fn PEM_write_bio_X509(bio: *mut c_void, certificate: *mut c_void) -> c_int;
    fn i2d_X509(cert: *const c_void, output: *mut *mut u8) -> c_int;
    fn OBJ_txt2nid(name: *const c_char) -> c_int;
    fn X509V3_EXT_conf_nid(conf: *mut c_void, context: *mut c_void, nid: c_int, value: *const c_char) -> *mut c_void;
    fn X509_add_ext(cert: *mut c_void, extension: *mut c_void, position: c_int) -> c_int;
    fn X509_EXTENSION_free(extension: *mut c_void);
    fn X509_STORE_new() -> *mut c_void;
    fn X509_STORE_free(store: *mut c_void);
    fn X509_STORE_add_cert(store: *mut c_void, cert: *mut c_void) -> c_int;
    fn X509_STORE_CTX_new() -> *mut c_void;
    fn X509_STORE_CTX_free(context: *mut c_void);
    fn X509_STORE_CTX_init(context: *mut c_void, store: *mut c_void, cert: *mut c_void, chain: *mut c_void) -> c_int;
    fn X509_STORE_CTX_set_purpose(context: *mut c_void, purpose: c_int) -> c_int;
    fn X509_STORE_CTX_get0_param(context: *mut c_void) -> *mut c_void;
    fn X509_VERIFY_PARAM_set1_host(param: *mut c_void, host: *const c_char, length: usize) -> c_int;
    fn X509_verify_cert(context: *mut c_void) -> c_int;
}

pub(crate) struct Certificate {
    cert: NonNull<c_void>,
    fingerprint: String,
}

impl Drop for Certificate {
    fn drop(&mut self) { unsafe { X509_free(self.cert.as_ptr()); } }
}

struct Bio(NonNull<c_void>);
impl Drop for Bio {
    fn drop(&mut self) { unsafe { BIO_free(self.0.as_ptr()); } }
}

pub(crate) struct PrivateKey(NonNull<c_void>);
impl Drop for PrivateKey {
    fn drop(&mut self) { unsafe { EVP_PKEY_free(self.0.as_ptr()) } }
}

impl PrivateKey {
    pub(crate) fn from_pem(pem: &[u8]) -> Result<Self> {
        extern "C" fn no_password(_: *mut c_char, _: c_int, _: c_int, _: *mut c_void) -> c_int { 0 }
        let bio = Bio(NonNull::new(unsafe { BIO_new_mem_buf(pem.as_ptr().cast(), pem.len().try_into()?) })
            .ok_or_else(|| fail("Cannot allocate managed key buffer"))?);
        NonNull::new(unsafe { PEM_read_bio_PrivateKey(bio.0.as_ptr(), ptr::null_mut(), Some(no_password), ptr::null_mut()) })
            .map(Self).ok_or_else(|| fail("Invalid managed private key"))
    }

    pub(crate) fn as_ptr(&self) -> *mut c_void { self.0.as_ptr() }
}

pub(crate) enum LeafUse<'a> {
    Desktop,
    Server { dns: &'a CStr, host: &'a CStr },
}

struct Store(NonNull<c_void>);
impl Drop for Store { fn drop(&mut self) { unsafe { X509_STORE_free(self.0.as_ptr()) } } }
struct Verify(NonNull<c_void>);
impl Drop for Verify { fn drop(&mut self) { unsafe { X509_STORE_CTX_free(self.0.as_ptr()) } } }

impl Certificate {
    pub(crate) fn as_ptr(&self) -> *mut c_void { self.cert.as_ptr() }

    pub(crate) unsafe fn take_peer(pointer: *mut c_void) -> Result<Self> {
        let cert = NonNull::new(pointer).ok_or_else(|| fail("Missing managed TLS peer certificate"))?;
        let mut owned = Self { cert, fingerprint:String::new() };
        let size = unsafe { i2d_X509(pointer, ptr::null_mut()) };
        if !(1..=16_384).contains(&size) { return Err(fail("Invalid managed TLS peer certificate")); }
        let mut bytes = vec![0; size as usize];
        let mut cursor = bytes.as_mut_ptr();
        if unsafe { i2d_X509(pointer, &mut cursor) } != size { return Err(fail("Cannot encode managed TLS peer certificate")); }
        owned.fingerprint = rel::hash(bytes);
        Ok(owned)
    }

    pub(crate) fn fingerprint(&self) -> &str { &self.fingerprint }

    pub(crate) fn renew(&self, issuer: &Self, leaf_key: &PrivateKey, issuer_key: &PrivateKey, usage: LeafUse<'_>,
        not_before_ms: i64, not_after_ms: i64) -> Result<String> {
        self.verify_issuer(issuer)?;
        let invalid = || fail("Managed certificate and signing keys do not match");
        if unsafe { X509_check_private_key(self.as_ptr(), leaf_key.as_ptr()) != 1
            || X509_check_private_key(issuer.as_ptr(), issuer_key.as_ptr()) != 1 } { return Err(invalid()); }
        let cert = Self { cert:NonNull::new(unsafe { X509_new() }).ok_or_else(|| fail("Cannot allocate managed certificate"))?,
            fingerprint:String::new() };
        let leaf = cert.as_ptr();
        let mut serial = [0; 16];
        getrandom::getrandom(&mut serial).map_err(|_| fail("Managed certificate entropy unavailable"))?;
        serial[0] |= 1;
        unsafe {
            let number = BN_bin2bn(serial.as_ptr(), 16, ptr::null_mut());
            if number.is_null() { return Err(fail("Cannot allocate managed certificate serial")); }
            let written = BN_to_ASN1_INTEGER(number, X509_get_serialNumber(leaf));
            BN_free(number);
            if written.is_null() || X509_set_version(leaf, 2) != 1
                || X509_set_subject_name(leaf, X509_get_subject_name(self.as_ptr())) != 1
                || X509_set_issuer_name(leaf, X509_get_subject_name(issuer.as_ptr())) != 1
                || X509_set_pubkey(leaf, self.key()?.as_ptr()) != 1
                || ASN1_TIME_set(X509_getm_notBefore(leaf), not_before_ms.div_euclid(1000)).is_null()
                || ASN1_TIME_set(X509_getm_notAfter(leaf), not_after_ms.div_euclid(1000)).is_null() {
                return Err(fail("Cannot construct managed certificate"));
            }
        }
        let add_extension = |name: &CStr, value: &CStr| -> Result<()> {
            unsafe {
                let extension = X509V3_EXT_conf_nid(ptr::null_mut(), ptr::null_mut(), OBJ_txt2nid(name.as_ptr()), value.as_ptr());
                if extension.is_null() { return Err(fail("Cannot construct managed certificate extension")); }
                let installed = X509_add_ext(leaf, extension, -1);
                X509_EXTENSION_free(extension);
                if installed != 1 { return Err(fail("Cannot install managed certificate extension")); }
            }
            Ok(())
        };
        let (purpose, host) = match usage {
            LeafUse::Desktop => {
                add_extension(c"extendedKeyUsage", c"clientAuth")?;
                (1, None)
            }
            LeafUse::Server { dns, host } => {
                add_extension(c"subjectAltName", dns)?;
                add_extension(c"extendedKeyUsage", c"serverAuth")?;
                (2, Some(host))
            }
        };
        unsafe {
            let name = EVP_PKEY_get0_type_name(issuer_key.as_ptr());
            if name.is_null() { return Err(invalid()); }
            let digest = if matches!(CStr::from_ptr(name).to_bytes(), b"ED25519" | b"ED448") { ptr::null() } else { EVP_sha256() };
            if X509_sign(leaf, issuer_key.as_ptr(), digest) <= 0 { return Err(fail("Managed certificate signing failed")); }
            let store = Store(NonNull::new(X509_STORE_new()).ok_or_else(|| fail("Cannot allocate managed certificate store"))?);
            let verification = Verify(NonNull::new(X509_STORE_CTX_new()).ok_or_else(|| fail("Cannot allocate managed certificate verification"))?);
            let context = verification.0.as_ptr();
            if X509_STORE_add_cert(store.0.as_ptr(), issuer.as_ptr()) != 1
                || X509_STORE_CTX_init(context, store.0.as_ptr(), leaf, ptr::null_mut()) != 1
                || X509_STORE_CTX_set_purpose(context, purpose) != 1
                || host.is_some_and(|host| X509_VERIFY_PARAM_set1_host(X509_STORE_CTX_get0_param(context), host.as_ptr(), 0) != 1)
                || X509_verify_cert(context) != 1 {
                return Err(fail("Managed certificate purpose, issuer, or hostname verification failed"));
            }
            let bio = Bio(NonNull::new(BIO_new(BIO_s_mem())).ok_or_else(|| fail("Cannot allocate managed certificate output"))?);
            if PEM_write_bio_X509(bio.0.as_ptr(), leaf) != 1 { return Err(fail("Cannot encode managed certificate")); }
            let size = BIO_ctrl_pending(bio.0.as_ptr());
            if !(1..=16_384).contains(&size) { return Err(fail("Managed certificate exceeds its output bound")); }
            let mut bytes = vec![0; size];
            if BIO_read(bio.0.as_ptr(), bytes.as_mut_ptr(), size as c_int) != size as c_int {
                return Err(fail("Cannot read managed certificate output"));
            }
            Ok(String::from_utf8(bytes)?)
        }
    }
}

impl Certificate {
    pub(crate) fn from_pem(pem: &str) -> Result<Self> {
        if !pem.is_ascii() { return Err(fail("Invalid public certificate encoding")); }
        let mut lines = pem.trim().lines();
        if lines.next() != Some("-----BEGIN CERTIFICATE-----") || lines.next_back() != Some("-----END CERTIFICATE-----") {
            return Err(fail("Expected one public certificate PEM"));
        }
        let der = Base64::decode_vec(&lines.collect::<String>()).map_err(|_| fail("Invalid public certificate encoding"))?;
        Self::parse(&der)
    }

    pub(crate) fn parse(der: &[u8]) -> Result<Self> {
        let mut cursor = der.as_ptr();
        let cert = unsafe { d2i_X509(ptr::null_mut(), &mut cursor, der.len().try_into()?) };
        let cert = NonNull::new(cert).ok_or_else(|| fail("Invalid public certificate"))?;
        let result = Self { cert, fingerprint: rel::hash(der).as_bytes().chunks_exact(2)
            .map(|pair| String::from_utf8_lossy(pair).to_ascii_uppercase()).collect::<Vec<_>>().join(":") };
        if cursor != der.as_ptr().wrapping_add(der.len()) {
            return Err(fail("Expected exactly one public certificate"));
        }
        Ok(result)
    }

    fn key(&self) -> Result<NonNull<c_void>> {
        NonNull::new(unsafe { X509_get0_pubkey(self.cert.as_ptr()) }).ok_or_else(|| fail("Missing public key"))
    }

    pub(crate) fn verify_issuer(&self, issuer: &Self) -> Result<()> {
        let leaf = self.cert.as_ptr();
        let ca = issuer.cert.as_ptr();
        let key = issuer.key()?;
        if unsafe { X509_check_ca(leaf) != 0 || X509_check_ca(ca) <= 0
            || X509_check_issued(ca, leaf) != 0 || X509_verify(leaf, key.as_ptr()) != 1 } {
            return Err(fail("Certificate and issuer do not match"));
        }
        Ok(())
    }

    fn subject(&self) -> Result<String> {
        // XN_FLAG_SEP_MULTILINE with UTF-8 and RFC 2253/control escaping.
        const NAME_FLAGS: c_ulong = (4 << 16) | 0x10 | 0x02 | 0x01;
        let bio = Bio(NonNull::new(unsafe { BIO_new(BIO_s_mem()) }).ok_or_else(|| fail("Cannot allocate X.509 name buffer"))?);
        let name = unsafe { X509_get_subject_name(self.cert.as_ptr()) };
        if name.is_null() || unsafe { X509_NAME_print_ex(bio.0.as_ptr(), name, 0, NAME_FLAGS) } < 0 {
            return Err(fail("Invalid certificate subject"));
        }
        let size = unsafe { BIO_ctrl_pending(bio.0.as_ptr()) };
        if size == 0 { return Ok(String::new()); }
        if size > 16_384 { return Err(fail("Certificate subject exceeds its limit")); }
        let mut bytes = vec![0; size];
        if unsafe { BIO_read(bio.0.as_ptr(), bytes.as_mut_ptr(), size as c_int) } != size as c_int {
            return Err(fail("Cannot read certificate subject"));
        }
        Ok(String::from_utf8(bytes)?)
    }

    fn serial(&self) -> Result<String> {
        unsafe {
            let number = ASN1_INTEGER_to_BN(X509_get0_serialNumber(self.cert.as_ptr()), ptr::null_mut());
            if number.is_null() { return Err(fail("Invalid certificate serial")); }
            let text = BN_bn2hex(number);
            BN_free(number);
            if text.is_null() { return Err(fail("Cannot read certificate serial")); }
            let result = CStr::from_ptr(text).to_str().map(str::to_owned);
            CRYPTO_free(text.cast(), ptr::null(), 0);
            Ok(result?)
        }
    }

    fn date(&self, before: bool) -> Result<chrono::DateTime<chrono::Utc>> {
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        let value = unsafe { if before { X509_get0_notBefore(self.cert.as_ptr()) } else { X509_get0_notAfter(self.cert.as_ptr()) } };
        if unsafe { ASN1_TIME_to_tm(value, &mut tm) } != 1 {
            return Err(fail("Invalid certificate date"));
        }
        let time = chrono::NaiveDate::from_ymd_opt(tm.tm_year + 1900, (tm.tm_mon + 1) as u32, tm.tm_mday as u32)
            .and_then(|date| date.and_hms_opt(tm.tm_hour as u32, tm.tm_min as u32, tm.tm_sec as u32))
            .ok_or_else(|| fail("Invalid certificate expiry"))?;
        Ok(time.and_utc())
    }

    pub(crate) fn valid_from(&self) -> Result<i64> { Ok(self.date(true)?.timestamp_millis()) }
    pub(crate) fn valid_until(&self) -> Result<i64> { Ok(self.date(false)?.timestamp_millis()) }
    pub(crate) fn is_ca(&self) -> bool { unsafe { X509_check_ca(self.cert.as_ptr()) > 0 } }

    pub(crate) fn metadata(&self) -> Result<Value> {
        let key = self.key()?.as_ptr();
        let kind = unsafe { EVP_PKEY_get0_type_name(key) };
        if kind.is_null() { return Err(fail("Missing public key type")); }
        let algorithm = unsafe { CStr::from_ptr(kind) }.to_str()?.to_ascii_lowercase();
        let algorithm = match algorithm.as_str() {
            "rsassa-pss" => "rsa-pss",
            "id-ecpublickey" => "ec",
            other => other,
        };
        let size = unsafe { i2d_PUBKEY(key, ptr::null_mut()) };
        if !(1..=16_384).contains(&size) { return Err(fail("Invalid public key encoding")); }
        let mut bytes = vec![0; size as usize];
        let mut cursor = bytes.as_mut_ptr();
        if unsafe { i2d_PUBKEY(key, &mut cursor) } != size { return Err(fail("Cannot encode public key")); }
        Ok(json!({"subject":self.subject()?, "serial":self.serial()?, "fingerprint":self.fingerprint,
            "expires":self.date(false)?.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "algorithm":algorithm, "keyFingerprint":rel::hash(bytes)}))
    }
}
