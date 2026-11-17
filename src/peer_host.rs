use crate::{Result, fail, peer_identity::PeerIdentity, peer_transport, process::Programme, rel::{self, Facts}};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs, os::unix::fs::PermissionsExt, path::Path};

pub(crate) const RETRY_ENTRY: &str = "peer.retry";

pub(crate) fn require_retry_grants(programme: &Programme) -> Result<()> {
    programme.require_grants(RETRY_ENTRY, &BTreeSet::from([
        "kernel.invoke", "peer.context", "peer.exchange", "storage.snapshot", "storage.operation",
        "storage.cas", "rel.encode", "rel.decode", "record.entries", "record.put", "text.matches",
        "digest.sha256", "json.stringify", "signature.ed25519.verify",
    ]))
}

pub fn supports_port(name: &str) -> bool {
    matches!(name, "peer.context" | "peer.attest" | "peer.exchange")
}

pub struct PeerHost {
    identity: PeerIdentity,
    remote: Value,
    port: u16,
}

impl PeerHost {
    pub fn read(file: &Path, assets: &Path, local_port: u16) -> Result<Self> {
        let file = file.canonicalize()?;
        let metadata = fs::metadata(&file)?;
        if file.starts_with(assets) || !metadata.is_file()
            || metadata.permissions().mode() & 0o077 != 0 || metadata.len() > 4096
        {
            return Err(fail("expected a private Temple peer configuration outside the served assets"));
        }
        let facts = Facts::read(&file)?;
        if facts.0.len() != 8 || facts.one("peer", "version")? != "encounter/temple-peer/1" {
            return Err(fail("unsupported Temple peer configuration"));
        }
        let token = |subject, field| -> Result<&str> {
            let value = facts.one(subject, field)?;
            if value.len() > 80 || !value.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
                || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
            {
                return Err(fail("invalid configured Temple or actor coordinate"));
            }
            Ok(value)
        };
        let seed = file.parent().ok_or_else(|| fail("missing configuration directory"))?
            .join(facts.one("local", "seedFile")?).canonicalize()?;
        if seed.starts_with(assets) || seed == file {
            return Err(fail("Temple seed must be outside the served assets and separate from configuration"));
        }
        let identity = PeerIdentity::read(&seed, token("local", "templeId")?, token("local", "actor")?)?;
        let remote_temple = token("remote", "templeId")?;
        let remote_actor = token("remote", "actor")?;
        let public_key = facts.one("remote", "publicKey")?;
        let bytes: [u8; 32] = hex::decode(public_key)?.try_into().map_err(|_| fail("expected a 32-byte Temple public key"))?;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| fail("invalid configured peer key"))?;
        if hex::encode(bytes) != public_key || verifying_key.is_weak()
            || remote_temple == identity.temple_id() || public_key == identity.public_key()
        {
            return Err(fail("expected a distinct Temple and strong lowercase peer key pin"));
        }
        let port: u16 = facts.one("remote", "port")?.parse()?;
        if port == 0 || local_port == 0 || port == local_port {
            return Err(fail("Temple peers require distinct fixed loopback ports"));
        }
        let remote = json!({"templeId":remote_temple,"actor":remote_actor,"publicKey":public_key});
        Ok(Self { identity, remote, port })
    }

    pub fn actor(&self) -> &str { self.identity.actor() }

    pub fn store_profile(&self, application_profile: &str) -> String {
        let identity = rel::hash(self.context().to_string());
        format!("{application_profile}/temple/{identity}")
    }

    fn context(&self) -> Value {
        json!({"local":{
            "templeId":self.identity.temple_id(),"actor":self.identity.actor(),"publicKey":self.identity.public_key()
        },"remote":self.remote})
    }

    pub fn effect(&self, name: &str, args: &Value, outbound: bool) -> Result<Value> {
        match name {
            "peer.context" if args.as_object().is_some_and(|fields| fields.is_empty()) => Ok(self.context()),
            "peer.attest" if args.as_object().is_some_and(|fields| fields.len() == 2) => {
                let slot = args["slot"].as_str().ok_or_else(|| fail("expected a Temple attestation slot"))?;
                self.identity.sign_attestation(slot, &args["statement"])
            }
            "peer.exchange" if outbound && args.as_object().is_some_and(|fields| fields.len() == 1)
                && args["envelope"].is_object() => peer_transport::exchange(self.port, &args["envelope"]),
            _ => Err(fail("unavailable Temple peer effect")),
        }
    }
}
