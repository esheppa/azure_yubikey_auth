use async_trait::async_trait;
use azure_core::auth::AccessToken;
use azure_core::auth::TokenCredential;
use azure_core::authority_hosts::AZURE_PUBLIC_CLOUD;
use azure_core::error::ErrorKind;
use azure_core::Error;
use base64::Engine;
// use azure_identity::AZURE_PUBLIC_CLOUD;
use der::Encode;
use log::debug;
use log::warn;
use rsa::Pkcs1v15Sign;
use serde_json::{json, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;
use std::fmt::Debug;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;
use yubikey::{
    piv::{self, AlgorithmId, SlotId},
    Certificate, YubiKey,
};

use azure_core::{error::Result, HttpClient};
use azure_identity::federated_credentials_flow;

#[derive(Clone)]
pub struct Secret {
    inner: String,
}

impl Secret {
    pub fn new(s: String) -> Secret {
        Secret { inner: s }
    }
    pub fn get(&self) -> &str {
        &self.inner
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret")
            .field("inner", &"<redacted>")
            .finish()
    }
}

/// The certificate _MUST_ be in Slot 9C  otherwise it will not work.
#[derive(Clone)]
pub struct Config {
    pub tenant_id: Uuid,
    pub client_id: Uuid, // principal_id / application_id (but _NOT_ the object_id!)
    pub pin: Secret,
    pub http_client: Arc<dyn HttpClient>,
    pub shared: Arc<Mutex<Shared>>,
}

pub struct Shared {
    yubikey: YubiKey,
    cache: BTreeMap<BTreeSet<String>, AccessToken>,
    yubikey_token_cache: Option<AccessToken>,
}

impl Shared {
    pub fn new(yubikey: YubiKey) -> Arc<Mutex<Shared>> {
        Arc::new(Mutex::new(Shared {
            yubikey,
            cache: BTreeMap::default(),
            yubikey_token_cache: None,
        }))
    }
}

impl Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("tenant_id", &self.tenant_id)
            .field("client_id", &self.client_id)
            .field("cache", &self.shared.lock().unwrap().cache.len())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl TokenCredential for Config {
    async fn get_token(&self, scopes: &[&str]) -> Result<AccessToken> {
        let scopes_set = scopes
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();

        let res = self.with_shared(|mut sh| {
            sh.cache.retain(|_, token| {
                token.expires_on > OffsetDateTime::now_utc() + time::Duration::seconds(5)
            });

            if let Some((_, existing)) = sh
                .cache
                .iter()
                .find(|(scopes, _)| scopes.is_superset(&scopes_set))
            {
                return Some(existing.clone());
            }
            None
        });

        if let Some(res) = res {
            return Ok(res);
        }

        debug!("Requesting a new token. This may require a signature to be completed by the yubikey, please prepare to touch when it flashes");
        let token = self.create_jwt()?;

        let resp = federated_credentials_flow::perform(
            self.http_client.clone(),
            &self.client_id.to_string(),
            &token,
            scopes,
            &self.tenant_id.to_string(),
            &AZURE_PUBLIC_CLOUD,
        )
        .await?;

        let token = AccessToken {
            token: resp.access_token,
            expires_on: resp.expires_on.unwrap_or_else(|| {
                // https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens#token-lifetime
                // we just want a little below the minimum
                OffsetDateTime::now_utc().saturating_add(time::Duration::minutes(55))
            }),
        };

        self.with_shared(|mut sh| sh.cache.insert(scopes_set, token.clone()));

        Ok(token)
    }

    async fn clear_cache(&self) -> Result<()> {
        self.with_shared(|mut sh| {
            sh.cache.clear();
        });
        Ok(())
    }
}

impl Config {
    fn with_shared<'a, T>(&'a self, func: impl FnOnce(MutexGuard<'a, Shared>) -> T) -> T {
        func(self.shared.lock().unwrap())
    }

    pub fn create_jwt(&self) -> Result<String> {
        self.with_shared(|mut sh| self.create_jwt_inner(&mut sh))
    }

    // we require the lock to be held for the entirety of this function
    // while this may seem suboptimal as the `sign` part will block
    // on user input on the yubikey,
    // this makes sense, as all other requests should queue up behind the
    // first yubikey touch such that they can use the newly cached
    // yubikey signed token.
    // we definitely don't want users to have to do multiple touches
    // where one would have sufficed
    fn create_jwt_inner(&self, sh: &mut Shared) -> Result<String> {
        let now = OffsetDateTime::now_utc();
        let expires_in = time::Duration::minutes(120);

        if let Some(existing) = sh.yubikey_token_cache.as_ref() {
            if existing.expires_on > now + time::Duration::seconds(5) {
                return Ok(existing.token.secret().to_string());
            }
        }

        let header = serde_json::to_vec(&self.header(sh)?)?;
        let claims = serde_json::to_vec(&self.claims(now, expires_in))?;

        let joined = [encode_slice(&header), encode_slice(&claims)].join(".");

        let sig = self.sign(&joined, sh)?;

        let jwt = [joined, sig].join(".");

        sh.yubikey_token_cache = Some(AccessToken {
            token: azure_core::auth::Secret::new(jwt.clone()),
            expires_on: now.saturating_add(expires_in),
        });

        Ok(jwt)
    }

    fn header(&self, sh: &mut Shared) -> Result<Value> {
        let cert = Certificate::read(&mut sh.yubikey, SlotId::Signature)
            .map_err(|e| Error::full(ErrorKind::Other, e, "reading certificate from yuibkey"))?;
        let data = cert
            .cert
            .to_der()
            .map_err(|e| Error::full(ErrorKind::Other, e, "convert certificate to DER"))?;

        // we need Sha1 for the certificate thumbprint as that is how the format is defined
        let mut hasher = Sha1::new();
        hasher.update(&data);

        let x5t = encode_slice(hasher.finalize().as_slice());

        Ok(json!({
            "alg": "RS256",
            "typ": "JWT",
            "x5t": x5t,
        }))
    }

    fn claims(&self, now: OffsetDateTime, length: Duration) -> Value {
        let data = json!({
            "aud": format!("{}{}/oauth2/v2.0/token", AZURE_PUBLIC_CLOUD.as_ref(), self.tenant_id),
            "exp": now.saturating_add(length).unix_timestamp(),
            "iss": self.client_id,
            "jti": Uuid::new_v4(),
            "nbf": now.unix_timestamp(),
            "sub": self.client_id,
            "iat": now.unix_timestamp()
        });

        debug!("Claims: {data:?}");

        data
    }

    fn sign(&self, input: &str, sh: &mut Shared) -> Result<String> {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let hashed = hasher.finalize();

        let padding = Pkcs1v15Sign::new::<Sha256>();

        let padded = pkcs1v15_sign_pad(&padding.prefix, &hashed, 256)?;

        // while it is usually not ideal to use `warn!` in a library, in this case it makes sense
        // as this message must be conveyed to the user
        warn!("Requesting signature from the yubikey, please tap...");
        let sig_buf = piv::sign_data(
            &mut sh.yubikey,
            &padded,
            AlgorithmId::Rsa2048,
            SlotId::Signature,
        )
        .map_err(|e| Error::full(ErrorKind::Other, e, "signing data using yuibkey"))?;
        debug!("Signature successfully completed");

        Ok(encode_slice(sig_buf.as_slice()))
    }
}

fn encode_slice(slice: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(slice)
}

// This is copied from the below location. It is not public API of that crate so it is necessary to replicate here
//
// PKCS1 v1.5 padding logic from: https://docs.rs/rsa/latest/src/rsa/algorithms/pkcs1v15.rs.html#116
fn pkcs1v15_sign_pad(prefix: &[u8], hashed: &[u8], k: usize) -> Result<Vec<u8>> {
    let hash_len = hashed.len();
    let t_len = prefix.len() + hashed.len();
    if k < t_len + 11 {
        return Err(Error::message(ErrorKind::Other, "message too long"));
    }

    // EM = 0x00 || 0x01 || PS || 0x00 || T
    let mut em = vec![0xff; k];
    em[0] = 0;
    em[1] = 1;
    em[k - t_len - 1] = 0;
    em[k - t_len..k - hash_len].copy_from_slice(prefix);
    em[k - hash_len..k].copy_from_slice(hashed);

    Ok(em)
}
