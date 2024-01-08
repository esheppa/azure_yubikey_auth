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
use std::fmt;
use std::fmt::Debug;
use std::sync::Arc;
use std::sync::Mutex;
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
    pub yubikey: Arc<Mutex<YubiKey>>,
    pub pin: Secret,
    pub http_client: Arc<dyn HttpClient>,
    pub cache: Arc<Mutex<BTreeMap<String, AccessToken>>>,
    pub yubikey_token_cache: Arc<Mutex<Option<AccessToken>>>,
}

impl Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("tenant_id", &self.tenant_id)
            .field("client_id", &self.client_id)
            .field("cache", &self.cache.lock().unwrap().len())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl TokenCredential for Config {
    async fn get_token(&self, scopes: &[&str]) -> Result<AccessToken> {
        // https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow#second-case-access-token-request-with-a-certificate
        // as per docs, only one scope allowed...
        if scopes.len() > 1 {
            return Err(azure_core::error::Error::new(
                ErrorKind::Other,
                format!("Unable to get a token for multiple scopes, requsted: {scopes:?}"),
            ));
        }

        let scope = scopes[0].to_string();

        {
            let cache = self.cache.lock().unwrap();

            if let Some(existing) = cache.get(&scope) {
                if existing.expires_on > OffsetDateTime::now_utc() + time::Duration::seconds(5) {
                    return Ok(existing.clone());
                }
            }
        }

        debug!("Requesting a new token. This may require a signature to be completed by the yubikey, please prepare to touch when it flashes");
        let token = self.create_jwt()?;

        let resp = federated_credentials_flow::perform(
            self.http_client.clone(),
            &self.client_id.to_string(),
            &token,
            &[&scope],
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

        {
            let mut cache = self.cache.lock().unwrap();
            cache.insert(scope, token.clone());
        }

        Ok(token)
    }

    async fn clear_cache(&self) -> Result<()> {
        *self.cache.lock().unwrap() = BTreeMap::new();
        Ok(())
    }
}

impl Config {
    pub fn create_jwt(&self) -> Result<String> {
        let now = OffsetDateTime::now_utc();
        let expires_in = time::Duration::minutes(120);

        {
            let cache = self.yubikey_token_cache.lock().unwrap();
            if let Some(existing) = cache.as_ref() {
                if existing.expires_on > now + time::Duration::seconds(5) {
                    return Ok(existing.token.secret().to_string());
                }
            }
        }

        let header = serde_json::to_vec(&self.header()?)?;
        let claims = serde_json::to_vec(&self.claims(now, expires_in))?;

        let joined = [encode_slice(&header)?, encode_slice(&claims)?].join(".");

        let sig = self.sign(&joined)?;

        let jwt = [joined, sig].join(".");

        {
            let mut cache = self.yubikey_token_cache.lock().unwrap();
            *cache = Some(AccessToken {
                token: azure_core::auth::Secret::new(jwt.clone()),
                expires_on: now.saturating_add(expires_in),
            })
        }

        Ok(jwt)
    }

    fn header(&self) -> Result<Value> {
        let cert = Certificate::read(&mut self.yubikey.lock().unwrap(), SlotId::Signature)
            .map_err(|e| Error::full(ErrorKind::Other, e, "reading certificate from yuibkey"))?;
        let data = cert
            .cert
            .to_der()
            .map_err(|e| Error::full(ErrorKind::Other, e, "convert certificate to DER"))?;

        // we need Sha1 for the certificate thumbprint as that is how the format is defined
        let mut hasher = Sha1::new();
        hasher.update(&data);

        let x5t = encode_slice(hasher.finalize().as_slice())?;

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

    fn sign(&self, input: &str) -> Result<String> {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let hashed = hasher.finalize();

        let padding = Pkcs1v15Sign::new::<Sha256>();

        let padded = pkcs1v15_sign_pad(&padding.prefix, &hashed, 256)?;

        // while it is usually not ideal to use `warn!` in a library, in this case it makes sense
        // as this message must be conveyed to the user
        warn!("Requesting signature from the yubikey, please tap...");
        let sig_buf = piv::sign_data(
            &mut self.yubikey.lock().unwrap(),
            &padded,
            AlgorithmId::Rsa2048,
            SlotId::Signature,
        )
        .map_err(|e| Error::full(ErrorKind::Other, e, "signing data using yuibkey"))?;
        debug!("Signature successfully completed");

        encode_slice(sig_buf.as_slice())
    }
}

#[allow(clippy::slow_vector_initialization)]
fn encode_slice(slice: &[u8]) -> Result<String> {
    let mut out_buf = Vec::new();
    out_buf.resize(slice.len() * 4 / 3 + 4, 0);

    let written = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode_slice(slice, &mut out_buf)
        .map_err(|e| Error::full(ErrorKind::Other, e, "Could not encode."))?;

    out_buf.truncate(written);

    String::from_utf8(out_buf)
        .map_err(|e| Error::full(ErrorKind::Other, e, "Could not convert to UTF-8 string."))
        
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
