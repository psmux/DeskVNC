#![forbid(unsafe_code)]

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[cfg(feature = "server")]
pub mod server;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Register {
    pub invitation: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lookup {
    pub code: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issued {
    pub code: String,
    pub revoke: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revoke {
    pub token: String,
}

/// The release build supplies the shared endpoint. No fictitious public endpoint is used.
pub fn default_service() -> String {
    std::env::var("BOUNDARY_CODE_SERVICE").unwrap_or_else(|_| {
        option_env!("BOUNDARY_DEFAULT_CODE_SERVICE")
            .unwrap_or("")
            .to_owned()
    })
}

fn service_origin<'a>(private: &'a str, shared: &'a str) -> Result<&'a str> {
    let selected = if private.trim().is_empty() {
        shared.trim()
    } else {
        private.trim()
    };
    ensure!(
        !selected.is_empty(),
        "This build has no shared code service configured. Enter a private service URL or use the full invitation"
    );
    Ok(selected)
}

pub fn normalize_code(value: &str) -> Result<String> {
    ensure!(value.len() <= 32, "Enter a 12 digit support code");
    let code: String = value.chars().filter(|c| *c != ' ').collect();
    ensure!(
        code.len() == 12 && code.bytes().all(|b| b.is_ascii_digit()),
        "Enter a 12 digit support code"
    );
    Ok(code)
}

#[derive(Clone)]
pub struct Client {
    base: reqwest::Url,
    http: reqwest::Client,
}
impl Client {
    pub fn new(base: &str) -> Result<Self> {
        let shared = default_service();
        let base = service_origin(base, &shared)?;
        let mut base =
            reqwest::Url::parse(base.trim()).context("Enter the support code service URL")?;
        let local = matches!(base.host_str(), Some("127.0.0.1" | "[::1]"));
        ensure!(
            base.scheme() == "https" || (base.scheme() == "http" && local),
            "The code service requires HTTPS, except literal loopback addresses for local tests"
        );
        ensure!(
            base.host_str().is_some()
                && base.username().is_empty()
                && base.password().is_none()
                && base.query().is_none()
                && base.fragment().is_none()
                && base.path() == "/",
            "Use a service origin without credentials, a path, query or fragment"
        );
        base.set_path("/");
        Ok(Self {
            base,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        })
    }
    async fn post<T: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R> {
        let mut response = self
            .http
            .post(self.base.join(path)?)
            .json(body)
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("Support code service could not be reached"))?;
        ensure!(
            response.status().is_success(),
            "Support code service refused the request (HTTP {}). The code may be expired, already used, or rate limited",
            response.status().as_u16()
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("Code service response failed"))?
        {
            ensure!(
                bytes.len() + chunk.len() <= 20000,
                "Code service response is too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).context("Invalid code service response")
    }
    pub async fn register(&self, invitation: String) -> Result<Lease> {
        boundary_session::Invitation::decode(&invitation)?;
        let issued: Issued = self.post("v1/register", &Register { invitation }).await?;
        let code = normalize_code(&issued.code)?;
        ensure!(
            issued.revoke.len() == 64 && issued.revoke.bytes().all(|b| b.is_ascii_hexdigit()),
            "Invalid revocation token"
        );
        Ok(Lease {
            code,
            token: issued.revoke,
            client: self.clone(),
        })
    }
    pub async fn resolve(&self, code: &str) -> Result<String> {
        let result: Register = self
            .post(
                "v1/resolve",
                &Lookup {
                    code: normalize_code(code)?,
                },
            )
            .await?;
        boundary_session::Invitation::decode(&result.invitation)?;
        Ok(result.invitation)
    }
}
/// Dropping the local lease requests deletion. Expiry bounds cleanup if offline.
pub struct Lease {
    pub code: String,
    token: String,
    client: Client,
}
impl Lease {
    pub fn display(&self) -> String {
        format!(
            "{} {} {}",
            &self.code[..4],
            &self.code[4..8],
            &self.code[8..]
        )
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let client = self.client.clone();
            let token = self.token.clone();
            runtime.spawn(async move {
                let _: Result<serde_json::Value> =
                    client.post("v1/revoke", &Revoke { token }).await;
            });
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validate_codes_and_service_origins() {
        assert_eq!(
            service_origin("", "https://shared.example").unwrap(),
            "https://shared.example"
        );
        assert_eq!(
            service_origin("https://private.example", "https://shared.example").unwrap(),
            "https://private.example"
        );
        assert!(service_origin("", "").is_err());
        assert_eq!(normalize_code("0123 4567 8901").unwrap(), "012345678901");
        for bad in ["123456", "01234567890a", "１２３４５６７８９０１２"] {
            assert!(normalize_code(bad).is_err());
        }
        for bad in [
            "http://example.com",
            "https://x.test/path",
            "https://user:pass@x.test",
            "https://x.test?key=secret",
        ] {
            assert!(Client::new(bad).is_err());
        }
        assert!(Client::new("http://127.0.0.1:4343").is_ok());
        assert!(Client::new("https://codes.example.com").is_ok());
    }
}
