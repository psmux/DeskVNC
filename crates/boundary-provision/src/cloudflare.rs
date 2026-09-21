//! Private account provisioning through Cloudflare APIs. No public tunnel or DNS record.
use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;

#[async_trait]
pub trait Api: Send + Sync {
    async fn call(&self, method: Method, path: &str, body: Option<Value>) -> Result<Value>;
}
pub struct Client {
    http: reqwest::Client,
    account: String,
    token: Zeroizing<String>,
}
impl Client {
    pub fn new(account: &str, token: &str) -> Result<Self> {
        validate_account(account)?;
        ensure!(
            !token.trim().is_empty() && token.len() <= 4096,
            "Enter a scoped Cloudflare API token"
        );
        Ok(Self {
            http: reqwest::Client::builder()
                .https_only(true)
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(30))
                .build()?,
            account: account.into(),
            token: Zeroizing::new(token.into()),
        })
    }
}
#[async_trait]
impl Api for Client {
    async fn call(&self, method: Method, path: &str, body: Option<Value>) -> Result<Value> {
        ensure!(
            path.starts_with('/') && !path.contains(".."),
            "Invalid provider API path"
        );
        let mut request = self
            .http
            .request(
                method.clone(),
                format!(
                    "https://api.cloudflare.com/client/v4/accounts/{}{path}",
                    self.account
                ),
            )
            .bearer_auth(self.token.as_str());
        if let Some(body) = body {
            request = request.json(&body);
        }
        let mut response = request
            .send()
            .await
            .context("Cloudflare request failed. Check connectivity and resume setup")?;
        let status = response.status();
        if status.as_u16() == 404 && method == Method::GET {
            return Ok(Value::Null);
        }
        // Never surface a provider response body; it can echo credentials or enrollment URLs.
        ensure!(
            status.is_success(),
            "Cloudflare rejected the operation (HTTP {}). Check token permissions or account prerequisites before resuming",
            status.as_u16()
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len() + chunk.len() <= 2 * 1024 * 1024,
                "Cloudflare response exceeded its limit"
            );
            bytes.extend_from_slice(&chunk);
        }
        let envelope: Value =
            serde_json::from_slice(&bytes).context("Cloudflare returned an invalid response")?;
        ensure!(
            envelope["success"] == true,
            "Cloudflare did not confirm the requested operation"
        );
        Ok(envelope["result"].clone())
    }
}
fn validate_account(account: &str) -> Result<()> {
    ensure!(
        account.len() == 32 && account.bytes().all(|b| b.is_ascii_hexdigit()),
        "Enter the 32 character Cloudflare account ID"
    );
    Ok(())
}
fn validate_emails(emails: &[String]) -> Result<()> {
    ensure!(
        !emails.is_empty() && emails.len() <= 10,
        "Enter between one and ten enrollment email addresses"
    );
    for email in emails {
        ensure!(
            email.len() <= 254
                && email.contains('@')
                && email
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"@._+-".contains(&b)),
            "Enter complete enrollment email addresses"
        );
    }
    Ok(())
}
#[derive(Serialize, Deserialize, Clone, Debug)]
struct Journal {
    deployment: String,
    team: String,
    emails: Vec<String>,
    enrollment_app: Option<String>,
    enrollment_policy: Option<String>,
    device_profile: Option<String>,
    disabled: bool,
}
impl Journal {
    fn new(team: &str, emails: &[String]) -> Self {
        Self {
            deployment: uuid::Uuid::new_v4().to_string(),
            team: team.into(),
            emails: emails.to_vec(),
            enrollment_app: None,
            enrollment_policy: None,
            device_profile: None,
            disabled: false,
        }
    }
    fn name(&self) -> String {
        format!("Boundary {}", self.deployment)
    }
}
fn journal_path(account: &str) -> Result<PathBuf> {
    validate_account(account)?;
    Ok(crate::platform::data_dir()?.join(format!("cloudflare-{account}.json")))
}
fn persist(path: &Path, journal: &Journal) -> Result<()> {
    use std::io::Write;
    let parent = path.parent().context("Invalid journal path")?;
    std::fs::create_dir_all(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(&serde_json::to_vec_pretty(journal)?)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|_| {
        anyhow::anyhow!("Could not save setup progress. Retry to reconcile provider resources")
    })?;
    Ok(())
}
pub async fn configure(api: &dyn Api, account: &str, team: &str, emails: &[String]) -> Result<()> {
    configure_at(api, team, emails, &journal_path(account)?).await
}
async fn configure_at(api: &dyn Api, team: &str, emails: &[String], path: &Path) -> Result<()> {
    crate::validate_team(team)?;
    validate_emails(emails)?;
    ensure!(
        profile_body("validation", emails, 0)["match"]
            .as_str()
            .is_some_and(|value| value.len() <= 500),
        "Enrollment email selection exceeds Cloudflare profile limits"
    );
    let mut journal = match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice::<Journal>(&bytes)
            .context("Saved provisioning state is invalid; it was not replaced")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Journal::new(team, emails),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        !journal.disabled,
        "This deployment was disconnected. Its resources will not be silently recreated"
    );
    ensure!(
        journal.team == team && journal.emails == emails,
        "This account already has a Boundary setup with different enrollment settings"
    );
    persist(path, &journal)?; // Reserve the resource name before issuing any mutations.
    let name = journal.name();
    let org = api.call(Method::GET, "/access/organizations", None).await?;
    if org.is_null() {
        api.call(Method::POST, "/access/organizations", Some(json!({"name": team, "auth_domain": format!("{team}.cloudflareaccess.com")}))).await.context("Cloudflare organization creation requires an activated account and sufficient permission")?;
    } else {
        ensure!(
            org["auth_domain"] == format!("{team}.cloudflareaccess.com"),
            "The selected team does not belong to this account"
        );
    }

    let providers = list(api, "/access/identity_providers").await?;
    if providers.is_empty() {
        api.call(
            Method::POST,
            "/access/identity_providers",
            Some(json!({"name": "Boundary email login", "type": "onetimepin", "config": {}})),
        )
        .await?;
    }
    let applications = list(api, "/access/apps").await?;
    let app = if let Some(id) = &journal.enrollment_app {
        applications
            .iter()
            .find(|app| app["id"] == *id)
            .cloned()
            .context(
                "The enrollment application was removed. Setup will not recreate revoked access",
            )?
    } else if let Some(app) = applications.iter().find(|app| app["type"] == "warp") {
        app.clone()
    } else {
        api.call(Method::POST, "/access/apps", Some(json!({"name": "Boundary device enrollment", "type": "warp", "session_duration": "24h"}))).await?
    };
    let app_id = id(&app, "id")?;
    journal.enrollment_app = Some(app_id.clone());
    persist(path, &journal)?;
    let policy_path = format!("/access/apps/{app_id}/policies");
    let policies = list(api, &policy_path).await?;
    let policy = owned(&policies, journal.enrollment_policy.as_deref(), &name)?;
    if let Some(policy) = policy {
        ensure!(
            policy["decision"] == "allow"
                && policy["include"]
                    == json!(
                        emails
                            .iter()
                            .map(|email| json!({"email": {"email": email}}))
                            .collect::<Vec<_>>()
                    ),
            "The enrollment policy changed externally. Review it before resuming"
        );
        journal.enrollment_policy = Some(id(&policy, "id")?);
    } else {
        // The explicit email allowlist never contains an Everyone selector.
        let policy = api.call(Method::POST, &policy_path, Some(json!({"name": name, "decision": "allow", "include": emails.iter().map(|email| json!({"email": {"email": email}})).collect::<Vec<_>>(), "precedence": 1000}))).await?;
        journal.enrollment_policy = Some(id(&policy, "id")?);
    }
    persist(path, &journal)?;

    let profiles = list(api, "/devices/policies").await?;
    if let Some(profile) = owned(&profiles, journal.device_profile.as_deref(), &name)? {
        let expected = profile_body(&name, emails, 0);
        ensure!(
            profile["match"] == expected["match"]
                && profile["include"] == expected["include"]
                && profile["service_mode_v2"]["mode"] == expected["service_mode_v2"]["mode"]
                && profile["tunnel_protocol"] == expected["tunnel_protocol"],
            "The private device profile changed externally. Review it before resuming"
        );
        journal.device_profile = Some(id(&profile, "policy_id")?);
    } else {
        let precedence = profiles
            .iter()
            .filter_map(|p| p["precedence"].as_u64())
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .context("Device profile precedence is out of range")?;
        let profile = api
            .call(
                Method::POST,
                "/devices/policy",
                Some(profile_body(&name, emails, precedence)),
            )
            .await?;
        journal.device_profile = Some(id(&profile, "policy_id")?);
    }
    persist(path, &journal)?;
    // This account switch is explicitly included in the review. Do not reset it on
    // cleanup because other enrolled devices may depend on it by then.
    api.call(
        Method::PATCH,
        "/zerotrust/connectivity_settings",
        Some(json!({"offramp_warp_enabled": true})),
    )
    .await?;
    Ok(())
}
fn profile_body(name: &str, emails: &[String], precedence: u64) -> Value {
    let expression = emails
        .iter()
        .map(|email| {
            format!(
                "identity.email == {}",
                serde_json::to_string(email).expect("string serialization")
            )
        })
        .collect::<Vec<_>>()
        .join(" or ");
    json!({"name": name, "match": expression, "precedence": precedence, "enabled": true, "service_mode_v2": {"mode": "warp"}, "tunnel_protocol": "masque", "include": [{"address": "100.96.0.0/12", "description": "Private device access"}], "allow_mode_switch": false})
}
async fn list(api: &dyn Api, path: &str) -> Result<Vec<Value>> {
    let mut values = Vec::new();
    for page in 1..=20 {
        let response = api
            .call(
                Method::GET,
                &format!("{path}?page={page}&per_page=100"),
                None,
            )
            .await?;
        let entries = response
            .as_array()
            .context("Cloudflare returned an unexpected resource list")?;
        values.extend(entries.iter().cloned());
        if entries.len() < 100 {
            return Ok(values);
        }
    }
    bail!("Cloudflare account exceeds this setup's resource scan limit")
}
fn id(value: &Value, field: &str) -> Result<String> {
    let id = value[field]
        .as_str()
        .context("Cloudflare response is missing a resource ID")?;
    ensure!(
        !id.is_empty()
            && id.len() <= 64
            && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "Invalid provider resource ID"
    );
    Ok(id.into())
}
fn owned(resources: &[Value], saved: Option<&str>, name: &str) -> Result<Option<Value>> {
    if let Some(saved) = saved {
        let value = resources
            .iter()
            .find(|value| value["id"] == saved || value["policy_id"] == saved)
            .context("A Boundary resource was removed. Setup will not recreate revoked access")?;
        ensure!(
            value["name"] == name,
            "A Boundary resource was changed externally. Review it before resuming"
        );
        return Ok(Some(value.clone()));
    }
    // Recover the result of a successful POST if the process died before saving its ID.
    let matches: Vec<_> = resources
        .iter()
        .filter(|value| value["name"] == name)
        .collect();
    ensure!(
        matches.len() <= 1,
        "Duplicate provisioning resources require review"
    );
    Ok(matches.first().map(|value| (*value).clone()))
}
pub async fn cleanup(api: &dyn Api, account: &str) -> Result<()> {
    cleanup_at(api, &journal_path(account)?).await
}
async fn cleanup_at(api: &dyn Api, path: &Path) -> Result<()> {
    let mut journal: Journal = serde_json::from_slice(&std::fs::read(path)?)?;
    journal.disabled = true;
    persist(path, &journal)?;
    if let Some(profile) = &journal.device_profile {
        let current = api
            .call(Method::GET, &format!("/devices/policy/{profile}"), None)
            .await?;
        if !current.is_null() {
            ensure!(
                current["name"] == journal.name(),
                "Device profile ownership changed; cleanup stopped"
            );
            api.call(Method::DELETE, &format!("/devices/policy/{profile}"), None)
                .await?;
        }
    }
    if let (Some(app), Some(policy)) = (&journal.enrollment_app, &journal.enrollment_policy) {
        let current = api
            .call(
                Method::GET,
                &format!("/access/apps/{app}/policies/{policy}"),
                None,
            )
            .await?;
        if !current.is_null() {
            ensure!(
                current["name"] == journal.name(),
                "Enrollment policy ownership changed; cleanup stopped"
            );
            api.call(
                Method::DELETE,
                &format!("/access/apps/{app}/policies/{policy}"),
                None,
            )
            .await?;
        }
    }
    // Retain the organization, shared enrollment app, account switch and provider client.
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<(Method, String, Option<Value>)>>,
        policies: Mutex<Vec<Value>>,
        profiles: Mutex<Vec<Value>>,
        lose_response: Mutex<bool>,
    }
    #[async_trait]
    impl Api for Fake {
        async fn call(&self, method: Method, path: &str, body: Option<Value>) -> Result<Value> {
            self.calls
                .lock()
                .unwrap()
                .push((method.clone(), path.into(), body.clone()));
            if path == "/access/organizations" {
                return Ok(json!({"auth_domain":"team.cloudflareaccess.com"}));
            }
            if path.starts_with("/access/identity_providers?") {
                return Ok(json!([{"id":"otp","type":"onetimepin"}]));
            }
            if path.starts_with("/access/apps?") {
                return Ok(json!([{"id":"app1","type":"warp"}]));
            }
            if method == Method::GET && path.starts_with("/access/") && path.contains("/policies?")
            {
                return Ok(json!(self.policies.lock().unwrap().clone()));
            }
            if method == Method::GET && path.starts_with("/devices/policies?") {
                return Ok(json!(self.profiles.lock().unwrap().clone()));
            }
            if method == Method::GET && path.starts_with("/devices/policy/") {
                return Ok(self
                    .profiles
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|value| value["policy_id"] == path.rsplit('/').next().unwrap())
                    .cloned()
                    .unwrap_or(Value::Null));
            }
            if method == Method::GET && path.starts_with("/access/apps/app1/policies/") {
                return Ok(self
                    .policies
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|value| value["id"] == path.rsplit('/').next().unwrap())
                    .cloned()
                    .unwrap_or(Value::Null));
            }
            if method == Method::DELETE {
                if path.starts_with("/devices/") {
                    self.profiles.lock().unwrap().clear();
                } else {
                    self.policies.lock().unwrap().clear();
                }
                return Ok(Value::Null);
            }
            if method == Method::POST {
                let mut value = body.unwrap();
                if path == "/devices/policy" {
                    value["policy_id"] = json!("profile1");
                    self.profiles.lock().unwrap().push(value.clone());
                } else {
                    value["id"] = json!("policy1");
                    self.policies.lock().unwrap().push(value.clone());
                }
                if std::mem::take(&mut *self.lose_response.lock().unwrap()) {
                    bail!("simulated lost response");
                }
                return Ok(value);
            }
            Ok(json!({}))
        }
    }
    #[tokio::test]
    async fn resume_does_not_duplicate_or_recreate_revoked_resources() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.json");
        let api = Fake::default();
        let emails = vec!["owner@example.com".into()];
        configure_at(&api, "team", &emails, &path).await.unwrap();
        configure_at(&api, "team", &emails, &path).await.unwrap();
        assert_eq!(
            api.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|(method, _, _)| *method == Method::POST)
                .count(),
            2
        );
        api.profiles.lock().unwrap().clear();
        assert!(configure_at(&api, "team", &emails, &path).await.is_err());
    }
    #[tokio::test]
    async fn lost_post_response_recovers_by_owned_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.json");
        let api = Fake::default();
        *api.lose_response.lock().unwrap() = true;
        let emails = vec!["owner@example.com".into()];
        assert!(configure_at(&api, "team", &emails, &path).await.is_err());
        configure_at(&api, "team", &emails, &path).await.unwrap();
        assert_eq!(api.policies.lock().unwrap().len(), 1);
        assert_eq!(api.profiles.lock().unwrap().len(), 1);
    }
    #[tokio::test]
    async fn policy_drift_is_not_silently_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.json");
        let api = Fake::default();
        let emails = vec!["owner@example.com".into()];
        configure_at(&api, "team", &emails, &path).await.unwrap();
        api.policies.lock().unwrap()[0]["include"] = json!([{"everyone":{}}]);
        assert!(configure_at(&api, "team", &emails, &path).await.is_err());
    }
    #[tokio::test]
    async fn cleanup_removes_only_owned_resources_and_prevents_resume() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.json");
        let api = Fake::default();
        let emails = vec!["owner@example.com".into()];
        configure_at(&api, "team", &emails, &path).await.unwrap();
        cleanup_at(&api, &path).await.unwrap();
        cleanup_at(&api, &path).await.unwrap();
        assert!(configure_at(&api, "team", &emails, &path).await.is_err());
        let calls = api.calls.lock().unwrap();
        let deleted: Vec<_> = calls
            .iter()
            .filter(|(method, _, _)| *method == Method::DELETE)
            .map(|(_, path, _)| path.as_str())
            .collect();
        assert_eq!(
            deleted,
            [
                "/devices/policy/profile1",
                "/access/apps/app1/policies/policy1"
            ]
        );
    }
    #[tokio::test]
    async fn cleanup_refuses_changed_ownership() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.json");
        let api = Fake::default();
        let emails = vec!["owner@example.com".into()];
        configure_at(&api, "team", &emails, &path).await.unwrap();
        api.profiles.lock().unwrap()[0]["name"] = json!("Someone else's profile");
        assert!(cleanup_at(&api, &path).await.is_err());
        assert!(
            !api.calls
                .lock()
                .unwrap()
                .iter()
                .any(|(method, _, _)| *method == Method::DELETE)
        );
    }
    #[test]
    fn profile_routes_only_mesh_and_matches_explicit_emails() {
        let body = profile_body("owned", &["owner@example.com".into()], 1);
        assert_eq!(
            body["include"],
            json!([{"address":"100.96.0.0/12","description":"Private device access"}])
        );
        assert_eq!(body["match"], "identity.email == \"owner@example.com\"");
        assert!(validate_emails(&["x\" or true".into()]).is_err());
    }
}
