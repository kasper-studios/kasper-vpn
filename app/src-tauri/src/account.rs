use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

const API_BASE: &str = "https://vpn.kasperstudios.xyz";
const USER_AGENT: &str = "KasperVPN/0.1.0";

fn is_loopback_target(host: &str) -> bool {
    let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
    host == "localhost"
        || host == "localhost.localdomain"
        || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn account_http_client() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 10 {
                attempt.error("too many redirects")
            } else if attempt.url().host_str().is_some_and(is_loopback_target) {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub username: String,
    pub vless_link: String,
    #[serde(skip, default)]
    pub used_mb: String,
    #[serde(rename = "usedGB")]
    pub used_gb: String,
    #[serde(rename = "totalGB")]
    pub total_gb: String,
    pub percentage: u8,
    pub is_admin: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LoginResult {
    pub username: String,
    pub is_admin: bool,
}

fn message(value: &Value) -> Option<&str> {
    value.get("error").and_then(Value::as_str)
}

fn validate_vless(link: &str) -> Result<(), String> {
    let parsed =
        url::Url::parse(link).map_err(|_| "Сервер вернул некорректную VLESS-ссылку".to_string())?;
    if parsed.scheme() != "vless" || parsed.host_str().is_none() || parsed.username().is_empty() {
        return Err("Сервер вернул некорректную VLESS-ссылку".into());
    }
    Ok(())
}

pub struct AccountClient {
    client: reqwest::Client,
    bases: Vec<String>,
}

impl AccountClient {
    pub fn new() -> Result<Self, String> {
        Self::with_bases(vec![
            API_BASE.to_string(),
            "https://vpn.kasperstudios.xyz:8443".to_string(),
        ])
    }

    #[cfg(test)]
    fn with_base(base: &str) -> Result<Self, String> {
        Self::with_bases(vec![base.to_string()])
    }

    fn with_bases(bases: Vec<String>) -> Result<Self, String> {
        let client = account_http_client()
            .cookie_store(true)
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("Не удалось создать HTTP-клиент: {e}"))?;
        Ok(Self {
            client,
            bases: bases
                .into_iter()
                .map(|b| b.trim_end_matches('/').to_string())
                .collect(),
        })
    }

    pub async fn login(&self, username: &str, password: &str) -> Result<LoginResult, String> {
        let username = username.trim();
        if username.is_empty() || password.is_empty() {
            return Err("Введите логин и пароль".into());
        }
        let mut last_error = String::new();
        for base in &self.bases {
            let res = self
                .client
                .post(format!("{}/api/login", base))
                .json(&serde_json::json!({"username": username, "password": password}))
                .send()
                .await;
            match res {
                Ok(response) => {
                    let status = response.status();
                    let value: Value = response
                        .json()
                        .await
                        .map_err(|e| format!("Некорректный ответ входа: {e}"))?;
                    if !status.is_success() || value.get("ok").and_then(Value::as_bool) == Some(false) {
                        return Err(message(&value)
                            .unwrap_or("Неверный логин или пароль")
                            .to_string());
                    }
                    return serde_json::from_value(value)
                        .map_err(|e| format!("Ответ входа не соответствует API: {e}"));
                }
                Err(err) => {
                    last_error = format!("{err}");
                }
            }
        }
        Err(format!("Не удалось связаться с KasperVPN: {last_error}"))
    }

    pub async fn me(&self) -> Result<Account, String> {
        let mut last_error = String::new();
        for base in &self.bases {
            let res = self
                .client
                .get(format!("{}/api/me", base))
                .send()
                .await;
            match res {
                Ok(response) => {
                    let status = response.status();
                    let value: Value = response
                        .json()
                        .await
                        .map_err(|e| format!("Некорректный ответ профиля: {e}"))?;
                    if !status.is_success() || value.get("ok").and_then(Value::as_bool) == Some(false) {
                        return Err(message(&value)
                            .unwrap_or("Требуется войти в KasperVPN")
                            .to_string());
                    }
                    let used_mb = value
                        .get("usedMB")
                        .map(|v| match v {
                            Value::String(s) => s.clone(),
                            Value::Number(n) => n.to_string(),
                            _ => String::new(),
                        })
                        .unwrap_or_default();
                    let account: Account = serde_json::from_value(value)
                        .map_err(|e| format!("Ответ профиля не соответствует API: {e}"))?;
                    validate_vless(&account.vless_link)?;
                    return Ok(Account { used_mb, ..account });
                }
                Err(err) => {
                    last_error = format!("{err}");
                }
            }
        }
        Err(format!("Не удалось получить профиль KasperVPN: {last_error}"))
    }

    pub async fn logout(&self) -> Result<(), String> {
        for base in &self.bases {
            let _ = self.client.get(format!("{}/api/logout", base)).send().await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        extract::State,
        http::{Request, StatusCode},
        response::IntoResponse,
        routing::get,
    };
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct FakeState(Arc<Mutex<Vec<String>>>);

    async fn me(State(state): State<FakeState>, request: Request<Body>) -> impl IntoResponse {
        let cookie = request
            .headers()
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        state.0.lock().unwrap().push(cookie.to_string());
        if !cookie.contains("auth_user=tester") {
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({"error":"Не авторизован"})),
            )
                .into_response();
        }
        axum::Json(serde_json::json!({
            "username":"tester", "vlessLink":"vless://example-uuid@example.com:443?security=tls",
            "usedMB":"12.50", "usedGB":"0.01", "totalGB":"70", "percentage":1,
            "isAdmin":false, "createdAt":"2026-01-01"
        }))
        .into_response()
    }

    async fn login(_state: State<FakeState>, request: Request<Body>) -> impl IntoResponse {
        use axum::body::to_bytes;
        let body = to_bytes(request.into_body(), 4096).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["username"], "tester");
        let password = body["password"].as_str().unwrap();
        assert!(!password.is_empty());
        assert!(body.get("token").is_none());
        (
            StatusCode::OK,
            [("set-cookie", "auth_user=tester; HttpOnly; Path=/")],
            axum::Json(serde_json::json!({"ok":true,"username":"tester","isAdmin":false})),
        )
    }

    #[tokio::test]
    async fn login_cookie_retrieves_profile_and_vless_link() {
        let state = FakeState::default();
        let app = Router::new()
            .route("/api/login", axum::routing::post(login))
            .route("/api/me", get(me))
            .with_state(state.clone());
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(server, app).await.unwrap();
        });
        let client = AccountClient::with_base(&format!("http://{address}")).unwrap();
        let login = client.login("tester", "not-a-real-secret").await.unwrap();
        assert_eq!(login.username, "tester");
        let account = client.me().await.unwrap();
        assert_eq!(account.username, "tester");
        assert_eq!(
            account.vless_link,
            "vless://example-uuid@example.com:443?security=tls"
        );
        let seen = state.0.lock().unwrap();
        assert_eq!(seen.as_slice(), &["auth_user=tester"]);
        assert_eq!(account.used_mb, "12.50");
    }

    #[test]
    fn rejects_non_vless_profile_links() {
        assert!(validate_vless("https://example.com").is_err());
        assert!(validate_vless("vless://example.com").is_err());
        assert!(validate_vless("vless://uuid@example.com:443").is_ok());
    }
}
