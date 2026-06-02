use std::env;

pub struct Config {
    pub notion_client_id: String,
    pub notion_client_secret: String,
    pub notion_base_url: String,
    pub hmac_secret: Vec<u8>,
    pub allowed_origins: String,
    pub sentry_dsn: String,
    pub port: String,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            notion_client_id: env::var("NOTION_CLIENT_ID").expect("NOTION_CLIENT_ID is required"),
            notion_client_secret: env::var("NOTION_CLIENT_SECRET")
                .expect("NOTION_CLIENT_SECRET is required"),
            notion_base_url: env::var("NOTION_BASE_URL")
                .unwrap_or_else(|_| "https://api.notion.com".into()),
            hmac_secret: env::var("PROXY_HMAC_SECRET")
                .expect("PROXY_HMAC_SECRET is required")
                .into_bytes(),
            allowed_origins: env::var("ALLOWED_ORIGINS").unwrap_or_default(),
            sentry_dsn: env::var("SENTRY_DSN").unwrap_or_default(),
            port: env::var("PORT").unwrap_or_else(|_| "3000".into()),
        }
    }

    pub fn is_lambda() -> bool {
        env::var("AWS_LAMBDA_FUNCTION_NAME").is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    const ALL_VARS: &[&str] = &[
        "NOTION_CLIENT_ID",
        "NOTION_CLIENT_SECRET",
        "PROXY_HMAC_SECRET",
        "NOTION_BASE_URL",
        "ALLOWED_ORIGINS",
        "SENTRY_DSN",
        "PORT",
        "AWS_LAMBDA_FUNCTION_NAME",
    ];

    fn clear_env() {
        for v in ALL_VARS {
            env::remove_var(v);
        }
    }

    fn set_required() {
        env::set_var("NOTION_CLIENT_ID", "cid");
        env::set_var("NOTION_CLIENT_SECRET", "csec");
        env::set_var("PROXY_HMAC_SECRET", "hmac-key");
    }

    #[test]
    #[serial]
    fn from_env_reads_required_vars() {
        clear_env();
        set_required();

        let cfg = Config::from_env();
        assert_eq!(cfg.notion_client_id, "cid");
        assert_eq!(cfg.notion_client_secret, "csec");
        assert_eq!(cfg.hmac_secret, b"hmac-key");
    }

    #[test]
    #[serial]
    fn from_env_applies_defaults_for_optional_vars() {
        clear_env();
        set_required();

        let cfg = Config::from_env();
        assert_eq!(cfg.notion_base_url, "https://api.notion.com");
        assert_eq!(cfg.port, "3000");
        assert_eq!(cfg.sentry_dsn, "");
        assert_eq!(cfg.allowed_origins, "");
    }

    #[test]
    #[serial]
    fn from_env_uses_overrides_when_set() {
        clear_env();
        set_required();
        env::set_var("NOTION_BASE_URL", "http://mock.local");
        env::set_var("PORT", "8080");
        env::set_var("ALLOWED_ORIGINS", "https://a.com,https://b.com");
        env::set_var("SENTRY_DSN", "https://sentry.example/1");

        let cfg = Config::from_env();
        assert_eq!(cfg.notion_base_url, "http://mock.local");
        assert_eq!(cfg.port, "8080");
        assert_eq!(cfg.allowed_origins, "https://a.com,https://b.com");
        assert_eq!(cfg.sentry_dsn, "https://sentry.example/1");
    }

    #[test]
    #[serial]
    fn is_lambda_tracks_aws_env_var() {
        env::remove_var("AWS_LAMBDA_FUNCTION_NAME");
        assert!(!Config::is_lambda());

        env::set_var("AWS_LAMBDA_FUNCTION_NAME", "my-fn");
        assert!(Config::is_lambda());

        env::remove_var("AWS_LAMBDA_FUNCTION_NAME");
    }

    #[test]
    #[serial]
    #[should_panic(expected = "NOTION_CLIENT_ID")]
    fn from_env_panics_without_client_id() {
        clear_env();
        Config::from_env();
    }

    #[test]
    #[serial]
    #[should_panic(expected = "PROXY_HMAC_SECRET")]
    fn from_env_panics_without_hmac_secret() {
        clear_env();
        env::set_var("NOTION_CLIENT_ID", "cid");
        env::set_var("NOTION_CLIENT_SECRET", "csec");
        Config::from_env();
    }
}
