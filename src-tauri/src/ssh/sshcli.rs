#![allow(unused)]
use async_trait::async_trait;
use russh::*;
use russh_keys::ssh_key;
use russh_keys::HashAlg::Sha512;
use russh_keys::{decode_secret_key, key::PrivateKeyWithHashAlg};
use std::fs;
use std::sync::Arc;

#[derive(Clone)]
pub enum AuthMethod {
    Password(String),
    PrivateKey {
        key: String,
        passphrase: Option<String>,
    },
    Interactive,
    None,
}

#[derive(Clone)]
pub struct SshConfig {
    pub username: Option<String>,
    pub hostname: String,
    pub port: u16,
    pub auth_method: AuthMethod,
    pub encoding: Option<String>,
    pub win_width: u16,
    pub win_height: u16,
}

impl SshConfig {
    fn validate_config(config: &SshConfig) -> Result<(), String> {
        if config.hostname.is_empty() {
            return Err("Hostname cannot be empty.".to_string());
        }

        if config.port == 0 {
            return Err("Port must be between 1 and 65535.".to_string());
        }

        match &config.auth_method {
            AuthMethod::Password(password) => {
                if password.is_empty() {
                    return Err("Password cannot be empty.".to_string());
                }
            }
            AuthMethod::PrivateKey { key, .. } => {
                if key.is_empty() {
                    return Err("Private key cannot be empty.".to_string());
                }
            }
            AuthMethod::Interactive => {}
            AuthMethod::None => {}
        }

        Ok(())
    }
}

struct CliHandler {}

#[async_trait]
impl russh::client::Handler for CliHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        let _ = server_public_key;
        Ok(true)
    }
}

pub struct SshClient {
    pub config: SshConfig,
    pub session: Option<client::Session>,
}

impl SshClient {
    pub fn new(config: &SshConfig) -> Result<Self, String> {
        SshConfig::validate_config(&config)?;
        Ok(Self {
            config: config.clone(),
            session: None,
        })
    }

    async fn authenticate_with_password(
        &self,
        session: &mut client::Handle<CliHandler>,
        username: &str,
        password: &str,
    ) -> Result<(), String> {
        session
            .authenticate_password(username, password.to_string())
            .await
            .map_err(|e| format!("Password authentication failed: {}", e))?;
        println!("Password authentication successful.");
        Ok(())
    }

    async fn authenticate_with_publick_key(
        &self,
        session: &mut client::Handle<CliHandler>,
        username: &str,
        key: &str,
        passphrase: &Option<String>,
    ) -> Result<(), String> {
        let key_pair = decode_secret_key(key, passphrase.as_deref())
            .map_err(|e| format!("Failed to load private key: {}", e))?;
        let private_key_with_hash_alg =
            PrivateKeyWithHashAlg::new(Arc::new(key_pair), Some(Sha512))
                .map_err(|e| format!("Failed to create private key with hash algorithm: {}", e))?;
        session
            .authenticate_publickey(username, private_key_with_hash_alg)
            .await
            .map_err(|e| format!("Private key authentication failed: {}", e))?;
        println!("Private key authentication successful.");
        Ok(())
    }

    pub async fn connect(&mut self) -> Result<(), String> {
        let host = self.config.hostname.clone();
        let port = self.config.port;
        let username = self.config.username.clone().unwrap_or("root".to_string());

        let config = client::Config {
            inactivity_timeout: Some(std::time::Duration::from_secs(5)),
            ..<_>::default()
        };

        let config = Arc::new(config);
        let handler = CliHandler {};
        let mut session: client::Handle<_> =
            match client::connect(config, (host, port), handler).await {
                Ok(session) => session,
                Err(e) => return Err(format!("Failed to connect: {}", e)),
            };

        match &self.config.auth_method {
            AuthMethod::Password(password) => {
                self.authenticate_with_password(&mut session, &username, password)
                    .await?;
            }
            AuthMethod::PrivateKey { key, passphrase } => {
                self.authenticate_with_publick_key(&mut session, &username, key, passphrase)
                    .await?;
            }
            _ => {
                return Err("Unsupported authentication method.".to_string());
            }
        }
        Ok(())
    }
}

#[tokio::test]
async fn test_ssh_client_connect_password_auth() {
    let config = SshConfig {
        username: Some("ryan".to_string()),
        hostname: "127.0.0.1".to_string(),
        port: 22,
        auth_method: AuthMethod::Password("passwordryan".to_string()),
        encoding: None,
        win_width: 80,
        win_height: 24,
    };

    let mut client = match SshClient::new(&config) {
        Ok(client) => client,
        Err(e) => {
            panic!("Failed to create SSH client: {}", e);
        }
    };

    let result = client.connect().await;
    assert!(result.is_ok(), "SSH connection failed: {:?}", result);
}

#[tokio::test]
async fn test_ssh_client_connect_private_key_auth() {
    let private_key_path = "/Users/ryan/.ssh/id_rsa";
    let private_key_content = match fs::read_to_string(private_key_path) {
        Ok(content) => content,
        Err(e) => panic!(
            "Failed to read private key from {}: {}",
            private_key_path, e
        ),
    };

    let config = SshConfig {
        username: Some("ryan".to_string()),
        hostname: "127.0.0.1".to_string(),
        port: 22,
        auth_method: AuthMethod::PrivateKey {
            key: private_key_content,
            passphrase: None,
        },
        encoding: None,
        win_width: 80,
        win_height: 24,
    };

    let mut client = match SshClient::new(&config) {
        Ok(client) => client,
        Err(e) => {
            panic!("Failed to create SSH client: {}", e);
        }
    };

    let result = client.connect().await;
    assert!(
        result.is_ok(),
        "SSH connection failed with private key authentication: {:?}",
        result
    );
}
