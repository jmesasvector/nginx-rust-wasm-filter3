extern crate jsonwebtoken as jwt;
extern crate reqwest;
extern crate serde;
extern crate serde_json;

use jwt::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio; // Importar Tokio para el contexto async

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

fn validate_jws(token: &str, public_key: &str) -> Result<Claims, jwt::errors::Error> {
    let key = DecodingKey::from_rsa_pem(public_key.as_bytes())?;
    let validation = Validation::new(Algorithm::RS256);
    let token_data = decode::<Claims>(token, &key, &validation)?;
    Ok(token_data.claims)
}

fn is_token_expired(exp: usize) -> bool {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as usize;
    exp < current_time
}

pub async fn handle_request(headers: &str, public_key: &str) -> Result<String, Box<dyn std::error::Error>> {
    let token = extract_jws_from_headers(headers).ok_or("Token not found")?;
    let claims = validate_jws(&token, public_key)?;
    if is_token_expired(claims.exp) {
        return Err("Token expired".into());
    }
    let response = call_microservice().await?;
    Ok(response)
}

fn extract_jws_from_headers(headers: &str) -> Option<String> {
    headers.lines().find_map(|line| {
        if line.starts_with("Authorization: Bearer") {
            Some(line[22..].trim().to_string())
        } else {
            None
        }
    })
}

async fn call_microservice() -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let res = client.get("http://microservice.url/api/data")
        .header("Authorization", "Bearer fixed_jwt_token")
        .send()
        .await?; // Cambiado a await aquí

    Ok(res.text().await?) // Cambiado a await aquí
}
