//! Huifu Alipay and WeChat H5/PC payment SDK built for Zebra Store.
//!
//! The gateway signs the top-level `data` object with RSA-SHA256. Nested objects required by
//! Huifu remain JSON strings at the protocol boundary. Transaction notifications are verified
//! against their original `resp_data` bytes; console webhooks use a separate MD5 endpoint key.
//! This crate covers hosted Alipay/WeChat collection, payment query, transaction notification,
//! original-route refund and refund query. It is not a complete Huifu product SDK.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use md5::{Digest as _, Md5};
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::Sha256;
use subtle::ConstantTimeEq;

pub const DEFAULT_BASE_URL: &str = "https://api.huifu.com";
pub const DEFAULT_SKILL_SOURCE: &str = "hfps/1.3.5";
pub const PREORDER_PATH: &str = "/v2/trade/hosting/payment/preorder";
pub const PAYMENT_QUERY_PATH: &str = "/v2/trade/hosting/payment/queryorderinfo";
pub const REFUND_PATH: &str = "/v2/trade/hosting/payment/htRefund";
pub const REFUND_QUERY_PATH: &str = "/v2/trade/hosting/payment/queryRefundInfo";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid Huifu configuration: {0}")]
    Config(String),
    #[error("invalid Huifu request: {0}")]
    Request(String),
    #[error("Huifu transport failed: {0}")]
    Transport(String),
    #[error("Huifu returned HTTP {0}")]
    Http(u16),
    #[error("invalid Huifu response: {0}")]
    Response(String),
    #[error("Huifu signature verification failed")]
    Signature,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub base_url: String,
    pub sys_id: String,
    pub product_id: String,
    pub huifu_id: String,
    pub merchant_private_key: String,
    pub huifu_public_key: String,
    pub skill_source: String,
}

impl Config {
    pub fn validate(&self) -> Result<(), Error> {
        for (name, value) in [
            ("sys_id", &self.sys_id),
            ("product_id", &self.product_id),
            ("huifu_id", &self.huifu_id),
            ("merchant_private_key", &self.merchant_private_key),
            ("huifu_public_key", &self.huifu_public_key),
        ] {
            if value.trim().is_empty() {
                return Err(Error::Config(format!("{name} is required")));
            }
        }
        let base = self.base_url.trim();
        if !(base.starts_with("https://")
            || base.starts_with("http://127.0.0.1:")
            || base.starts_with("http://localhost:"))
        {
            return Err(Error::Config(
                "base_url must use HTTPS (loopback HTTP is allowed for the local sandbox)".into(),
            ));
        }
        parse_private_key(&self.merchant_private_key)?;
        parse_public_key(&self.huifu_public_key)?;
        Ok(())
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.base_url.trim().trim_end_matches('/'), path)
    }

    fn source(&self) -> &str {
        let source = self.skill_source.trim();
        if source.is_empty() {
            DEFAULT_SKILL_SOURCE
        } else {
            source
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

#[async_trait]
pub trait Transport: Send + Sync + std::fmt::Debug {
    async fn post(&self, request: HttpRequest) -> Result<HttpResponse, Error>;
}

#[derive(Debug, Clone)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    pub fn new() -> Result<Self, Error> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| Error::Config(e.to_string()))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl Transport for ReqwestTransport {
    async fn post(&self, request: HttpRequest) -> Result<HttpResponse, Error> {
        let mut builder = self.client.post(request.url);
        for (name, value) in request.headers {
            builder = builder.header(name, value);
        }
        let response = builder
            .body(request.body)
            .send()
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .map_err(|e| Error::Transport(e.to_string()))?
            .to_vec();
        Ok(HttpResponse { status, body })
    }
}

#[derive(Debug, Clone)]
pub struct Client {
    config: Config,
    transport: Arc<dyn Transport>,
}

impl Client {
    pub fn new(config: Config) -> Result<Self, Error> {
        let transport = Arc::new(ReqwestTransport::new()?);
        Self::with_transport(config, transport)
    }

    pub fn with_transport(config: Config, transport: Arc<dyn Transport>) -> Result<Self, Error> {
        config.validate()?;
        Ok(Self { config, transport })
    }

    pub async fn preorder(&self, request: &PreorderRequest) -> Result<ApiResponse, Error> {
        request.validate()?;
        let hosting_data = json!({
            "callback_url": request.callback_url,
            "project_id": request.project_id,
            "project_title": request.project_title,
            "request_type": request.request_type,
        });
        let mut data = strings([
            ("goods_desc", request.goods_desc.as_str()),
            ("hosting_data", canonical_json(&hosting_data)?.as_str()),
            ("huifu_id", self.config.huifu_id.as_str()),
            ("notify_url", request.notify_url.as_str()),
            ("pre_order_type", "1"),
            ("req_date", request.req_date.as_str()),
            ("req_seq_id", request.req_seq_id.as_str()),
            ("trans_amt", request.trans_amt.as_str()),
            ("trans_type", request.trans_type.as_str()),
        ]);
        if !request.time_expire.trim().is_empty() {
            data.insert(
                "time_expire".into(),
                Value::String(request.time_expire.clone()),
            );
        }
        self.post(PREORDER_PATH, data).await
    }

    pub async fn query_payment(&self, request: &PaymentQueryRequest) -> Result<ApiResponse, Error> {
        request.validate()?;
        self.post(
            PAYMENT_QUERY_PATH,
            strings([
                ("huifu_id", self.config.huifu_id.as_str()),
                ("org_req_date", request.org_req_date.as_str()),
                ("org_req_seq_id", request.org_req_seq_id.as_str()),
                ("req_date", request.req_date.as_str()),
                ("req_seq_id", request.req_seq_id.as_str()),
            ]),
        )
        .await
    }

    pub async fn refund(&self, request: &RefundRequest) -> Result<ApiResponse, Error> {
        request.validate()?;
        let mut data = strings([
            ("huifu_id", self.config.huifu_id.as_str()),
            ("notify_url", request.notify_url.as_str()),
            ("ord_amt", request.ord_amt.as_str()),
            ("org_req_date", request.org_req_date.as_str()),
            ("org_req_seq_id", request.org_req_seq_id.as_str()),
            ("req_date", request.req_date.as_str()),
            ("req_seq_id", request.req_seq_id.as_str()),
        ]);
        if !request.remark.trim().is_empty() {
            data.insert("remark".into(), Value::String(request.remark.clone()));
        }
        if !request.client_ip.trim().is_empty() {
            data.insert(
                "risk_check_data".into(),
                Value::String(canonical_json(&json!({"ip_addr": request.client_ip}))?),
            );
            data.insert(
                "terminal_device_data".into(),
                Value::String(canonical_json(
                    &json!({"device_ip": request.client_ip, "device_type": "4"}),
                )?),
            );
        }
        self.post(REFUND_PATH, data).await
    }

    pub async fn query_refund(&self, request: &RefundQueryRequest) -> Result<ApiResponse, Error> {
        request.validate()?;
        self.post(
            REFUND_QUERY_PATH,
            strings([
                ("huifu_id", self.config.huifu_id.as_str()),
                ("org_req_date", request.org_req_date.as_str()),
                ("org_req_seq_id", request.org_req_seq_id.as_str()),
                ("req_date", request.req_date.as_str()),
                ("req_seq_id", request.req_seq_id.as_str()),
            ]),
        )
        .await
    }

    pub fn verify_notify(&self, sign: &str, resp_data: &str) -> Result<Notify, Error> {
        verify_bytes(&self.config.huifu_public_key, resp_data.as_bytes(), sign)?;
        let data: Map<String, Value> = serde_json::from_str(resp_data)
            .map_err(|e| Error::Response(format!("notify resp_data is not an object: {e}")))?;
        Ok(Notify { data })
    }

    async fn post(&self, path: &str, data: Map<String, Value>) -> Result<ApiResponse, Error> {
        let data_value = Value::Object(data);
        let sign = sign_value(&self.config.merchant_private_key, &data_value)?;
        let envelope = json!({
            "data": data_value,
            "product_id": self.config.product_id,
            "sign": sign,
            "sys_id": self.config.sys_id,
        });
        let response = self
            .transport
            .post(HttpRequest {
                url: self.config.endpoint(path),
                headers: vec![
                    (
                        "content-type".into(),
                        "application/json;charset=UTF-8".into(),
                    ),
                    ("jpt-x-skill-source".into(), self.config.source().to_owned()),
                    ("jpt-x-skill-huifu_id".into(), self.config.huifu_id.clone()),
                ],
                body: canonical_json(&envelope)?.into_bytes(),
            })
            .await?;
        if !(200..300).contains(&response.status) {
            return Err(Error::Http(response.status));
        }
        let envelope: ResponseEnvelope = serde_json::from_slice(&response.body)
            .map_err(|e| Error::Response(format!("invalid JSON envelope: {e}")))?;
        if envelope.sign.trim().is_empty() {
            return Err(Error::Response("response sign is missing".into()));
        }
        verify_value(
            &self.config.huifu_public_key,
            &envelope.data,
            &envelope.sign,
        )?;
        let data = envelope
            .data
            .as_object()
            .cloned()
            .ok_or_else(|| Error::Response("response data is not an object".into()))?;
        Ok(ApiResponse { data })
    }
}

#[derive(Debug, Clone, Default)]
pub struct PreorderRequest {
    pub req_date: String,
    pub req_seq_id: String,
    pub trans_amt: String,
    pub goods_desc: String,
    pub notify_url: String,
    pub callback_url: String,
    pub project_id: String,
    pub project_title: String,
    pub request_type: String,
    pub trans_type: String,
    pub time_expire: String,
}

impl PreorderRequest {
    fn validate(&self) -> Result<(), Error> {
        required([
            ("req_date", self.req_date.as_str()),
            ("req_seq_id", self.req_seq_id.as_str()),
            ("trans_amt", self.trans_amt.as_str()),
            ("goods_desc", self.goods_desc.as_str()),
            ("notify_url", self.notify_url.as_str()),
            ("project_id", self.project_id.as_str()),
            ("project_title", self.project_title.as_str()),
            ("request_type", self.request_type.as_str()),
            ("trans_type", self.trans_type.as_str()),
        ])?;
        if !matches!(self.trans_type.as_str(), "A_NATIVE" | "A_JSAPI" | "T_JSAPI") {
            return Err(Error::Request(
                "only Alipay and WeChat trans_type values are supported".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct PaymentQueryRequest {
    pub req_date: String,
    pub req_seq_id: String,
    pub org_req_date: String,
    pub org_req_seq_id: String,
}

impl PaymentQueryRequest {
    fn validate(&self) -> Result<(), Error> {
        required([
            ("req_date", self.req_date.as_str()),
            ("req_seq_id", self.req_seq_id.as_str()),
            ("org_req_date", self.org_req_date.as_str()),
            ("org_req_seq_id", self.org_req_seq_id.as_str()),
        ])
    }
}

#[derive(Debug, Clone, Default)]
pub struct RefundRequest {
    pub req_date: String,
    pub req_seq_id: String,
    pub org_req_date: String,
    pub org_req_seq_id: String,
    pub ord_amt: String,
    pub notify_url: String,
    pub remark: String,
    pub client_ip: String,
}

impl RefundRequest {
    fn validate(&self) -> Result<(), Error> {
        required([
            ("req_date", self.req_date.as_str()),
            ("req_seq_id", self.req_seq_id.as_str()),
            ("org_req_date", self.org_req_date.as_str()),
            ("org_req_seq_id", self.org_req_seq_id.as_str()),
            ("ord_amt", self.ord_amt.as_str()),
        ])
    }
}

#[derive(Debug, Clone, Default)]
pub struct RefundQueryRequest {
    pub req_date: String,
    pub req_seq_id: String,
    pub org_req_date: String,
    pub org_req_seq_id: String,
}

impl RefundQueryRequest {
    fn validate(&self) -> Result<(), Error> {
        required([
            ("req_date", self.req_date.as_str()),
            ("req_seq_id", self.req_seq_id.as_str()),
            ("org_req_date", self.org_req_date.as_str()),
            ("org_req_seq_id", self.org_req_seq_id.as_str()),
        ])
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApiResponse {
    pub data: Map<String, Value>,
}

impl ApiResponse {
    pub fn string(&self, key: &str) -> String {
        self.data
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_owned()
    }

    pub fn accepted(&self) -> bool {
        matches!(self.string("resp_code").as_str(), "00000000" | "00000100")
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Notify {
    pub data: Map<String, Value>,
}

impl Notify {
    pub fn string(&self, key: &str) -> String {
        self.data
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_owned()
    }

    pub fn ack(&self) -> Result<String, Error> {
        let req_seq_id = self.string("req_seq_id");
        if req_seq_id.is_empty() {
            return Err(Error::Response("notify req_seq_id is missing".into()));
        }
        Ok(format!("RECV_ORD_ID_{req_seq_id}"))
    }
}

#[derive(Debug, Deserialize)]
struct ResponseEnvelope {
    sign: String,
    data: Value,
}

#[derive(Serialize)]
struct SortedObject<'a>(BTreeMap<&'a str, &'a Value>);

pub fn canonical_json(value: &Value) -> Result<String, Error> {
    match value {
        Value::Object(map) => {
            let sorted = map.iter().map(|(k, v)| (k.as_str(), v)).collect();
            serde_json::to_string(&SortedObject(sorted)).map_err(|e| Error::Request(e.to_string()))
        }
        _ => serde_json::to_string(value).map_err(|e| Error::Request(e.to_string())),
    }
}

pub fn sign_value(private_key: &str, value: &Value) -> Result<String, Error> {
    let canonical = canonical_json(value)?;
    let key = parse_private_key(private_key)?;
    let digest = Sha256::digest(canonical.as_bytes());
    let signature = key
        .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
        .map_err(|e| Error::Config(format!("RSA signing failed: {e}")))?;
    Ok(B64.encode(signature))
}

pub fn verify_value(public_key: &str, value: &Value, sign: &str) -> Result<(), Error> {
    verify_bytes(public_key, canonical_json(value)?.as_bytes(), sign)
}

pub fn verify_bytes(public_key: &str, content: &[u8], sign: &str) -> Result<(), Error> {
    let key = parse_public_key(public_key)?;
    let signature = B64.decode(sign.trim()).map_err(|_| Error::Signature)?;
    let digest = Sha256::digest(content);
    key.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &signature)
        .map_err(|_| Error::Signature)
}

pub fn verify_webhook(raw_body: &[u8], endpoint_key: &str, sign: &str) -> bool {
    if endpoint_key.is_empty() || sign.trim().is_empty() {
        return false;
    }
    let mut hash = Md5::new();
    hash.update(raw_body);
    hash.update(endpoint_key.as_bytes());
    let expected = format!("{:X}", hash.finalize());
    let got = sign.trim().to_ascii_uppercase();
    expected.len() == got.len() && bool::from(expected.as_bytes().ct_eq(got.as_bytes()))
}

fn strings<const N: usize>(items: [(&str, &str); N]) -> Map<String, Value> {
    items
        .into_iter()
        .filter(|(_, value)| !value.trim().is_empty())
        .map(|(key, value)| (key.to_owned(), Value::String(value.to_owned())))
        .collect()
}

fn required<const N: usize>(items: [(&str, &str); N]) -> Result<(), Error> {
    for (name, value) in items {
        if value.trim().is_empty() {
            return Err(Error::Request(format!("{name} is required")));
        }
    }
    Ok(())
}

fn key_body(raw: &str) -> String {
    raw.lines()
        .filter(|line| !line.starts_with("-----"))
        .map(str::trim)
        .collect()
}

fn parse_private_key(raw: &str) -> Result<RsaPrivateKey, Error> {
    let trimmed = raw.trim();
    if trimmed.contains("BEGIN") {
        RsaPrivateKey::from_pkcs8_pem(trimmed)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(trimmed))
            .map_err(|_| Error::Config("merchant_private_key is not PKCS8/PKCS1 RSA".into()))
    } else {
        let der = B64
            .decode(key_body(trimmed))
            .map_err(|_| Error::Config("merchant_private_key is not Base64".into()))?;
        RsaPrivateKey::from_pkcs8_der(&der)
            .or_else(|_| RsaPrivateKey::from_pkcs1_der(&der))
            .map_err(|_| Error::Config("merchant_private_key is not PKCS8/PKCS1 RSA".into()))
    }
}

fn parse_public_key(raw: &str) -> Result<RsaPublicKey, Error> {
    let trimmed = raw.trim();
    if trimmed.contains("BEGIN") {
        RsaPublicKey::from_public_key_pem(trimmed)
            .or_else(|_| RsaPublicKey::from_pkcs1_pem(trimmed))
            .map_err(|_| Error::Config("huifu_public_key is not X509/PKCS1 RSA".into()))
    } else {
        let der = B64
            .decode(key_body(trimmed))
            .map_err(|_| Error::Config("huifu_public_key is not Base64".into()))?;
        RsaPublicKey::from_public_key_der(&der)
            .or_else(|_| RsaPublicKey::from_pkcs1_der(&der))
            .map_err(|_| Error::Config("huifu_public_key is not X509/PKCS1 RSA".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use rsa::rand_core::OsRng;

    fn keys() -> (String, String) {
        let private = RsaPrivateKey::new(&mut OsRng, 2048).unwrap_or_else(|e| panic!("{e}"));
        let public = RsaPublicKey::from(&private);
        (
            private
                .to_pkcs8_pem(LineEnding::LF)
                .unwrap_or_else(|e| panic!("{e}"))
                .to_string(),
            public
                .to_public_key_pem(LineEnding::LF)
                .unwrap_or_else(|e| panic!("{e}")),
        )
    }

    #[test]
    fn canonical_json_sorts_top_level_and_preserves_string_json() {
        let value = json!({"z":"last","a":"<tag>&","nested":"{\"b\":2,\"a\":1}"});
        assert_eq!(
            canonical_json(&value).ok().as_deref(),
            Some(r#"{"a":"<tag>&","nested":"{\"b\":2,\"a\":1}","z":"last"}"#)
        );
    }

    #[test]
    fn rsa_round_trip_and_tamper_rejection() {
        let (private, public) = keys();
        let value = json!({"trans_amt":"0.01","req_seq_id":"R1"});
        let sign = sign_value(&private, &value).unwrap_or_else(|e| panic!("{e}"));
        assert!(verify_value(&public, &value, &sign).is_ok());
        assert!(
            verify_value(
                &public,
                &json!({"trans_amt":"0.02","req_seq_id":"R1"}),
                &sign
            )
            .is_err()
        );
    }

    #[test]
    fn notify_ack_and_webhook_signature_are_distinct() {
        let body = br#"{"event":"payment.succeeded","amount":"0.10"}"#;
        let key = "0123456789abcdef0123456789abcdef";
        let mut hash = Md5::new();
        hash.update(body);
        hash.update(key.as_bytes());
        let sign = format!("{:x}", hash.finalize());
        assert!(verify_webhook(body, key, &sign));
        assert!(!verify_webhook(br#"{"amount":"0.11"}"#, key, &sign));
        let notify = Notify {
            data: strings([("req_seq_id", "ORDER-1")]),
        };
        assert_eq!(notify.ack().ok().as_deref(), Some("RECV_ORD_ID_ORDER-1"));
    }
}
