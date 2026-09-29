//! Opt-in end-to-end test for the official local sandbox preview.

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use huifu_pay_sdk::{
    Client, Config, PaymentQueryRequest, PreorderRequest, RefundQueryRequest, RefundRequest,
};
use serde_json::{Value, json};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

fn sequence(prefix: &str) -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default();
    format!("{prefix}{millis}")
}

fn client() -> Client {
    Client::new(Config {
        base_url: env("HUIFU_SANDBOX_URL"),
        sys_id: env("HUIFU_SANDBOX_SYS_ID"),
        product_id: env("HUIFU_SANDBOX_PRODUCT_ID"),
        huifu_id: env("HUIFU_SANDBOX_HUIFU_ID"),
        merchant_private_key: fs::read_to_string(env("HUIFU_SANDBOX_PRIVATE_KEY_FILE"))
            .unwrap_or_else(|e| panic!("private key: {e}")),
        huifu_public_key: fs::read_to_string(env("HUIFU_SANDBOX_PUBLIC_KEY_FILE"))
            .unwrap_or_else(|e| panic!("public key: {e}")),
        skill_source: "hfps/1.3.1;sandbox/1.0.0".into(),
    })
    .unwrap_or_else(|e| panic!("client: {e}"))
}

async fn mark_hosted_payment_success(pre_order_id: &str, req_seq_id: &str) {
    let base = env("HUIFU_SANDBOX_CONTROL_URL");
    let token = env("HUIFU_SANDBOX_ADMIN_TOKEN");
    let http = reqwest::Client::new();
    let session: Value = http
        .get(format!("{}/__admin/session", base.trim_end_matches('/')))
        .bearer_auth(&token)
        .send()
        .await
        .expect("sandbox admin session request")
        .error_for_status()
        .expect("sandbox admin session status")
        .json()
        .await
        .expect("sandbox admin session JSON");
    let csrf = session
        .get("csrf_token")
        .and_then(Value::as_str)
        .expect("sandbox csrf_token");
    http.post(format!(
        "{}/__admin/hosting/success",
        base.trim_end_matches('/')
    ))
    .bearer_auth(token)
    .header("X-Huifu-Sandbox-CSRF", csrf)
    .json(&json!({"pre_order_id": pre_order_id, "req_seq_id": req_seq_id}))
    .send()
    .await
    .expect("sandbox hosted success request")
    .error_for_status()
    .expect("sandbox hosted success status");
}

#[tokio::test]
#[ignore = "requires the separately downloaded Huifu local sandbox"]
async fn alipay_and_wechat_payment_query_refund_round_trip() {
    let client = client();
    let date = env("HUIFU_SANDBOX_DATE");
    for trans_type in ["A_NATIVE", "T_JSAPI"] {
        let pay_id = sequence(if trans_type == "A_NATIVE" {
            "ZSA"
        } else {
            "ZSW"
        });
        let created = client
            .preorder(&PreorderRequest {
                req_date: date.clone(),
                req_seq_id: pay_id.clone(),
                trans_amt: "0.01".into(),
                goods_desc: "Zebra Store sandbox order".into(),
                notify_url: "http://127.0.0.1:19999/huifu-notify".into(),
                callback_url: "http://127.0.0.1:19999/pay".into(),
                project_id: "P123".into(),
                project_title: "Zebra Store".into(),
                request_type: "P".into(),
                trans_type: trans_type.into(),
                ..PreorderRequest::default()
            })
            .await
            .unwrap_or_else(|e| panic!("preorder {trans_type}: {e}"));
        assert!(created.accepted(), "preorder response: {:?}", created.data);
        assert!(!created.string("jump_url").is_empty());
        assert!(!created.string("pre_order_id").is_empty());

        mark_hosted_payment_success(&created.string("pre_order_id"), &pay_id).await;

        let queried = client
            .query_payment(&PaymentQueryRequest {
                req_date: date.clone(),
                req_seq_id: sequence("ZSQ"),
                org_req_date: date.clone(),
                org_req_seq_id: pay_id.clone(),
            })
            .await
            .unwrap_or_else(|e| panic!("query {trans_type}: {e}"));
        assert!(queried.accepted(), "query response: {:?}", queried.data);
        assert_eq!(queried.string("trans_stat"), "S");

        let refund_id = sequence("ZSR");
        let refunded = client
            .refund(&RefundRequest {
                req_date: date.clone(),
                req_seq_id: refund_id.clone(),
                org_req_date: date.clone(),
                org_req_seq_id: pay_id,
                ord_amt: "0.01".into(),
                notify_url: "http://127.0.0.1:19999/huifu-notify".into(),
                remark: "sandbox refund".into(),
                client_ip: "127.0.0.1".into(),
            })
            .await
            .unwrap_or_else(|e| panic!("refund {trans_type}: {e}"));
        assert!(refunded.accepted(), "refund response: {:?}", refunded.data);

        let refund_query = client
            .query_refund(&RefundQueryRequest {
                req_date: date.clone(),
                req_seq_id: sequence("ZSRQ"),
                org_req_date: date.clone(),
                org_req_seq_id: refund_id,
            })
            .await
            .unwrap_or_else(|e| panic!("refund query {trans_type}: {e}"));
        assert!(
            refund_query.accepted(),
            "refund query: {:?}",
            refund_query.data
        );
        assert!(matches!(
            refund_query.string("trans_stat").as_str(),
            "P" | "S"
        ));
    }
}
