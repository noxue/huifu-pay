# huifu-pay

[中文](README.md) · [Register with the Zebra Store Huifu invitation](https://paas.huifu.com/login?inviteCode=TAXG4QKSR) · [Huifu documentation](https://paas.huifu.com/docs/devtools/#/skillsv1_0)

A Huifu Rust SDK dedicated to Alipay and WeChat H5/PC payments. It implements the complete Zebra Store payment loop: hosted Alipay (`A_NATIVE`) and WeChat (`T_JSAPI`) collection, payment query, RSA-SHA256 response and transaction-notification verification, dynamic notification acknowledgements, original-route refund, refund query, trade-bill query and secure download, and console-webhook MD5 verification. It is not a collection of every Huifu product API.

This library is developed for [Zebra Store](https://github.com/noxue/zebra-store) and is its underlying Huifu payment SDK. Its API remains independent so other Rust services can use it as well.

Merchant onboarding, account opening, card binding, split/settlement/withdrawal bills, mini-program/openid flows, native Alipay or WeChat integrations, and other Huifu products are outside this crate's scope. Only the `TRADE_BILL` used to reconcile the supported Alipay and WeChat payments is included.

Add it from Git:

```toml
huifu-pay = "0.2"
```

For personal Huifu onboarding, start with the [Zebra Store invitation link](https://paas.huifu.com/login?inviteCode=TAXG4QKSR). Contacting Huifu support through its official WeChat support or group after registration can make the application process faster.

See the [Chinese README](README.md) for configuration, complete examples, personal onboarding material, callback rules, local-sandbox verification, and security boundaries. The public API is documented with Rustdoc:

```bash
cargo doc --open
```

The built-in HTTP client rejects redirects, uses a bounded timeout, requires HTTPS in production, and permits plain HTTP only on loopback for the official local sandbox. A custom `Transport` can be injected for application-level network controls and deterministic tests.

Run checks with:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

Licensed under [AGPL-3.0](LICENSE).
