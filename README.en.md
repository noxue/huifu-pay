# huifu-pay

[中文](README.md) · [Huifu documentation](https://paas.huifu.com/docs/devtools/#/skillsv1_0)

A Huifu Rust SDK dedicated to Alipay and WeChat H5/PC payments. It implements the complete Zebra Store payment loop: hosted Alipay (`A_NATIVE`) and WeChat (`T_JSAPI`) collection, payment query, RSA-SHA256 response and transaction-notification verification, dynamic notification acknowledgements, original-route refund, refund query, and console-webhook MD5 verification. It is not a collection of every Huifu product API.

This library is developed for [Zebra Store](https://github.com/noxue/zebra-store) and is its underlying Huifu payment SDK. Its API remains independent so other Rust services can use it as well.

Merchant onboarding, account opening, card binding, split settlement, withdrawals, reconciliation files, mini-program/openid flows, native Alipay or WeChat integrations, and other Huifu products are outside this crate's scope.

Add it from Git:

```toml
huifu-pay = "0.1"
```

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
