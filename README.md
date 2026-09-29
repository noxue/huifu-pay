# huifu-pay

[English](README.en.md) · [汇付开发文档](https://paas.huifu.com/docs/devtools/#/skillsv1_0) · [Zebra Store](https://github.com/noxue/zebra-store)

汇付斗拱支付 Rust SDK，专用于支付宝、微信 H5 和 PC 收款，并覆盖 Zebra Store 电商支付所需的完整处理闭环。本库不是汇付全部产品接口的集合。

本库为 [Zebra Store](https://github.com/noxue/zebra-store) 开发，并作为 Zebra Store 的汇付支付底层 SDK 使用。接口保持独立，因此也可以集成到其他 Rust 服务。

- 支付宝托管支付（`A_NATIVE`）
- 微信托管支付（`T_JSAPI`）
- 支付查询
- RSA-SHA256 异步通知验签与动态 ACK
- 原路退款与退款查询
- 控制台 Webhook 的 MD5 验签
- 可注入 HTTP Transport，方便离线测试和业务系统统一管控网络请求

### 支持范围

| 能力 | 状态 |
| --- | --- |
| 支付宝托管 H5/PC 收款 | 支持 |
| 微信托管 H5/PC 收款 | 支持 |
| 支付订单查询 | 支持 |
| 交易通知 RSA 验签与 ACK | 支持 |
| 原路退款 | 支持 |
| 退款查询 | 支持 |
| 控制台 Webhook MD5 验签 | 支持 |
| 商户进件、开户、绑卡 | 不支持 |
| 分账、结算、提现 | 不支持 |
| 对账单下载与对账 | 不支持 |
| 微信小程序/公众号 openid 模式 | 不支持 |
| 支付宝/微信原生直连 SDK | 不支持 |
| 汇付其他产品和完整接口集合 | 不支持 |

SDK 只支持表中标记为“支持”的接口。生产环境默认仅允许 HTTPS；本地官方沙箱允许 `127.0.0.1` 或 `localhost` 的 HTTP 地址。HTTP 客户端不自动跟随重定向。

## 安装

```toml
[dependencies]
huifu-pay = "0.1"
```

需要跟踪尚未发布的提交时，也可以使用 Git 依赖：

```toml
huifu-pay = { git = "https://github.com/noxue/huifu-pay" }
```

## 配置

需要从汇付商户平台取得以下参数：

| 参数 | 用途 |
| --- | --- |
| `sys_id` | 系统号 |
| `product_id` | 产品号 |
| `huifu_id` | 汇付商户号 |
| `merchant_private_key` | 商户 RSA 私钥，用于请求签名 |
| `huifu_public_key` | 汇付 RSA 公钥，用于响应和交易通知验签 |
| `skill_source` | 来源标识，生产环境默认 `hfps/1.3.5` |

密钥可使用 PEM，或去掉 PEM 头尾与换行后的 Base64。私钥不要提交到 Git，也不要记录到日志。

## 创建托管支付

```rust,no_run
use huifu_pay::{Client, Config, PreorderRequest};

# async fn run() -> Result<(), huifu_pay::Error> {
let client = Client::new(Config {
    base_url: "https://api.huifu.com".into(),
    sys_id: std::env::var("HUIFU_SYS_ID").unwrap_or_default(),
    product_id: std::env::var("HUIFU_PRODUCT_ID").unwrap_or_default(),
    huifu_id: std::env::var("HUIFU_ID").unwrap_or_default(),
    merchant_private_key: std::env::var("HUIFU_MERCHANT_PRIVATE_KEY").unwrap_or_default(),
    huifu_public_key: std::env::var("HUIFU_PUBLIC_KEY").unwrap_or_default(),
    skill_source: "hfps/1.3.5".into(),
})?;

let response = client.preorder(&PreorderRequest {
    req_date: "20260929".into(),
    req_seq_id: "ORDER202609290001".into(),
    trans_amt: "0.01".into(),
    goods_desc: "测试订单".into(),
    notify_url: "https://shop.example.com/api/v1/payments/callback".into(),
    callback_url: "https://shop.example.com/pay".into(),
    project_id: "your-project-id".into(),
    project_title: "商城".into(),
    request_type: "P".into(),
    trans_type: "A_NATIVE".into(), // 微信使用 T_JSAPI
    ..PreorderRequest::default()
}).await?;

if response.accepted() {
    let jump_url = response.string("jump_url");
    // 302 跳转或由前端打开 jump_url。
}
# Ok(()) }
```

`resp_code` 只表示请求是否受理。订单最终状态以经过验签的异步通知或主动查询返回的 `trans_stat` 为准：`S` 成功、`P/I` 处理中、`F` 失败。

## 支付通知

汇付交易通知使用 `application/x-www-form-urlencoded`，包含 `sign` 与原始 `resp_data`。必须对原始 `resp_data` 字符串验签，不能先解析再序列化。

```rust,no_run
# use huifu_pay::{Client, Config};
# fn handle(client: &Client, sign: &str, resp_data: &str) -> Result<String, huifu_pay::Error> {
let notify = client.verify_notify(sign, resp_data)?;
let merchant_order_no = notify.string("req_seq_id");
let status = notify.string("trans_stat");
// 校验 huifu_id、订单号、金额和币种，并以幂等事务更新订单。
let ack = notify.ack()?; // RECV_ORD_ID_<req_seq_id>
# let _ = (merchant_order_no, status);
# Ok(ack) }
```

只有业务处理成功后才返回动态 ACK。验签、归属、金额或落库失败时不能返回成功 ACK，让汇付继续重试。

## 查询与退款

SDK 提供：

- `query_payment(PaymentQueryRequest)`
- `refund(RefundRequest)`
- `query_refund(RefundQueryRequest)`

退款请求同样可能先返回处理中。业务系统应保存退款请求号，并通过签名通知或退款查询确认最终状态后，再将本地退款标记为完成。

## 个人申请汇付

个人申请时可先准备以下资料：

- 姓名
- 手机号
- 邮箱
- 本人银行卡正反面照片
- 本人身份证正反面照片

在汇付官方渠道提交申请，审核通过后再申请相应的支付产品、创建托管项目并取得商户号、系统号、产品号和 RSA 密钥。资料必须通过汇付官方页面或工作人员指定的安全渠道提交，不要放进代码仓库、Issue 或聊天记录。具体准入、费率、结算周期和补充材料以汇付当次审核结果为准。

## 官方本地沙箱测试

1. 下载[官方预览包](https://cloudpnrcdn.oss-cn-shanghai.aliyuncs.com/huifuskills/hf-payment-local-sandbox-latest-preview.zip)。
2. 先校验 ZIP 内 `SHA256SUMS.txt`，再选择当前操作系统与架构对应的程序包。
3. 启动 control 与 gateway 服务，使用 `official-demo` 凭证。
4. 设置下列环境变量后运行忽略测试：

```bash
cargo test --test local_sandbox -- --ignored
```

测试需要 `HUIFU_SANDBOX_URL`、`HUIFU_SANDBOX_CONTROL_URL`、`HUIFU_SANDBOX_ADMIN_TOKEN`、`HUIFU_SANDBOX_SYS_ID`、`HUIFU_SANDBOX_PRODUCT_ID`、`HUIFU_SANDBOX_HUIFU_ID`、`HUIFU_SANDBOX_PRIVATE_KEY_FILE`、`HUIFU_SANDBOX_PUBLIC_KEY_FILE`、`HUIFU_SANDBOX_DATE`。测试会分别验证支付宝、微信、支付查询、模拟支付成功、退款和退款查询。

## 安全边界

- 请求只签名顶层 `data`；嵌套 JSON 按接口要求作为 JSON 字符串传递。
- 响应必须先验签再读取业务字段。
- 交易通知 RSA 验签和控制台 Webhook MD5 验签是两套不同机制。
- 回调必须校验商户号、订单号、金额与币种，并保证幂等。
- 生产私钥、通知原文、完整签名与管理令牌不能写入日志。

## 开发

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

本项目采用 [AGPL-3.0](LICENSE) 许可证。
