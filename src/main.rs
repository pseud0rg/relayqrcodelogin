#[tokio::main]
async fn main() {
    if let Err(error) = pseud0_web_login_relay::run().await {
        tracing::error!(code = error.code().as_str(), "relay failed");
        std::process::exit(1);
    }
}
