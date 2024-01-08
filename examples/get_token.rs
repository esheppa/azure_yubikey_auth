use azure_core::auth::TokenCredential;
use azure_yubikey_auth::{Config, Secret, Shared};
use color_eyre::eyre::Context;
use rustyline::config::Configurer;
use rustyline::highlight::Highlighter;
use rustyline::{ColorMode, Editor};
use rustyline_derive::{Completer, Helper, Hinter, Validator};
use yubikey::YubiKey;

use std::borrow::Cow;
use std::env;

#[derive(Completer, Helper, Hinter, Validator)]
struct MaskingHighlighter {
    masking: bool,
}

impl Highlighter for MaskingHighlighter {
    fn highlight<'l>(&self, line: &'l str, _pos: usize) -> Cow<'l, str> {
        use unicode_width::UnicodeWidthStr;
        if self.masking {
            Cow::Owned("*".repeat(line.width()))
        } else {
            Cow::Borrowed(line)
        }
    }

    fn highlight_char(&self, _line: &str, _pos: usize, _forced: bool) -> bool {
        self.masking
    }
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    tracing_subscriber::fmt::init();

    let h = MaskingHighlighter { masking: false };
    let mut rl = Editor::new()?;
    rl.set_helper(Some(h));
    rl.helper_mut().expect("No helper").masking = true;
    rl.set_color_mode(ColorMode::Forced); // force masking
    rl.set_auto_add_history(false); // make sure password is not added to history
    let pin = rl.readline("Please provide pin: ")?;

    let mut yubikey = YubiKey::open()?;
    yubikey.verify_pin(pin.trim().as_bytes())?;
    println!("Pin successfully verified");

    let tenant_id =
        env::var("TENANT_ID").context("Unable to find environment variable `TENANT_ID`")?;
    let client_id =
        env::var("CLIENT_ID").context("Unable to find environment variable `CLIENT_ID`")?;

    let config = Config {
        tenant_id: tenant_id.parse()?,
        client_id: client_id.parse()?,
        pin: Secret::new(pin),
        http_client: azure_core::new_http_client(),
        shared: Shared::new(yubikey),
    };

    println!("Requesting token");

    // let token = config
    //     .get_token(&[])
    //     .await?;

    // println!("Got token 1: {token:?}");

    let token = config
        .get_token(&["https://storage.azure.com/.default"])
        .await?;

    println!("Got token 1a: {token:?}");

    let token = config
        .get_token(&["https://database.windows.net/.default"])
        .await?;

    println!("Got token 2: {token:?}");

    let token = config
        .get_token(&["https://database.windows.net/.default"])
        .await?;

    println!("Got token 2a: {token:?}");

    let token = config
        .get_token(&["https://graph.microsoft.com/.default"])
        .await?;

    println!("Got token 3: {token:?}");

    let token = config
        .get_token(&["https://graph.microsoft.com/.default"])
        .await?;

    println!("Got token 3a: {token:?}");

    let client = reqwest::Client::new();
    let out = client
        .get("https://graph.microsoft.com/beta/users")
        .header("content-type", "application/json")
        .header("authorization", format!("bearer {}", token.token.secret()))
        .send()
        .await?
        .text()
        .await?;

    println!("{out}");

    Ok(())
}
