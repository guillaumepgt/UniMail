//! UniMail binary entry point.
//!
//! Parses CLI subcommands and delegates to [`unimail::cli`]. See `README.md`
//! for usage, or run `cargo run -- --help`.

#[tokio::main]
async fn main() {
    if let Err(e) = unimail::cli::run().await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
