use clap::Parser;
use smart_contract_analyzer::cli::Args;

#[tokio::main]
async fn main() -> smart_contract_analyzer::Result<()> {
    let args = Args::parse();
    args.run().await?;
    Ok(())
}
