use crate::holder::start_holder;
use ockam::{CredentialIssuer, Result};
use ockam_node::Context;
use structopt::StructOpt;

mod holder;
mod issuer;
mod message;
mod schema;
mod verifier;

static DEFAULT_PORT: usize = 7967;

#[derive(StructOpt)]
enum NodeType {
    Issuer {
        #[structopt(long, short = "k")]
        signing_key: Option<String>,

        #[structopt(long, short)]
        port: Option<usize>,
    },
    Holder {
        #[structopt(long, short = "i")]
        issuer: Option<String>,
    },
    Verifier,
    Keygen,
}

#[derive(StructOpt)]
struct Args {
    #[structopt(subcommand)]
    node_type: NodeType,
}

#[ockam::node]
async fn main(ctx: Context) -> Result<()> {
    let args: Args = Args::from_args();

    match args.node_type {
        NodeType::Issuer { signing_key, port } => {
            issuer::start_issuer(ctx, signing_key, port).await
        }
        NodeType::Holder { issuer } => {
            let issuer = if let Some(issuer) = issuer {
                issuer
            } else {
                format!("127.0.0.1:{}", DEFAULT_PORT)
            };
            start_holder(ctx, issuer).await
        }
        NodeType::Verifier => verifier::start_verifier(ctx).await,
        NodeType::Keygen => {
            let i = CredentialIssuer::new();
            println!("Secret signing key: {}", hex::encode(i.get_signing_key()));
            ctx.stop().await
        }
    }
}
