use crate::holder::start_holder;
use crate::issuer::{start_issuer, Issuer};
use crate::verifier::start_verifier;
use ockam::{CredentialIssuer, Result};
use ockam_node::Context;
use std::net::SocketAddr;
use structopt::StructOpt;

mod holder;
mod issuer;
mod message;
mod schema;
mod verifier;

static DEFAULT_ISSUER_PORT: usize = 7967;
static DEFAULT_VERIFIER_PORT: usize = DEFAULT_ISSUER_PORT + 1;

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
    Verifier {
        #[structopt(long, short = "i")]
        issuer: Option<String>,

        #[structopt(long, short)]
        port: Option<usize>,
    },
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
        NodeType::Issuer { signing_key, port } => start_issuer(ctx, signing_key, port).await,
        NodeType::Holder { issuer } => start_holder(ctx, Issuer::on_or_default(issuer)).await,
        NodeType::Verifier { issuer, port } => {
            start_verifier(ctx, Issuer::on_or_default(issuer), port).await
        }

        NodeType::Keygen => {
            let i = CredentialIssuer::new();
            println!("Secret signing key: {}", hex::encode(i.get_signing_key()));
            ctx.stop().await
        }
    }
}
