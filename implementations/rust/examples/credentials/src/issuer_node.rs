mod message;
mod schema;

use crate::message::CredentialMessage;
use crate::schema::example_schema;
use ockam::{async_worker, CredentialIssuer, OckamError, Result, Routed, Worker};
use ockam_node::Context;
use ockam_transport_tcp::TcpRouter;
use std::net::SocketAddr;
use structopt::StructOpt;

static DEFAULT_PORT: usize = 7967;

#[derive(StructOpt)]
struct Args {
    /// HEX encoded issuer signing key
    #[structopt(long)]
    secret_key: Option<String>,

    #[structopt(long)]
    print_secret_key: bool,

    #[structopt(long)]
    port: Option<usize>,
}

struct Issuer {
    credential_issuer: CredentialIssuer,
    print_secret_key: bool,
}

#[async_worker]
impl Worker for Issuer {
    type Message = CredentialMessage;
    type Context = Context;

    async fn initialize(&mut self, _context: &mut Self::Context) -> Result<()> {
        let issuer = &self.credential_issuer;

        let pk = issuer.get_public_key();
        let pop = issuer.create_proof_of_possession();

        let _schema = example_schema();

        println!("Issuer public key:{}", hex::encode(pk));
        println!("Issuer proof of possession: {}", hex::encode(pop));

        if self.print_secret_key {
            println!(
                "⚠️SECRET SIGNING KEY ⚠ {}",
                hex::encode(issuer.get_signing_key())
            );
        }

        Ok(())
    }

    fn shutdown(&mut self, _context: &mut Self::Context) -> Result<()> {
        println!("Shutdown");
        Ok(())
    }

    async fn handle_message(
        &mut self,
        _context: &mut Self::Context,
        _msg: Routed<Self::Message>,
    ) -> Result<()> {
        println!("handle_message");
        Ok(())
    }
}

#[ockam::node]
async fn main(ctx: Context) -> Result<()> {
    let args = Args::from_args();

    let port = if let Some(port) = args.port {
        port
    } else {
        DEFAULT_PORT
    };

    let local_tcp: SocketAddr = format!("127.0.0.1:{}", port)
        .parse()
        .map_err(|_| OckamError::InvalidInternalState)?;

    let _router = TcpRouter::bind(&ctx, local_tcp).await?;

    let credential_issuer = if let Some(secret_key) = args.secret_key {
        CredentialIssuer::with_signing_key_hex(secret_key).unwrap()
    } else {
        CredentialIssuer::new()
    };

    let print_secret_key = args.print_secret_key;

    ctx.start_worker(
        "issuer",
        Issuer {
            credential_issuer,
            print_secret_key,
        },
    )
    .await
}
