use ockam::{async_worker, Context, OckamError, Result, Worker};

use crate::message::CredentialMessage;
use crate::{DEFAULT_ISSUER_PORT, DEFAULT_VERIFIER_PORT};
use ockam_transport_tcp::TcpRouter;
use std::net::SocketAddr;

struct Verifier {
    issuer: SocketAddr,
}

#[async_worker]
impl Worker for Verifier {
    type Message = CredentialMessage;
    type Context = Context;

    async fn initialize(&mut self, _context: &mut Self::Context) -> Result<()> {
        println!("Verifier");
        Ok(())
    }
}

pub async fn start_verifier(ctx: Context, issuer: SocketAddr, port: Option<usize>) -> Result<()> {
    let port = port.unwrap_or(DEFAULT_VERIFIER_PORT);

    let local_tcp: SocketAddr = format!("0.0.0.0:{}", port)
        .parse()
        .map_err(|_| OckamError::InvalidInternalState)?;

    let _router = TcpRouter::bind(&ctx, local_tcp).await?;
    Ok(())
}
