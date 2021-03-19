use ockam::{
    async_worker, Context, CredentialVerifier, OckamError, PublicKeyBytes, Result, Route, Routed,
    Worker,
};

use crate::message::CredentialMessage;
use crate::DEFAULT_VERIFIER_PORT;
use ockam_transport_tcp::{self as tcp, TcpRouter};
use std::net::SocketAddr;

struct Verifier {
    issuer: SocketAddr,
    issuer_public_key: Option<PublicKeyBytes>,
}

#[async_worker]
impl Worker for Verifier {
    type Message = CredentialMessage;
    type Context = Context;

    async fn initialize(&mut self, ctx: &mut Self::Context) -> Result<()> {
        let issuer = self.issuer;

        println!("Verifier starting. Discovering Issuer");

        // Send a New Credential Connection message
        ctx.send_message(
            Route::new()
                .append(format!("1#{}", issuer))
                .append("issuer"),
            CredentialMessage::CredentialConnection,
        )
        .await
    }

    async fn handle_message(
        &mut self,
        _context: &mut Self::Context,
        msg: Routed<Self::Message>,
    ) -> Result<()> {
        let msg = msg.take();

        match msg {
            CredentialMessage::CredentialIssuer { public_key, proof } => {
                if CredentialVerifier::verify_proof_of_possession(public_key, proof) {
                    self.issuer_public_key = Some(public_key);
                    println!("Discovered Issuer Pubkey: {}", hex::encode(public_key));
                    Ok(())
                } else {
                    Err(OckamError::InvalidProof.into())
                }
            }
            _ => Ok(()),
        }
    }
}

pub async fn start_verifier(ctx: Context, issuer: SocketAddr, port: Option<usize>) -> Result<()> {
    let port = port.unwrap_or(DEFAULT_VERIFIER_PORT);

    let local_tcp: SocketAddr = format!("0.0.0.0:{}", port)
        .parse()
        .map_err(|_| OckamError::InvalidInternalState)?;

    let router = TcpRouter::bind(&ctx, local_tcp).await?;

    let pair = tcp::start_tcp_worker(&ctx, issuer).await?;

    router.register(&pair).await?;

    ctx.start_worker(
        "verifier",
        Verifier {
            issuer,
            issuer_public_key: None,
        },
    )
    .await
}
