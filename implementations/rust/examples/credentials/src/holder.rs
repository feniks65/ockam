use ockam::{
    async_worker, Context, Credential, CredentialFragment1, CredentialHolder, CredentialVerifier,
    OckamError, PublicKeyBytes, Result, Route, Routed, Worker,
};

use crate::message::CredentialMessage;
use ockam_transport_tcp::{self as tcp, TcpRouter};
use std::net::SocketAddr;

struct Holder {
    holder: CredentialHolder,
    issuer: SocketAddr,
    issuer_pubkey: Option<PublicKeyBytes>,
    frag1: Option<CredentialFragment1>,
    credential: Option<Credential>,
}

#[async_worker]
impl Worker for Holder {
    type Message = CredentialMessage;
    type Context = Context;

    async fn initialize(&mut self, ctx: &mut Self::Context) -> Result<()> {
        let issuer = self.issuer;

        let router = TcpRouter::register(&ctx).await?;
        let pair = tcp::start_tcp_worker(&ctx, issuer).await?;

        router.register(&pair).await?;

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
        ctx: &mut Self::Context,
        msg: Routed<Self::Message>,
    ) -> Result<()> {
        let route = msg.reply();
        let msg = msg.take();

        match msg {
            CredentialMessage::CredentialIssuer { public_key, proof } => {
                if CredentialVerifier::verify_proof_of_possession(public_key, proof) {
                    self.issuer_pubkey = Some(public_key);

                    ctx.send_message(route, CredentialMessage::NewCredential)
                        .await
                } else {
                    Err(OckamError::InvalidProof.into())
                }
            }
            CredentialMessage::CredentialOffer(offer) => {
                if let Some(issuer_key) = self.issuer_pubkey {
                    if let Ok((request, frag1)) =
                        self.holder.accept_credential_offer(&offer, issuer_key)
                    {
                        self.frag1 = Some(frag1);
                        return ctx
                            .send_message(route, CredentialMessage::CredentialRequest(request))
                            .await;
                    }
                }
                Err(OckamError::InvalidInternalState.into())
            }

            CredentialMessage::CredentialResponse(frag2) => {
                if let Some(frag1) = &self.frag1 {
                    let credential = self
                        .holder
                        .combine_credential_fragments(frag1.clone(), frag2);

                    self.credential = Some(credential);
                    println!("Credential obtained!")
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

pub async fn start_holder(ctx: Context, issuer: SocketAddr) -> ockam::Result<()> {
    let holder = CredentialHolder::new();

    ctx.start_worker(
        "holder",
        Holder {
            holder,
            issuer,
            issuer_pubkey: None,
            frag1: None,
            credential: None,
        },
    )
    .await
}
