use std::net::SocketAddr;

use ockam::{
    async_worker, Context, CredentialAttribute, CredentialIssuer, CredentialSchema, OckamError,
    Routed, Worker,
};
use ockam_transport_tcp::TcpRouter;

use crate::message::CredentialMessage;
use crate::message::CredentialMessage::{CredentialOffer, CredentialResponse};
use crate::schema::example_schema;
use crate::DEFAULT_PORT;
use std::collections::BTreeMap;

struct Issuer {
    credential_issuer: CredentialIssuer,
    schema: CredentialSchema,
}

#[async_worker]
impl Worker for Issuer {
    type Message = CredentialMessage;
    type Context = Context;

    async fn handle_message(
        &mut self,
        ctx: &mut Self::Context,
        msg: Routed<Self::Message>,
    ) -> ockam::Result<()> {
        let issuer = &self.credential_issuer;

        let route = msg.reply();
        let msg = msg.take();

        let public_key = issuer.get_public_key();
        let proof = issuer.create_proof_of_possession();

        let response = match msg {
            CredentialMessage::CredentialConnection => {
                CredentialMessage::CredentialIssuer { public_key, proof }
            }
            CredentialMessage::NewCredential => {
                let offer = issuer.create_offer(&self.schema);
                CredentialOffer(offer)
            }
            CredentialMessage::CredentialRequest(request) => {
                let mut attributes = BTreeMap::new();
                attributes.insert(
                    self.schema.attributes[1].label.clone(),
                    CredentialAttribute::Numeric(1), // TRUE, the device has access
                );

                let credential_fragment2 = issuer
                    .sign_credential_request(&request, &self.schema, &attributes, request.offer_id)
                    .unwrap();

                CredentialResponse(credential_fragment2)
            }
            _ => unimplemented!(),
        };

        ctx.send_message(route, response).await
    }
}

pub async fn start_issuer(
    ctx: Context,
    signing_key: Option<String>,
    port: Option<usize>,
) -> ockam::Result<()> {
    let port = if let Some(port) = port {
        port
    } else {
        DEFAULT_PORT
    };

    let local_tcp: SocketAddr = format!("0.0.0.0:{}", port)
        .parse()
        .map_err(|_| OckamError::InvalidInternalState)?;

    let _router = TcpRouter::bind(&ctx, local_tcp).await?;

    let credential_issuer = if let Some(signing_key) = signing_key {
        CredentialIssuer::with_signing_key_hex(signing_key).unwrap()
    } else {
        CredentialIssuer::new()
    };

    let schema = example_schema();

    ctx.start_worker(
        "issuer",
        Issuer {
            credential_issuer,
            schema,
        },
    )
    .await
}
