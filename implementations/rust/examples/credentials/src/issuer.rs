use std::net::SocketAddr;

use ockam::{
    async_worker, Context, CredentialAttribute, CredentialIssuer, CredentialSchema, OckamError,
    Routed, Worker,
};
use ockam_transport_tcp::TcpRouter;

use crate::message::CredentialMessage;
use crate::message::CredentialMessage::{CredentialOffer, CredentialResponse};
use crate::schema::example_schema;
use crate::DEFAULT_ISSUER_PORT;
use std::collections::BTreeMap;

pub struct Issuer {
    credential_issuer: CredentialIssuer,
    schema: CredentialSchema,
}

impl Issuer {
    pub fn default_address() -> SocketAddr {
        Issuer::on("127.0.0.1", DEFAULT_ISSUER_PORT)
    }

    pub fn on<S: ToString>(host: S, port: usize) -> SocketAddr {
        format!("{}:{}", host.to_string(), port).parse().unwrap()
    }

    pub fn on_or_default<S: ToString>(host: Option<S>) -> SocketAddr {
        if let Some(host) = host {
            let host = host.to_string();
            if let Some(_) = host.find(":") {
                host.parse().unwrap()
            } else {
                Issuer::on(host, DEFAULT_ISSUER_PORT)
            }
        } else {
            Issuer::default_address()
        }
    }
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
    let port = port.unwrap_or(DEFAULT_ISSUER_PORT);

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
