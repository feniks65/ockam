use ockam::{async_worker, Context, Result, Worker};

use crate::message::CredentialMessage;

struct Verifier;

#[async_worker]
impl Worker for Verifier {
    type Message = CredentialMessage;
    type Context = Context;

    async fn initialize(&mut self, _context: &mut Self::Context) -> Result<()> {
        println!("Verifier");
        Ok(())
    }
}

pub async fn start_verifier(_ctx: Context) -> Result<()> {
    Ok(())
}
