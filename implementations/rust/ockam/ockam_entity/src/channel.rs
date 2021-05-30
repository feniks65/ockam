use crate::{ProfileTrait, SecureChannelTrait};
use async_trait::async_trait;
use ockam_core::{Address, Result, Route};
use ockam_node::Context;
use ockam_vault_sync_core::VaultSync;

mod responder;
pub(crate) use responder::*;
mod initiator;
pub(crate) use initiator::*;
mod listener;
pub(crate) use listener::*;
mod messages;
pub(crate) use messages::*;

#[async_trait]
impl<P: ProfileTrait + Clone> SecureChannelTrait for P {
    /// Create mutually authenticated secure channel
    async fn create_secure_channel(
        &mut self,
        ctx: &Context,
        route: Route,
        vault: &Address,
    ) -> Result<Address> {
        let vault = VaultSync::create_with_worker(ctx, vault)?;
        Initiator::create(ctx, route, self, vault).await
    }

    /// Create mutually authenticated secure channel listener
    async fn create_secure_channel_listener(
        &mut self,
        ctx: &Context,
        address: Address,
        vault: &Address,
    ) -> Result<()> {
        let vault = VaultSync::create_with_worker(ctx, vault)?;
        let listener = ProfileChannelListener::new(self.clone(), vault);
        ctx.start_worker(address, listener).await
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Profile;
    use ockam_vault_sync_core::Vault;
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_channel() {
        let (mut ctx, mut executor) = ockam_node::start_node();
        executor
            .execute(async move {
                let vault = Vault::create(&ctx).unwrap();

                let mut alice = Profile::create(&ctx, &vault).await.unwrap();
                let mut bob = Profile::create(&ctx, &vault).await.unwrap();

                bob.create_secure_channel_listener(&mut ctx, "bob_listener".into(), &vault)
                    .await
                    .unwrap();

                let alice_channel = alice
                    .create_secure_channel(
                        &mut ctx,
                        Route::new().append("bob_listener").into(),
                        &vault,
                    )
                    .await
                    .unwrap();

                ctx.send(
                    Route::new().append(alice_channel).append(ctx.address()),
                    "Hello, Bob!".to_string(),
                )
                .await
                .unwrap();
                let msg = ctx.receive::<String>().await.unwrap().take();
                let return_route = msg.return_route();
                assert_eq!("Hello, Bob!", msg.body());

                ctx.send(return_route, "Hello, Alice!".to_string())
                    .await
                    .unwrap();
                assert_eq!(
                    "Hello, Alice!",
                    ctx.receive::<String>().await.unwrap().take().body()
                );

                ctx.stop().await.unwrap();
            })
            .unwrap();
    }

    #[test]
    fn test_tunneled_secure_channel_works() {
        let (mut ctx, mut executor) = ockam_node::start_node();
        executor
            .execute(async move {
                let vault = Vault::create(&ctx).unwrap();

                let mut alice = Profile::create(&ctx, &vault).await.unwrap();
                let mut bob = Profile::create(&ctx, &vault).await.unwrap();

                bob.create_secure_channel_listener(&mut ctx, "bob_listener".into(), &vault)
                    .await
                    .unwrap();

                let alice_channel = alice
                    .create_secure_channel(
                        &mut ctx,
                        Route::new().append("bob_listener").into(),
                        &vault,
                    )
                    .await
                    .unwrap();

                bob.create_secure_channel_listener(&mut ctx, "bob_another_listener".into(), &vault)
                    .await
                    .unwrap();

                let alice_another_channel = alice
                    .create_secure_channel(
                        &mut ctx,
                        Route::new()
                            .append(alice_channel)
                            .append("bob_another_listener")
                            .into(),
                        &vault,
                    )
                    .await
                    .unwrap();

                ctx.send(
                    Route::new()
                        .append(alice_another_channel)
                        .append(ctx.address()),
                    "Hello, Bob!".to_string(),
                )
                .await
                .unwrap();
                let msg = ctx.receive::<String>().await.unwrap().take();
                let return_route = msg.return_route();
                assert_eq!("Hello, Bob!", msg.body());

                ctx.send(return_route, "Hello, Alice!".to_string())
                    .await
                    .unwrap();
                assert_eq!(
                    "Hello, Alice!",
                    ctx.receive::<String>().await.unwrap().take().body()
                );

                ctx.stop().await.unwrap();
            })
            .unwrap();
    }

    #[test]
    #[serial]
    fn test_double_tunneled_secure_channel_works() {
        let (mut ctx, mut executor) = ockam_node::start_node();
        executor
            .execute(async move {
                let vault = Vault::create(&ctx).unwrap();

                let mut alice = Profile::create(&ctx, &vault).await.unwrap();
                let mut bob = Profile::create(&ctx, &vault).await.unwrap();

                bob.create_secure_channel_listener(&mut ctx, "bob_listener".into(), &vault)
                    .await
                    .unwrap();

                let alice_channel = alice
                    .create_secure_channel(
                        &mut ctx,
                        Route::new().append("bob_listener").into(),
                        &vault,
                    )
                    .await
                    .unwrap();

                bob.create_secure_channel_listener(&mut ctx, "bob_another_listener".into(), &vault)
                    .await
                    .unwrap();

                let alice_another_channel = alice
                    .create_secure_channel(
                        &mut ctx,
                        Route::new()
                            .append(alice_channel)
                            .append("bob_another_listener")
                            .into(),
                        &vault,
                    )
                    .await
                    .unwrap();

                bob.create_secure_channel_listener(
                    &mut ctx,
                    "bob_yet_another_listener".into(),
                    &vault,
                )
                .await
                .unwrap();

                let alice_yet_another_channel = alice
                    .create_secure_channel(
                        &mut ctx,
                        Route::new()
                            .append(alice_another_channel)
                            .append("bob_yet_another_listener")
                            .into(),
                        &vault,
                    )
                    .await
                    .unwrap();

                ctx.send(
                    Route::new()
                        .append(alice_yet_another_channel)
                        .append(ctx.address()),
                    "Hello, Bob!".to_string(),
                )
                .await
                .unwrap();
                let msg = ctx.receive::<String>().await.unwrap().take();
                let return_route = msg.return_route();
                assert_eq!("Hello, Bob!", msg.body());

                ctx.send(return_route, "Hello, Alice!".to_string())
                    .await
                    .unwrap();
                assert_eq!(
                    "Hello, Alice!",
                    ctx.receive::<String>().await.unwrap().take().body()
                );

                ctx.stop().await.unwrap();
            })
            .unwrap();
    }

    #[test]
    #[serial]
    fn test_many_times_tunneled_secure_channel_works() {
        let (mut ctx, mut executor) = ockam_node::start_node();
        executor
            .execute(async move {
                let vault = Vault::create(&ctx).unwrap();

                let mut alice = Profile::create(&ctx, &vault).await.unwrap();
                let mut bob = Profile::create(&ctx, &vault).await.unwrap();
                let n = rand::random::<u8>() % 5 + 4;
                let mut channels = vec![];
                for i in 0..n {
                    bob.create_secure_channel_listener(&mut ctx, i.to_string().into(), &vault)
                        .await
                        .unwrap();
                    let channel_route: Route;
                    if i > 0 {
                        channel_route = Route::new()
                            .append(channels.pop().unwrap())
                            .append(i.to_string())
                            .into();
                    } else {
                        channel_route = Route::new().append(i.to_string()).into();
                    }
                    let alice_channel = alice
                        .create_secure_channel(&mut ctx, channel_route, &vault)
                        .await
                        .unwrap();
                    channels.push(alice_channel);
                }

                ctx.send(
                    Route::new()
                        .append(channels.pop().unwrap())
                        .append(ctx.address()),
                    "Hello, Bob!".to_string(),
                )
                .await
                .unwrap();
                let msg = ctx.receive::<String>().await.unwrap().take();
                let return_route = msg.return_route();
                assert_eq!("Hello, Bob!", msg.body());

                ctx.send(return_route, "Hello, Alice!".to_string())
                    .await
                    .unwrap();
                assert_eq!(
                    "Hello, Alice!",
                    ctx.receive::<String>().await.unwrap().take().body()
                );

                ctx.stop().await.unwrap();
            })
            .unwrap();
    }
}
