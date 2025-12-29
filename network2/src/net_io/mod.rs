// mod quic;
mod tcp;

#[derive(Debug, Clone, Copy)]
pub enum Role {
    Server,
    Client,
}

/// Network IO trait
pub trait TreeNetIO {
    fn share(
        &self,
        data: &[u8],
        buf: &mut [u8],
    ) -> impl std::future::Future<Output = anyhow::Result<()>>;
}

pub trait PairWiseNetIO {
    fn send(self: Arc<Self>, data: &[u8]) -> impl std::future::Future<Output = anyhow::Result<()>>;

    fn recv(
        self: Arc<Self>,
        data: &mut [u8],
    ) -> impl std::future::Future<Output = anyhow::Result<()>>;
}

use std::sync::Arc;

// pub use quic::QuicNetIO;
pub use tcp::TcpNetIO;
