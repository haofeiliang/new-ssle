mod quic;
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

pub use quic::QuicNetIO;
pub use tcp::TcpNetIO;
