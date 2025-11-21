use crate::NetIoResult;

mod quic;

/// Network IO trait
pub trait NetIO {
    /// Send data to a party.
    fn send(&self, data: &[u8]) -> impl Future<Output = NetIoResult<()>>;

    /// Receive data from a party.
    fn recv(&self, buf: &mut [u8]) -> impl Future<Output = NetIoResult<usize>>;

    /// Flush the send buffer.
    fn flush(&self) -> impl Future<Output = NetIoResult<()>>;
}
