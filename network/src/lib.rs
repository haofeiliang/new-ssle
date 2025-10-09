mod error;
pub mod netio;

use std::sync::Arc;

use bytes::Bytes;

pub use error::{NetIoError, NetIoResult};

pub type Id = u32;

/// Network IO trait
pub trait IO {
    /// Get the party id of the current party.
    fn party_id(&self) -> Id;

    /// Get the number of parties in the network.
    fn num_parties(&self) -> usize;

    /// Send data to a party.
    fn send(&self, party_id: Id, data: &[u8]) -> impl Future<Output = NetIoResult<()>>;

    /// Receive data from a party.
    fn recv(&self, party_id: Id, buf: &mut [u8]) -> impl Future<Output = NetIoResult<usize>>;

    /// Broadcast data to all parties.
    fn broadcast(&self, data: &[u8]) -> impl Future<Output = NetIoResult<()>>;

    /// Broadcast data to all parties.
    fn par_broadcast(&self, data: Bytes) -> impl Future<Output = NetIoResult<()>>;

    /// Flush the send buffer.
    fn flush(&self, party_id: Id) -> impl Future<Output = NetIoResult<()>>;

    /// Flush all send buffers.
    fn flush_all(&self) -> impl Future<Output = NetIoResult<()>>;

    /// Flush the send buffer.
    fn spawn_flush(self: Arc<Self>, party_id: Id) -> impl Future<Output = NetIoResult<()>>;

    /// Flush all send buffers.
    fn spawn_flush_all(self: Arc<Self>) -> impl Future<Output = NetIoResult<()>>;
}
