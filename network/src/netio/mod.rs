use std::{net::SocketAddr, sync::Arc, time::Duration};

use crate::{IO, Id, NetIoError, NetIoResult};

mod party;

use bytes::Bytes;
use dashmap::DashMap;
pub use party::Participant;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpListener, TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
};

/// A network I/O abstraction for multiple participants.
///
/// Manages connections and provides methods for sending, receiving,
/// and broadcasting messages between participants.
pub struct NetIO {
    party_id: Id,
    participants: Vec<Participant>,
    write_halves: Arc<DashMap<Id, OwnedWriteHalf>>,
    read_halves: Arc<DashMap<Id, OwnedReadHalf>>,
}

impl NetIO {
    /// Creates a new `NetIO` instance.
    ///
    /// # Arguments
    /// - `party_id`: The ID of the current participant.
    /// - `participants`: A list of all participants in the network.
    ///
    /// # Returns
    /// A `NetIO` instance or an error if initialization fails.
    pub async fn new(party_id: Id, participants: Vec<Participant>) -> NetIoResult<Arc<Self>> {
        assert!(
            participants
                .iter()
                .enumerate()
                .all(|(i, p)| <u32 as TryInto<usize>>::try_into(p.id).unwrap() == i)
        );

        let net_io: NetIO = NetIO {
            party_id,
            participants,
            write_halves: Arc::new(DashMap::new()),
            read_halves: Arc::new(DashMap::new()),
        };

        net_io.initialize().await?;

        Ok(Arc::new(net_io))
    }

    /// Initializes the network connections.
    async fn initialize(&self) -> NetIoResult<()> {
        let num_parties = self.participants.len();
        let self_id = self.party_id;
        let index: usize = self.party_id.try_into().unwrap();
        let local_addr = self.participants[index].address;

        let listener = TcpListener::bind(local_addr).await?;

        let (tx, mut rx) = tokio::sync::mpsc::channel(num_parties - 1);

        // Accept connections from participants
        let tx_c = tx.clone();
        tokio::spawn(async move {
            for _ in index + 1..num_parties {
                let (mut stream, _addr) = listener.accept().await?;
                let peer_id = stream.read_u32_le().await?; // Receives the peer's ID
                tx_c.send((peer_id, stream)).await.unwrap();
            }
            Ok::<(), NetIoError>(())
        });

        // Connect to participants
        for (peer_id, peer_addr) in self
            .participants
            .iter()
            .take(index)
            .map(|p| p.address)
            .enumerate()
        {
            let tx_c = tx.clone();
            tokio::spawn(async move {
                let mut stream = connect_with_retry(peer_addr, 10).await?;
                stream.write_u32_le(self_id).await?; // Sends the current participant's ID to a peer
                tx_c.send((peer_id as Id, stream)).await.unwrap();
                Ok::<(), NetIoError>(())
            });
        }

        drop(tx);

        while let Some((peer_id, stream)) = rx.recv().await {
            self.setup_connection(peer_id, stream)?;
        }

        Ok(())
    }

    /// Sets up the connection.
    fn setup_connection(&self, id: Id, stream: TcpStream) -> NetIoResult<()> {
        let (r, w) = stream.into_split();
        self.read_halves.insert(id, r);
        self.write_halves.insert(id, w);
        Ok(())
    }
}

/// Connects to a peer with retries.
async fn connect_with_retry(address: SocketAddr, max_retries: usize) -> NetIoResult<TcpStream> {
    for attempt in 0..max_retries {
        match TcpStream::connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                println!(
                    "Attempt {} failed to connect to {}: {}",
                    attempt + 1,
                    address,
                    e
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
    Err(NetIoError::Timeout(format!(
        "Failed to connect to {address} after {max_retries} attempts",
    )))
}

impl IO for NetIO {
    /// Get the party ID of the current participant.
    fn party_id(&self) -> Id {
        self.party_id
    }

    /// Get the number of participants in the network.
    fn num_parties(&self) -> usize {
        self.participants.len()
    }

    /// Sends data to a participant.
    async fn send(&self, party_id: Id, data: &[u8]) -> NetIoResult<()> {
        let mut ref_write_half = self
            .write_halves
            .get_mut(&party_id)
            .ok_or(NetIoError::ConnectionNotFound(party_id))?;
        let write_half = ref_write_half.value_mut();

        write_half.write_all(data).await?;

        Ok(())
    }

    /// Receives data from a participant.
    async fn recv(&self, party_id: Id, buf: &mut [u8]) -> NetIoResult<usize> {
        self.flush(party_id).await?;

        let mut ref_read_half = self
            .read_halves
            .get_mut(&party_id)
            .ok_or(NetIoError::ConnectionNotFound(party_id))?;
        let read_half = ref_read_half.value_mut();

        read_half.read_exact(buf).await.map_err(NetIoError::IoError)
    }

    /// Broadcast data to all participants.
    async fn broadcast(&self, data: &[u8]) -> NetIoResult<()> {
        // for mut ref_write_half in self.write_halves.iter_mut() {
        //     let write_half = ref_write_half.value_mut();
        //     write_half.write_all(data).await?;
        // }

        for id in (0..self.num_parties() as Id).filter(|x| *x != self.party_id) {
            let mut ref_write_half = self
                .write_halves
                .get_mut(&id)
                .ok_or(NetIoError::ConnectionNotFound(id))?;
            let write_half = ref_write_half.value_mut();
            write_half.write_all(data).await?;
        }

        Ok(())
    }

    /// Broadcast data to all parties.
    async fn par_broadcast(&self, data: Bytes) -> NetIoResult<()> {
        let mut handles = Vec::with_capacity(self.num_parties());

        for id in (0..self.num_parties() as Id).filter(|x| *x != self.party_id) {
            let wh = self.write_halves.clone();
            let data = data.clone();
            let handle = tokio::spawn(async move {
                let mut ref_write_half =
                    wh.get_mut(&id).ok_or(NetIoError::ConnectionNotFound(id))?;
                let write_half = ref_write_half.value_mut();

                write_half.write_all(&data).await?;
                Ok::<_, NetIoError>(())
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await.unwrap()?;
        }

        Ok(())
    }

    /// Flush the send buffer.
    async fn flush(&self, party_id: Id) -> NetIoResult<()> {
        let mut ref_write_half = self
            .write_halves
            .get_mut(&party_id)
            .ok_or(NetIoError::ConnectionNotFound(party_id))?;
        let write_half = ref_write_half.value_mut();

        write_half.flush().await?;

        Ok(())
    }

    async fn flush_all(&self) -> NetIoResult<()> {
        for mut write_half in self.write_halves.iter_mut() {
            let write_half = write_half.value_mut();
            write_half.flush().await?;
        }
        Ok(())
    }

    /// Flush the send buffer.
    async fn spawn_flush(self: Arc<Self>, party_id: Id) -> NetIoResult<()> {
        let mut ref_write_half = self
            .write_halves
            .get_mut(&party_id)
            .ok_or(NetIoError::ConnectionNotFound(party_id))?;
        let write_half = ref_write_half.value_mut();

        write_half.flush().await?;

        Ok(())
    }

    /// Flush all send buffers.
    async fn spawn_flush_all(self: Arc<Self>) -> NetIoResult<()> {
        for mut write_half in self.write_halves.iter_mut() {
            let write_half = write_half.value_mut();
            write_half.flush().await?;
        }
        Ok(())
    }
}
