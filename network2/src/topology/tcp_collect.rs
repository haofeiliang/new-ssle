use std::{sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::sleep,
};

use crate::{Id, PairWiseNetIO, Role, TcpNetIO};

use super::Participant;

pub struct TcpCollect {
    party_id: Id,
    party_count: usize,
    connections: Vec<Arc<TcpNetIO>>,
}

impl TcpCollect {
    pub async fn new(party_id: Id, participants: Vec<Participant>) -> anyhow::Result<Self> {
        let party_count = participants.len();

        if party_id == 0 {
            let listener = tokio::net::TcpListener::bind(participants[0].address).await?;

            let listen_handle = tokio::spawn(async move {
                let mut i = party_count - 1;
                let mut connections = Vec::with_capacity(i);
                while i != 0 {
                    let (mut tcp_stream, _addr) = listener.accept().await?;

                    tcp_stream.set_nodelay(true)?;

                    let peer_id = tcp_stream.read_u32().await?;

                    connections.push((peer_id, Role::Server, tcp_stream));

                    i -= 1;
                }

                anyhow::Ok(connections)
            });

            let mut connections = listen_handle.await??;
            connections.sort_unstable_by(|a, b| a.0.cmp(&b.0));

            let connections: Vec<_> = connections
                .into_iter()
                .map(|(_, role, tcp_stream)| Arc::new(TcpNetIO::new(role, tcp_stream)))
                .collect();

            Ok(Self {
                party_id,
                party_count,
                connections,
            })
        } else {
            let mut retry_count = 100;
            let peer_address = participants[0].address;
            let mut tcp_stream = loop {
                if let Ok(tcp_stream) = tokio::net::TcpStream::connect(peer_address).await {
                    break tcp_stream;
                } else {
                    sleep(Duration::from_secs(1)).await
                }
                retry_count -= 1;
                if retry_count == 0 {
                    panic!("Retry too many times.")
                }
            };

            tcp_stream.set_nodelay(true)?;
            tcp_stream.write_u32(party_id).await?;
            tcp_stream.flush().await?;

            let connection = Arc::new(TcpNetIO::new(Role::Client, tcp_stream));

            Ok(Self {
                party_id,
                party_count,
                connections: vec![connection],
            })
        }
    }

    pub async fn collect(&self, data: &'static mut [u8], chunk_size: usize) -> anyhow::Result<()> {
        if self.party_id == 0 {
            assert_eq!(data.len(), chunk_size * (self.party_count - 1));

            let mut send_tasks = Vec::with_capacity(self.party_count - 1);
            for conn in self.connections.iter() {
                let conn_s = conn.clone();
                send_tasks.push(tokio::spawn(async move {
                    conn_s.send(&[0x01]).await?;
                    anyhow::Ok(())
                }));
            }

            let mut recv_tasks = Vec::with_capacity(self.party_count - 1);

            let chunks: Vec<&'static mut [u8]> = data.chunks_exact_mut(chunk_size).collect();

            for (conn, recv_chunk) in self.connections.iter().zip(chunks) {
                let conn_r = conn.clone();
                recv_tasks.push(tokio::spawn(async move {
                    conn_r.recv(recv_chunk).await?;
                    anyhow::Ok(())
                }));
            }

            for task in recv_tasks {
                task.await??;
            }
        } else {
            assert_eq!(data.len(), chunk_size);

            let mut sync_signal = [0u8; 1];
            self.connections[0].clone().recv(&mut sync_signal).await?;

            self.connections[0].clone().send(data).await?;
        }

        Ok(())
    }

    pub async fn close(self) -> anyhow::Result<()> {
        for c in self.connections {
            Arc::<TcpNetIO>::into_inner(c).unwrap().close().await?
        }
        Ok(())
    }
}
