use std::{sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::sleep,
};

use crate::{Id, PairWiseNetIO, Role, TcpNetIO};

use super::Participant;

pub struct TcpPairWise {
    party_id: Id,
    party_count: usize,
    connections: Vec<Arc<TcpNetIO>>,
}

impl TcpPairWise {
    pub async fn new(party_id: Id, participants: Vec<Participant>) -> anyhow::Result<Self> {
        let party_count = participants.len();

        let listener =
            tokio::net::TcpListener::bind(participants[party_id as usize].address).await?;

        let listen_handle = tokio::spawn(async move {
            let mut i = party_count - party_id as usize - 1;
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

        let mut connections = if party_id == 0 {
            Vec::new()
        } else {
            let mut connections = Vec::with_capacity(party_id as usize);

            for peer_id in 0..party_id {
                let mut retry_count = 100;
                let peer_address = participants[peer_id as usize].address;
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

                connections.push((peer_id, Role::Client, tcp_stream));
            }

            connections
        };

        let mut ext_connections = listen_handle.await??;
        connections.append(&mut ext_connections);

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
    }

    pub async fn share(&self, data: &'static mut [u8], chunk_size: usize) -> anyhow::Result<()> {
        assert_eq!(data.len(), chunk_size * self.party_count);

        let mut send_tasks = Vec::with_capacity(self.party_count - 1);
        let mut recv_tasks = Vec::with_capacity(self.party_count - 1);

        if self.party_id == 0 {
            let (send_chunk, recv_chunks) = data.split_at_mut(chunk_size);

            for (conn, recv_chunk) in self
                .connections
                .iter()
                .zip(recv_chunks.chunks_exact_mut(chunk_size))
            {
                let conn_r = conn.clone();
                recv_tasks.push(tokio::spawn(async {
                    conn_r.recv(recv_chunk).await?;
                    anyhow::Ok(())
                }));
                // println!("Party {}: Receive from Peer {}", self.party_id, i + 1);
            }

            for conn in self.connections.iter() {
                let conn_s = conn.clone();
                send_tasks.push(tokio::spawn(async {
                    conn_s.send(send_chunk).await?;
                    anyhow::Ok(())
                }));
                // println!("Party {}: Send to Peer {}", self.party_id, i + 1);
            }
        } else if self.party_id == self.party_count as u32 - 1 {
            let (recv_chunks, send_chunk) = data.split_at_mut(chunk_size * (self.party_count - 1));

            for (conn, recv_chunk) in self
                .connections
                .iter()
                .zip(recv_chunks.chunks_exact_mut(chunk_size))
            {
                let conn_r = conn.clone();
                recv_tasks.push(tokio::spawn(async {
                    conn_r.recv(recv_chunk).await?;
                    anyhow::Ok(())
                }));
                // println!("Party {}: Receive from Peer {}", self.party_id, i);
            }

            for conn in self.connections.iter() {
                let conn_s = conn.clone();
                send_tasks.push(tokio::spawn(async {
                    conn_s.send(send_chunk).await?;
                    anyhow::Ok(())
                }));
                // println!("Party {}: Send to Peer {}", self.party_id, i);
            }
        } else {
            let (recv_chunks1, others) = data.split_at_mut(chunk_size * (self.party_id as usize));
            let (send_chunk, recv_chunks2) = others.split_at_mut(chunk_size);

            for (conn, recv_chunk) in self.connections.iter().zip(
                recv_chunks1
                    .chunks_exact_mut(chunk_size)
                    .chain(recv_chunks2.chunks_exact_mut(chunk_size)),
            ) {
                let conn_r = conn.clone();
                recv_tasks.push(tokio::spawn(async {
                    conn_r.recv(recv_chunk).await?;
                    anyhow::Ok(())
                }));
                // println!(
                //     "Party {}: Receive from Party {}",
                //     self.party_id,
                //     if i < self.party_count { i } else { i + 1 }
                // );
            }

            for conn in self.connections.iter() {
                let conn_s = conn.clone();
                send_tasks.push(tokio::spawn(async {
                    conn_s.send(send_chunk).await?;
                    anyhow::Ok(())
                }));
                // println!(
                //     "Party {}: Send to Party {}",
                //     self.party_id,
                //     if i < self.party_count { i } else { i + 1 }
                // );
            }
        }

        for task in send_tasks {
            task.await??;
        }

        for task in recv_tasks {
            task.await??;
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
