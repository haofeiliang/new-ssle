use std::{sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
    time::sleep,
};

use crate::{Id, Role, TreeNetIO, net_io::TcpNetIO};

use super::Participant;

pub struct TcpTree {
    party_id: Id,
    party_count: usize,
    log_n: u32,
    connections: Vec<TcpNetIO>,
}

impl TcpTree {
    pub async fn new(party_id: Id, participants: Vec<Participant>) -> anyhow::Result<Self> {
        let party_count = participants.len();
        assert!(party_count.is_power_of_two());

        let listener =
            tokio::net::TcpListener::bind(participants[party_id as usize].address).await?;

        let log_n = party_count.trailing_zeros();

        let connections = Arc::new(Mutex::new(Vec::with_capacity(log_n as usize)));

        let mut temp = connections.lock().await;
        for _i in 0..log_n {
            temp.push(None);
        }
        drop(temp);

        let mut client_count = log_n as usize - party_id.count_ones() as usize;
        let mut listen_handle = None;
        if client_count != 0 {
            let conns = connections.clone();
            listen_handle = Some(tokio::spawn(async move {
                // println!("Party {party_id}: Waiting for Connection Count {client_count}.");
                while client_count != 0 {
                    let (mut tcp_stream, _addr) = listener.accept().await?;
                    // println!("Party {party_id}: Get A Connection.");

                    tcp_stream.set_nodelay(true)?;

                    let peer_id = tcp_stream.read_u32().await?;
                    // println!("Party {party_id}: Peer id {peer_id}.");

                    let mask = party_id ^ peer_id;
                    assert!(mask.is_power_of_two(), "Party {party_id} vs Peer {peer_id}");
                    let index = mask.trailing_zeros() as usize;

                    let mut conns_mut = conns.lock().await;
                    if conns_mut[index].is_some() {
                        panic!("Sever: duplicated connection!")
                    } else {
                        conns_mut[index] = Some((Role::Server, tcp_stream));
                    }

                    drop(conns_mut);

                    client_count -= 1;
                }
                anyhow::Ok(())
            }));
        }

        if party_id != 0 {
            for i in 0..log_n {
                let peer_id = party_id ^ (1 << i);
                if peer_id < party_id {
                    // println!("Party {party_id}: Connect to Party {peer_id}.");
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
                    // println!("Party {party_id}: Connect to Party {peer_id} successfully.");
                    tcp_stream.set_nodelay(true)?;
                    tcp_stream.write_u32(party_id).await?;
                    tcp_stream.flush().await?;

                    let mut conns_mut = connections.lock().await;
                    if conns_mut[i as usize].is_some() {
                        panic!("Client: duplicated connection!")
                    } else {
                        conns_mut[i as usize] = Some((Role::Client, tcp_stream));
                    }
                }
            }
        }

        if let Some(handle) = listen_handle {
            handle.await??;
        }

        let guard = Arc::try_unwrap(connections).unwrap();

        let connections = guard
            .into_inner()
            .into_iter()
            .map(|a| {
                let (role, tcp_stream) = a.expect("All connections should be established!");
                TcpNetIO::new(role, tcp_stream)
            })
            .collect();

        Ok(Self {
            party_id,
            party_count,
            log_n,
            connections,
        })
    }

    pub async fn share(&self, data: &mut [u8], chunk_size: usize) -> anyhow::Result<()> {
        assert_eq!(data.len(), chunk_size * self.party_count);

        let mut part_size = chunk_size;
        let mut start = part_size * self.party_id as usize;
        let mut end = start + part_size;

        for net_io in self.connections.iter() {
            match net_io.role() {
                Role::Server => end += part_size,
                Role::Client => start -= part_size,
            }
            let part = &mut data[start..end];
            let (data, buf) = match net_io.role() {
                Role::Server => part.split_at_mut(part_size),
                Role::Client => {
                    let (buf, data) = part.split_at_mut(part_size);
                    (data, buf)
                }
            };
            net_io.share(data, buf).await?;
            part_size += part_size;
        }

        Ok(())
    }

    pub fn log_n(&self) -> u32 {
        self.log_n
    }

    pub async fn close(self) -> anyhow::Result<()> {
        for c in self.connections {
            c.close().await?
        }
        Ok(())
    }
}
