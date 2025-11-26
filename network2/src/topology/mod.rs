use std::{
    fs::File,
    io::{BufRead, BufReader},
    net::{Ipv4Addr, SocketAddr},
    path::Path,
};

mod quic;
mod tcp;

use crate::Id;

pub use quic::QuicTree;
pub use tcp::TcpTree;

/// Represents a participant in the network.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Participant {
    /// The unique ID of the participant.
    pub id: Id,
    /// The network address of the participant.
    pub address: SocketAddr,
}

impl Participant {
    /// Creates a list of participants with sequential IDs and addresses.
    ///
    /// # Arguments
    /// - `count`: The number of participants.
    /// - `base_port`: The starting port number.
    ///
    /// # Returns
    /// A vector of participants.
    pub fn from_default(count: usize, base_port: u16) -> Vec<Self> {
        let count: Id = count.try_into().unwrap();
        let port = |id| {
            base_port
                .checked_add(<Id as TryInto<u16>>::try_into(id).unwrap())
                .unwrap()
        };
        (0..count)
            .map(|id| Participant {
                id,
                address: SocketAddr::from(([127, 0, 0, 1], port(id))),
            })
            .collect()
    }

    pub fn from_file(file_path: &Path, base_port: u16) -> anyhow::Result<Vec<Self>> {
        let file = File::open(file_path)?;
        let mut reader = BufReader::new(file);

        Self::from_reader(&mut reader, base_port)
    }

    pub fn from_reader(reader: &mut BufReader<File>, base_port: u16) -> anyhow::Result<Vec<Self>> {
        let mut line = String::new();

        reader.read_line(&mut line)?;

        let party_count = trim_end(&mut line).parse::<usize>()?;

        let mut parties = Vec::with_capacity(party_count);

        let port = |id| {
            base_port
                .checked_add(<Id as TryInto<u16>>::try_into(id).unwrap())
                .unwrap()
        };

        for i in 0..party_count {
            line.clear();
            reader.read_line(&mut line)?;
            let addr = trim_end(&mut line).parse::<Ipv4Addr>()?;

            let id = i as Id;

            parties.push(Participant {
                id,
                address: SocketAddr::from((addr, port(id))),
            });
        }

        Ok(parties)
    }
}

fn trim_end(buf: &mut String) -> &str {
    if buf.ends_with('\n') {
        buf.pop();
        if buf.ends_with('\r') {
            buf.pop();
        }
    }
    buf
}
