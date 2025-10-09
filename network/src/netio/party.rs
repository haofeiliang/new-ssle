use std::net::SocketAddr;

use crate::Id;

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
}
