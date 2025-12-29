mod net_io;
mod topology;

pub use net_io::{PairWiseNetIO, Role, TcpNetIO, TreeNetIO};
pub use topology::{Participant, TcpPairWise, TcpTree};

pub type Id = u32;
