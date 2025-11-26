mod net_io;
mod topology;

pub use net_io::{QuicNetIO, Role, TcpNetIO, TreeNetIO};
pub use topology::{Participant, QuicTree, TcpTree};

pub type Id = u32;
