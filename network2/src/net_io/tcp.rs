use std::cell::RefCell;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
};

use crate::TreeNetIO;

use super::Role;

pub struct TcpNetIO {
    role: Role,
    write_half: RefCell<OwnedWriteHalf>,
    read_half: RefCell<OwnedReadHalf>,
}

impl TcpNetIO {
    pub fn new(role: Role, tcp_stream: TcpStream) -> Self {
        let (read_half, write_half) = tcp_stream.into_split();
        Self {
            role,
            write_half: RefCell::new(write_half),
            read_half: RefCell::new(read_half),
        }
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub async fn close(self) -> anyhow::Result<()> {
        let mut tcp_stream = self
            .write_half
            .into_inner()
            .reunite(self.read_half.into_inner())?;

        tcp_stream.shutdown().await?;

        Ok(())
    }
}

impl TreeNetIO for TcpNetIO {
    async fn share(&self, data: &[u8], buf: &mut [u8]) -> anyhow::Result<()> {
        let send_task = async {
            let mut write_half_mut = self.write_half.borrow_mut();
            write_half_mut.write_all(data).await?;
            write_half_mut.flush().await?;
            anyhow::Ok(())
        };

        let recv_task = async {
            self.read_half.borrow_mut().read_exact(buf).await?;
            anyhow::Ok(())
        };

        tokio::try_join!(send_task, recv_task)?;

        Ok(())
    }
}
