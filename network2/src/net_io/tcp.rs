use std::{cell::RefCell, sync::Arc};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::Mutex,
};

use crate::TreeNetIO;

use super::Role;

pub struct TcpNetIO {
    role: Role,
    write_half: Arc<Mutex<OwnedWriteHalf>>,
    read_half: RefCell<OwnedReadHalf>,
}

impl TcpNetIO {
    pub fn new(role: Role, tcp_stream: TcpStream) -> Self {
        let (read_half, write_half) = tcp_stream.into_split();
        Self {
            role,
            write_half: Arc::new(Mutex::new(write_half)),
            read_half: RefCell::new(read_half),
        }
    }

    pub fn role(&self) -> Role {
        self.role
    }
}

impl TreeNetIO for TcpNetIO {
    async fn share(&self, data: &[u8], buf: &mut [u8]) -> anyhow::Result<()> {
        let static_data: &'static [u8] = unsafe { std::mem::transmute(data) };

        let write_half = self.write_half.clone();
        let send_task = tokio::spawn(async move {
            let mut write_half_mut = write_half.lock().await;
            write_half_mut.write_all(static_data).await?;
            write_half_mut.flush().await?;
            anyhow::Ok(())
        });

        self.read_half.borrow_mut().read_exact(buf).await?;

        send_task.await??;

        Ok(())
    }
}
