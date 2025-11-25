use quinn::Connection;
use tokio::io::AsyncWriteExt;

use crate::net_io::TreeNetIO;

use super::Role;

pub struct QuicNetIO {
    role: Role,
    connection: Connection,
}

impl QuicNetIO {
    pub fn new(role: Role, connection: Connection) -> Self {
        Self { role, connection }
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

impl TreeNetIO for QuicNetIO {
    async fn share(&self, data: &[u8], buf: &mut [u8]) -> anyhow::Result<()> {
        let (mut send, mut recv) = match self.role {
            Role::Server => self.connection.accept_bi().await?,
            Role::Client => self.connection.open_bi().await?,
        };

        let static_data: &'static [u8] = unsafe { std::mem::transmute(data) };

        let send_task = tokio::spawn(async move {
            send.write_all(static_data).await?;
            send.flush().await?;
            anyhow::Ok(())
        });

        recv.read_exact(buf).await?;

        send_task.await??;

        Ok(())
    }
}
