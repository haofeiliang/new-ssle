use parking_lot::Mutex;
use quinn::{Connection, RecvStream, SendStream};
use tokio::io::AsyncWriteExt;

use crate::net_io::TreeNetIO;

use super::Role;

pub struct QuicNetIO {
    role: Role,
    connection: Connection,
    send: Mutex<SendStream>,
    recv: Mutex<RecvStream>,
}

impl QuicNetIO {
    pub fn new(role: Role, connection: Connection, send: SendStream, recv: RecvStream) -> Self {
        Self {
            role,
            connection,
            send: Mutex::new(send),
            recv: Mutex::new(recv),
        }
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub fn close(&self) {
        let _ = self.send.lock().finish();
        // let _ = self.recv.lock().stop(0u32.into());
        // self.connection.close(0u32.into(), b"finished");
    }
}

impl TreeNetIO for QuicNetIO {
    async fn share(&self, data: &[u8], buf: &mut [u8]) -> anyhow::Result<()> {
        let mut send = self.send.lock();
        let mut recv = self.recv.lock();

        let send_task = async {
            send.write_all(data).await?;
            send.flush().await?;
            anyhow::Ok(())
        };
        let recv_task = async {
            recv.read_exact(buf).await?;
            anyhow::Ok(())
        };

        tokio::try_join!(send_task, recv_task)?;

        Ok(())
    }
}
