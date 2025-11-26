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
}

impl TreeNetIO for QuicNetIO {
    async fn share(&self, data: &[u8], buf: &mut [u8]) -> anyhow::Result<()> {
        // let data_chunk_size = data.len() / self.stream_count;
        // assert_eq!(data_chunk_size * self.stream_count, data.len());

        // let send_tasks: Vec<_> = self
        //     .send
        //     .iter()
        //     .zip(data.chunks_exact(data_chunk_size))
        //     .map(|(send, data_chunk)| {
        //         let send_task = async {
        //             let mut send = send.lock();
        //             send.write_all(data_chunk).await?;
        //             send.flush().await?;
        //             anyhow::Ok(())
        //         };
        //         send_task
        //     })
        //     .collect();

        // let buf_chunk_size = buf.len() / self.stream_count;
        // assert_eq!(buf_chunk_size * self.stream_count, data.len());

        // let recv_tasks: Vec<_> = self
        //     .recv
        //     .iter()
        //     .zip(buf.chunks_exact_mut(buf_chunk_size))
        //     .map(|(recv, buf_chunk)| {
        //         let recv_task = async {
        //             let mut recv = recv.lock();
        //             recv.read_exact(buf_chunk).await?;
        //             anyhow::Ok(())
        //         };
        //         recv_task
        //     })
        //     .collect();

        // let send_task = futures::future::try_join_all(send_tasks);
        // let recv_task = futures::future::try_join_all(recv_tasks);

        // tokio::try_join!(send_task, recv_task)?;

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
