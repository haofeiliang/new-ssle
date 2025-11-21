use quinn::Connection;

pub struct QuicNetIO {
    connection: Connection,
}

impl QuicNetIO {
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }
}

async fn open_bidirectional_stream(connection: Connection) -> anyhow::Result<()> {
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(b"test").await?;
    send.finish()?;
    let received = recv.read_to_end(10).await?;
    Ok(())
}

async fn receive_bidirectional_stream(connection: Connection) -> anyhow::Result<()> {
    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
        // Because it is a bidirectional stream, we can both send and receive.
        println!("request: {:?}", recv.read_to_end(50).await?);
        send.write_all(b"response").await?;
        send.finish()?;
    }
    Ok(())
}
