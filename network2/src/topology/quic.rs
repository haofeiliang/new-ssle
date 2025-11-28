use std::sync::Arc;

use parking_lot::Mutex;
use quinn::{
    ClientConfig, Endpoint, EndpointConfig,
    crypto::rustls::{NoInitialCipherSuite, QuicClientConfig},
    default_runtime,
};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    Id, TreeNetIO,
    net_io::{QuicNetIO, Role},
};

use super::Participant;

pub struct QuicTree {
    party_id: Id,
    party_count: usize,
    log_n: u32,
    endpoint: Endpoint,
    connections: Vec<QuicNetIO>,
}

impl QuicTree {
    pub async fn new(party_id: Id, participants: Vec<Participant>) -> anyhow::Result<Self> {
        let party_count = participants.len();
        assert!(party_count.is_power_of_two());

        let socket = std::net::UdpSocket::bind(participants[party_id as usize].address)?;
        let server_config = server_config()?;
        let mut endpoint = Endpoint::new(
            EndpointConfig::default(),
            Some(server_config),
            socket,
            default_runtime().unwrap(),
        )?;

        let client_config = configure_client()?;
        endpoint.set_default_client_config(client_config);

        let log_n = party_count.trailing_zeros();
        let connections = Arc::new(Mutex::new(Vec::with_capacity(log_n as usize)));

        let mut temp = connections.lock();
        for _i in 0..log_n {
            temp.push(None);
        }
        drop(temp);

        let mut client_count = log_n as usize - party_id.count_ones() as usize;
        let mut listen_handle = None;
        if client_count != 0 {
            let server = endpoint.clone();
            let conns = connections.clone();
            listen_handle = Some(tokio::spawn(async move {
                // println!("Party {party_id}: Waiting for Connection Count {client_count}.");
                while client_count != 0
                    && let Some(conn) = server.accept().await
                {
                    // println!("Party {party_id}: Get A Connection.");
                    let connection = conn.await?;
                    let (send, mut recv) = connection.accept_bi().await?;
                    // println!("Party {party_id}: accept_uni.");
                    let peer_id = recv.read_u32().await?;

                    // println!("Party {party_id}: Peer id {peer_id}.");

                    let mask = party_id ^ peer_id;
                    assert!(mask.is_power_of_two(), "Party {party_id} vs Peer {peer_id}");
                    let index = mask.trailing_zeros() as usize;

                    let mut conns_mut = conns.lock();
                    if let Some(_) = conns_mut[index] {
                        panic!("Sever: duplicated connection!")
                    } else {
                        conns_mut[index] = Some((Role::Server, connection, send, recv));
                    }
                    drop(conns_mut);

                    client_count -= 1;
                }
                anyhow::Ok(())
            }));
        }

        if party_id != 0 {
            for i in 0..log_n {
                let peer_id = party_id ^ (1 << i);
                if peer_id < party_id {
                    // println!("Party {party_id}: Connect to Party {peer_id}.");
                    let connection = endpoint
                        .connect(participants[peer_id as usize].address, "localhost")?
                        .await?;
                    // println!("Party {party_id}: Connect to Party {peer_id} successfully.");
                    let (mut send, recv) = connection.open_bi().await?;
                    // println!("Party {party_id}: open_uni.");
                    send.write_u32(party_id).await?;
                    send.flush().await?;

                    let mut conns_mut = connections.lock();
                    if let Some(_) = conns_mut[i as usize] {
                        panic!("Client: duplicated connection!")
                    } else {
                        conns_mut[i as usize] = Some((Role::Client, connection, send, recv));
                    }
                }
            }
        }

        if let Some(handle) = listen_handle {
            handle.await??;
        }

        // println!("Party {party_id}: Connect finished.");

        let guard = Arc::try_unwrap(connections).unwrap();

        let connections: Vec<QuicNetIO> = guard
            .into_inner()
            .into_iter()
            .map(|a| {
                let (role, connection, send, recv) =
                    a.expect("All connections should be established!");
                QuicNetIO::new(role, connection, send, recv)
            })
            .collect();

        Ok(Self {
            party_id,
            party_count,
            log_n,
            endpoint,
            connections,
        })
    }

    pub async fn share(&self, data: &mut [u8], chunk_size: usize) -> anyhow::Result<()> {
        assert_eq!(data.len(), chunk_size * self.party_count);

        let mut part_size = chunk_size;
        let mut start = part_size * self.party_id as usize;
        let mut end = start + part_size;

        for net_io in self.connections.iter() {
            match net_io.role() {
                Role::Server => end += part_size,
                Role::Client => start -= part_size,
            }
            let part = &mut data[start..end];
            let (data, buf) = match net_io.role() {
                Role::Server => part.split_at_mut(part_size),
                Role::Client => {
                    let (buf, data) = part.split_at_mut(part_size);
                    (data, buf)
                }
            };
            net_io.share(data, buf).await?;
            part_size += part_size;
        }

        Ok(())
    }

    pub fn log_n(&self) -> u32 {
        self.log_n
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub async fn close(&self) {
        for c in self.connections.iter() {
            c.close();
        }

        self.endpoint.wait_idle().await;
        self.endpoint.close(0u32.into(), b"finished");
    }
}

fn generate_self_signed_cert()
-> anyhow::Result<(CertificateDer<'static>, PrivatePkcs8KeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = CertificateDer::from(cert.cert);
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    Ok((cert_der, key))
}

fn server_config() -> anyhow::Result<quinn::ServerConfig> {
    let (certs, key) = generate_self_signed_cert()?;

    let mut server_config = quinn::ServerConfig::with_single_cert(
        vec![certs],
        rustls::pki_types::PrivateKeyDer::Pkcs8(key),
    )?;

    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    // transport_config.max_concurrent_uni_streams(128_u8.into());
    transport_config.max_concurrent_bidi_streams(128_u8.into());

    Ok(server_config)
}

// Implementation of `ServerCertVerifier` that verifies everything as trustworthy.
#[derive(Debug)]
struct SkipServerVerification(Arc<CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<danger::ServerCertVerified, rustls::Error> {
        Ok(danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn configure_client() -> Result<ClientConfig, NoInitialCipherSuite> {
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();

    Ok(ClientConfig::new(Arc::new(QuicClientConfig::try_from(
        crypto,
    )?)))
}
