use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use network::{
    IO, Id, NetIoError,
    netio::{NetIO, Participant},
};
use primus_fhe_core::{NttRlwePublicKey, NttRlweSecretKey, RlweSecretKey};
use primus_integer::UnsignedInteger;
use tokio::runtime::Runtime;

use crate::{CommitTable, CommitValueT, MasterPublicKey, SsleParameters};

pub struct Party {
    mpk: MasterPublicKey,
    rt: Runtime,
    netio: Arc<NetIO>,
}

impl Party {
    pub fn new(
        party_id: Id,
        participants: Vec<Participant>,
        mpk: MasterPublicKey,
        worker_threads: usize,
    ) -> Self {
        let rt = if worker_threads <= 1 {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
        } else {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(worker_threads)
                .enable_all()
                .build()
                .unwrap()
        };

        let netio = rt
            .block_on(async { NetIO::new(party_id, participants).await })
            .unwrap();

        Self { mpk, rt, netio }
    }

    pub fn party_id(&self) -> Id {
        self.netio.party_id()
    }

    pub fn num_parties(&self) -> usize {
        self.netio.num_parties()
    }

    pub fn mpk(&self) -> &MasterPublicKey {
        &self.mpk
    }

    pub fn params(&self) -> &SsleParameters {
        self.mpk.params()
    }

    pub fn table(&self) -> &primus_ntt::CrtConcrete64Table {
        self.mpk.table()
    }

    pub fn generate_rotate_rgsw<R>(
        &self,
        degree: usize,
        rng: &mut R,
    ) -> primus_lattice::ggsw::DcrtGgsw<Vec<crate::CrtValueT>>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        self.mpk.generate_rotate_rgsw(degree, rng)
    }

    pub fn generate_rotate_rgsw_inplace<R, A>(
        &self,
        degree: usize,
        result: &mut primus_lattice::ggsw::DcrtGgsw<A>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: primus_poly::RawData<Elem = crate::CrtValueT> + primus_poly::DataMut,
    {
        self.mpk.generate_rotate_rgsw_inplace(degree, result, rng)
    }

    pub fn generate_commit_key_pair<R>(
        &self,
        ntt_table: &CommitTable,
        rng: &mut R,
    ) -> (
        NttRlweSecretKey<CommitValueT>,
        NttRlwePublicKey<Vec<CommitValueT>>,
    )
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let commit_params = self.mpk.commit_params();

        let commit_sk = RlweSecretKey::generate(commit_params, rng);
        let commit_sk = NttRlweSecretKey::from_coeff_secret_key(&commit_sk, ntt_table);
        let commit_pk = NttRlwePublicKey::new(&commit_sk, commit_params, ntt_table, rng);

        (commit_sk, commit_pk)
    }

    pub fn share(&self, data: Bytes, mut destination: BytesMut) -> Bytes {
        let chunk_size = data.len();

        self.rt
            .block_on(async {
                for (i, chunk) in destination.chunks_exact_mut(chunk_size).enumerate() {
                    if i as Id == self.party_id() {
                        self.netio.broadcast(&data).await?;
                        chunk.copy_from_slice(&data);
                    } else {
                        self.netio.recv(i as Id, chunk).await?;
                    }
                }
                Ok::<_, NetIoError>(())
            })
            .unwrap();

        destination.freeze()
    }

    pub fn share_v2<T: UnsignedInteger>(&self, data: &[T], destination: &mut [T]) {
        let chunk_size = data.len();

        self.rt
            .block_on(async {
                for (i, chunk) in destination.chunks_exact_mut(chunk_size).enumerate() {
                    if i as Id == self.party_id() {
                        self.netio.broadcast(bytemuck::cast_slice(data)).await?;
                        chunk.copy_from_slice(data);
                    } else {
                        self.netio
                            .recv(i as Id, bytemuck::cast_slice_mut(chunk))
                            .await?;
                    }
                }
                Ok::<_, NetIoError>(())
            })
            .unwrap();
    }

    pub fn share_v3<I: AsRef<[T]> + AsMut<[T]>, T: UnsignedInteger>(
        &self,
        data: &I,
        result: &mut [I],
    ) {
        let data: &[T] = data.as_ref();
        let data_bytes: &[u8] = bytemuck::cast_slice(data);

        self.rt
            .block_on(async {
                for (i, chunk) in result.iter_mut().enumerate() {
                    if i as Id == self.party_id() {
                        self.netio.broadcast(data_bytes).await?;
                        chunk.as_mut().copy_from_slice(data);
                    } else {
                        self.netio
                            .recv(i as Id, bytemuck::cast_slice_mut(chunk.as_mut()))
                            .await?;
                    }
                }
                Ok::<_, NetIoError>(())
            })
            .unwrap();
    }
}
