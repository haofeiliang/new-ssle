use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use network::{
    IO, Id, NetIoError,
    netio::{NetIO, Participant},
};
use primus_factor::ShoupFactor;
use primus_fhe_core::{NttRlwePublicKey, NttRlweSecretKey};
use primus_integer::{AsInto, DataMut, RawData, UnsignedInteger};
use primus_lattice::{ggsw::DcrtGgsw, glwe::CrtGlwe};
use primus_reduce::{Modulus, ReduceInv};
use tokio::runtime::Runtime;

use crate::{CommitModulus, CommitTable, CommitValueT, CrtValueT, MasterPublicKey, SsleParameters};

pub struct Party {
    mpk: MasterPublicKey,
    rt: Runtime,
    netio: Arc<NetIO>,
    inv_two: CommitValueT,
    inv_two_factor: ShoupFactor<CommitValueT>,
    inv_party_count: CommitValueT,
    inv_party_count_factor: ShoupFactor<CommitValueT>,
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

        let party_count = participants.len();

        let netio = rt
            .block_on(async { NetIO::new(party_id, participants).await })
            .unwrap();

        let commit_params = mpk.commit_params();

        let inv_two = CommitModulus.reduce_inv(2);
        let inv_two_factor = ShoupFactor::new(inv_two, CommitModulus.value_unchecked());
        let inv_party_count = commit_params
            .cipher_modulus()
            .reduce_inv(party_count.as_into());
        let inv_party_count_factor =
            ShoupFactor::new(inv_party_count, CommitModulus.value_unchecked());

        Self {
            mpk,
            rt,
            netio,
            inv_two,
            inv_two_factor,
            inv_party_count,
            inv_party_count_factor,
        }
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

    pub fn inv_two(&self) -> CommitValueT {
        self.inv_two
    }

    pub fn inv_two_factor(&self) -> ShoupFactor<CommitValueT> {
        self.inv_two_factor
    }

    pub fn inv_party_count(&self) -> CommitValueT {
        self.inv_party_count
    }

    pub fn inv_party_count_factor(&self) -> ShoupFactor<CommitValueT> {
        self.inv_party_count_factor
    }

    pub fn generate_rotate_rgsw<R>(
        &self,
        degree: usize,
        rng: &mut R,
    ) -> DcrtGgsw<Vec<crate::CrtValueT>>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        self.mpk.generate_rotate_rgsw(degree, rng)
    }

    pub fn generate_rotate_rgsw_inplace<R, A>(
        &self,
        degree: usize,
        result: &mut DcrtGgsw<A>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = crate::CrtValueT> + DataMut,
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
        self.mpk.generate_commit_key_pair(ntt_table, rng)
    }

    pub fn generate_init_acc(&self) -> CrtGlwe<Vec<CrtValueT>> {
        let ring_params = self.mpk.ring_params();
        let poly_length = ring_params.poly_length();
        let rns_glwe_len = ring_params.rns_glwe_len();
        let num_parties = self.num_parties();

        let mut acc: CrtGlwe<Vec<CrtValueT>> = CrtGlwe::zero(rns_glwe_len);
        let (_, b) = acc.a_b_mut_slices(ring_params.rns_glwe_mid());
        b.chunks_exact_mut(poly_length)
            .zip(ring_params.delta_mod_q())
            .for_each(|(poly, &one)| {
                poly.iter_mut().step_by(num_parties).for_each(|v| *v = one);
            });

        acc
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

    pub fn share_to_p0<T: UnsignedInteger>(&self, data: &[T], destination: Option<&mut [T]>) {
        let chunk_size = data.len();

        self.rt
            .block_on(async {
                match destination {
                    Some(des) => {
                        for (i, chunk) in des.chunks_exact_mut(chunk_size).enumerate() {
                            if i as Id == self.party_id() {
                                chunk.copy_from_slice(data);
                            } else {
                                self.netio
                                    .recv(i as Id, bytemuck::cast_slice_mut(chunk))
                                    .await?;
                            }
                        }
                    }
                    None => {
                        self.netio.send(0, bytemuck::cast_slice(data)).await?;
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
