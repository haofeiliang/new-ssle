use std::sync::Arc;

use primus_fhe_core::{DcrtGlwePublicKey, NttRlwePublicKey, NttRlweSecretKey, RlweSecretKey};
use primus_integer::{DataMut, RawData};
use primus_lattice::{ggsw::DcrtGgsw, glwe::CrtGlwe};

use crate::{CommitTable, CommitValueT, CrtTable, CrtValueT, SsleParameters};

#[derive(Clone)]
pub struct MasterPublicKey {
    pk: DcrtGlwePublicKey<CrtValueT>,
    table: Arc<CrtTable>,
    params: Arc<SsleParameters>,
}

impl MasterPublicKey {
    pub fn new(
        pk: DcrtGlwePublicKey<CrtValueT>,
        table: Arc<CrtTable>,
        params: Arc<SsleParameters>,
    ) -> Self {
        Self { pk, table, params }
    }

    /// Returns a reference to the pk public key this [`MasterPublicKey`].
    #[inline]
    pub fn pk(&self) -> &DcrtGlwePublicKey<CrtValueT> {
        &self.pk
    }

    #[inline]
    pub fn table(&self) -> &CrtTable {
        &self.table
    }

    #[inline]
    pub fn params(&self) -> &SsleParameters {
        &self.params
    }

    pub fn generate_rotate_rgsw<R>(&self, degree: usize, rng: &mut R) -> DcrtGgsw<Vec<CrtValueT>>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let ggsw_params = self.ggsw_params();
        let moduli_count = ggsw_params.cipher_moduli_count();

        let coeff_residues: Vec<CrtValueT> = vec![1; moduli_count];

        self.pk.encrypt_monomial_ggsw(
            &coeff_residues,
            degree,
            ggsw_params,
            self.table.as_ref(),
            rng,
        )
    }

    pub fn generate_rotate_rgsw_inplace<R, A>(
        &self,
        mut degree: usize,
        result: &mut DcrtGgsw<A>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = CrtValueT> + DataMut,
    {
        let ggsw_params = self.ggsw_params();
        let moduli_count = ggsw_params.cipher_moduli_count();

        let poly_length = ggsw_params.poly_length();

        assert!(degree < poly_length * 2);

        let coeff_residues: Vec<CrtValueT> = if degree < poly_length {
            vec![1; moduli_count]
        } else {
            degree -= poly_length;
            ggsw_params.cipher_moduli_minus_one().to_vec()
        };

        self.pk.encrypt_monomial_ggsw_inplace(
            &coeff_residues,
            degree,
            result,
            ggsw_params,
            self.table.as_ref(),
            rng,
        );
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
        let commit_params = self.commit_params();

        let commit_sk = RlweSecretKey::generate(commit_params, rng);
        let commit_sk = NttRlweSecretKey::from_coeff_secret_key(&commit_sk, ntt_table);
        let commit_pk = NttRlwePublicKey::new(&commit_sk, commit_params, ntt_table, rng);

        (commit_sk, commit_pk)
    }

    pub fn generate_init_acc(&self, party_count: usize) -> CrtGlwe<Vec<CrtValueT>> {
        let ring_params = self.ring_params();
        let poly_length = ring_params.poly_length();

        let mut acc: CrtGlwe<Vec<CrtValueT>> = CrtGlwe::zero(ring_params.rns_glwe_len());

        let (_, b) = acc.a_b_mut_slices(ring_params.rns_glwe_mid());
        b.chunks_exact_mut(poly_length)
            .zip(ring_params.delta_mod_q())
            .for_each(|(poly, &one)| {
                poly.iter_mut().step_by(party_count).for_each(|v| *v = one);
            });

        acc
    }

    pub fn ring_params(
        &self,
    ) -> &primus_fhe_core::CrtGlweParameters<CrtValueT, primus_modulus::BarrettModulus<CrtValueT>>
    {
        self.params.ring_params()
    }

    pub fn ggsw_params(
        &self,
    ) -> &primus_fhe_core::CrtGgswParameters<CrtValueT, primus_modulus::BarrettModulus<CrtValueT>>
    {
        self.params.ggsw_params()
    }

    pub fn commit_params(&self) -> &primus_fhe_core::RlweParameters<u32, crate::CommitModulus> {
        self.params.commit_params()
    }
}
