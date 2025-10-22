use std::sync::Arc;

use primus_fhe_core::DcrtGlwePublicKey;
use primus_lattice::ggsw::DcrtGgsw;
use primus_ntt::CrtConcrete64Table;

use crate::{CrtValueT, SsleParameters};

#[derive(Clone)]
pub struct MasterPublicKey {
    pk: DcrtGlwePublicKey<CrtValueT>,
    table: Arc<CrtConcrete64Table>,
    params: SsleParameters,
}

impl MasterPublicKey {
    pub fn new(
        pk: DcrtGlwePublicKey<CrtValueT>,
        table: Arc<CrtConcrete64Table>,
        params: SsleParameters,
    ) -> Self {
        Self { pk, table, params }
    }

    /// Returns a reference to the pk public key this [`MasterPublicKey`].
    #[inline]
    pub fn pk(&self) -> &DcrtGlwePublicKey<CrtValueT> {
        &self.pk
    }

    #[inline]
    pub fn table(&self) -> &CrtConcrete64Table {
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
            &ggsw_params,
            self.table.as_ref(),
            rng,
        )
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
}
