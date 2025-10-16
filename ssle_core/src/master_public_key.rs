use std::{cell::RefCell, sync::Arc};

use primus_fhe_core::DcrtGlwePublicKey;
use primus_integer::ByteCount;
use primus_lattice::DcrtGgsw;
use primus_modulus::BarrettModulus;
use primus_ntt::CrtConcrete64Table;

use crate::{CrtValueT, SsleParameters};

thread_local! {
    static BUFFER: RefCell<Vec<u8>> = RefCell::new(vec![0;3*8]);
}

#[derive(Clone)]
pub struct MasterPublicKey {
    pk: DcrtGlwePublicKey<CrtValueT, BarrettModulus<CrtValueT>>,
    table: Arc<CrtConcrete64Table>,
    params: SsleParameters,
}

impl MasterPublicKey {
    /// Returns a reference to the pk public key this [`MasterPublicKey`].
    #[inline]
    pub fn pk(&self) -> &DcrtGlwePublicKey<CrtValueT, BarrettModulus<CrtValueT>> {
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
        BUFFER.with_borrow_mut(|buf| {
            let ring_params = self.ring_params();
            let moduli_count = ring_params.moduli_count();
            buf.resize(moduli_count * <CrtValueT as ByteCount>::BYTES_COUNT, 0);

            let coeff_residues = bytemuck::cast_slice_mut(buf);
            coeff_residues.fill(1);

            self.pk.encrypt_monomial_ggsw(
                coeff_residues,
                degree,
                &ring_params.basis(),
                ring_params.noise_distribution(),
                self.table.as_ref(),
                rng,
            )
        })
    }

    /// Returns a reference to the ring params of this [`MasterPublicKey`].
    #[inline]
    pub fn ring_params(
        &self,
    ) -> &primus_fhe_core::CrtGgswParameters<u64, primus_modulus::BarrettModulus<u64>> {
        self.params.ring_params()
    }
}
