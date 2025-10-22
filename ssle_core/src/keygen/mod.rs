use std::sync::Arc;

use primus_fhe_core::{CrtGlweSecretKey, DcrtGlwePublicKey, DcrtGlweSecretKey};
use primus_ntt::{CrtConcrete64Table, DcrtTable};

use crate::{MasterPublicKey, MasterSecretKey, SsleParameters};

pub struct KeyGen;

impl KeyGen {
    pub fn generate_keys<R>(
        params: SsleParameters,
        rng: &mut R,
    ) -> (MasterSecretKey, MasterPublicKey)
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let ring_params = params.ring_params();
        let poly_length = ring_params.poly_length();

        let table = Arc::new(
            CrtConcrete64Table::new(poly_length.trailing_zeros(), ring_params.cipher_moduli())
                .unwrap(),
        );
        let sk = { CrtGlweSecretKey::generate(&ring_params, rng) };
        let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, table.as_ref());

        let pk = DcrtGlwePublicKey::new(&dcrt_sk, &ring_params, table.as_ref(), rng);

        (
            MasterSecretKey::new(sk, dcrt_sk, Arc::clone(&table), params.clone()),
            MasterPublicKey::new(pk, table, params),
        )
    }
}
