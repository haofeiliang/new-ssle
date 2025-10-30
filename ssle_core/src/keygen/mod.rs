use std::sync::Arc;

use primus_fhe_core::{
    CrtGlevParameters, CrtGlweCiphertext, CrtGlweSecretKey, CrtGlweTraceContext, CrtGlweTraceKey,
    DcrtGlwePublicKey, DcrtGlweSecretKey,
};
use primus_modulus::BarrettModulus;
use primus_ntt::DcrtTable;
use primus_poly::{Data, DataMut, RawData};
use primus_reduce::FieldContext;
use primus_rns::RNSBase;

use crate::{CrtTable, CrtValueT, MasterPublicKey, MasterSecretKey, SsleParameters};

pub struct KeyGen;

impl KeyGen {
    pub fn generate_keys<R>(
        params: &Arc<SsleParameters>,
        rng: &mut R,
    ) -> (MasterSecretKey, MasterPublicKey, CoefficientExpansionKey)
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let ring_params = params.ring_params();
        let poly_length = ring_params.poly_length();

        let table = Arc::new(
            CrtTable::new(poly_length.trailing_zeros(), ring_params.cipher_moduli()).unwrap(),
        );
        let sk = CrtGlweSecretKey::generate(&ring_params, rng);
        let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, table.as_ref());

        let pk = DcrtGlwePublicKey::new(&dcrt_sk, &ring_params, table.as_ref(), rng);

        let eck = CoefficientExpansionKey::new(
            params.expand_coeff_params(),
            &sk,
            &dcrt_sk,
            Arc::clone(&table),
            rng,
        );

        (
            MasterSecretKey::new(sk, dcrt_sk, Arc::clone(&table), Arc::clone(params)),
            MasterPublicKey::new(pk, table, Arc::clone(params)),
            eck,
        )
    }
}

#[derive(Clone)]
pub struct CoefficientExpansionKey {
    trace_key: CrtGlweTraceKey<CrtValueT, CrtTable>,
}

impl CoefficientExpansionKey {
    pub fn new<R>(
        params: &CrtGlevParameters<CrtValueT, BarrettModulus<CrtValueT>>,
        sk: &CrtGlweSecretKey<CrtValueT>,
        dcrt_sk: &DcrtGlweSecretKey<CrtValueT>,
        table: Arc<CrtTable>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
    {
        Self {
            trace_key: CrtGlweTraceKey::new(params, sk, dcrt_sk, table, rng),
        }
    }

    pub fn expand_partial_coefficients_inplace<M, A, B>(
        &self,
        ciphertext: &CrtGlweCiphertext<A>,
        result: &mut [CrtGlweCiphertext<B>],
        params: &CrtGlevParameters<CrtValueT, M>,
        rns_base: &RNSBase<CrtValueT, M>,
        context: &mut CrtGlweTraceContext<CrtValueT>,
    ) where
        M: FieldContext<CrtValueT>,
        A: RawData<Elem = CrtValueT> + Data,
        B: RawData<Elem = CrtValueT> + DataMut,
    {
        self.trace_key
            .expand_partial_coefficients_inplace(ciphertext, result, params, rns_base, context)
    }
}
