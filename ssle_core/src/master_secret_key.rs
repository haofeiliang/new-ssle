use std::sync::Arc;

use primus_fhe_core::{
    CrtGlweParameters, CrtGlweSecretKey, DcrtGlweCiphertext, DcrtGlweDecryptContext,
    DcrtGlweSecretKey,
};
use primus_ntt::{Dcrt, DcrtTable};
use primus_poly::{Data, DataMut, Polynomial, RawData};
use primus_reduce::FieldContext;

use crate::{CrtTable, CrtValueT, SsleParameters};

#[derive(Clone)]
pub struct MasterSecretKey {
    sk: CrtGlweSecretKey<CrtValueT>,
    dcrt_sk: DcrtGlweSecretKey<CrtValueT>,
    table: Arc<CrtTable>,
    params: Arc<SsleParameters>,
}

impl MasterSecretKey {
    /// Creates a new [`MasterSecretKey`].
    pub fn new(
        sk: CrtGlweSecretKey<CrtValueT>,
        dcrt_sk: DcrtGlweSecretKey<CrtValueT>,
        table: Arc<CrtTable>,
        params: Arc<SsleParameters>,
    ) -> Self {
        Self {
            sk,
            dcrt_sk,
            table,
            params,
        }
    }

    pub fn sk(&self) -> &CrtGlweSecretKey<CrtValueT> {
        &self.sk
    }

    pub fn dcrt_sk(&self) -> &DcrtGlweSecretKey<CrtValueT> {
        &self.dcrt_sk
    }

    pub fn params(&self) -> &SsleParameters {
        &self.params
    }

    pub fn table(&self) -> &CrtTable {
        &self.table
    }

    pub fn decrypt_inplace<M, Table, A, B>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        msg: &mut Polynomial<B>,
        params: &CrtGlweParameters<CrtValueT, M>,
        table: &Table,
        context: &mut DcrtGlweDecryptContext<CrtValueT>,
    ) where
        M: FieldContext<CrtValueT>,
        Table: DcrtTable<ValueT = CrtValueT> + Dcrt,
        A: RawData<Elem = CrtValueT> + Data,
        B: RawData<Elem = CrtValueT> + DataMut,
    {
        self.dcrt_sk
            .decrypt_inplace(ciphertext, msg, params, table, context)
    }

    pub fn decrypt<M, Table, A>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        params: &CrtGlweParameters<CrtValueT, M>,
        table: &Table,
        context: &mut DcrtGlweDecryptContext<CrtValueT>,
    ) -> primus_poly::PolynomialOwned<CrtValueT>
    where
        M: FieldContext<CrtValueT>,
        Table: DcrtTable<ValueT = CrtValueT> + Dcrt,
        A: RawData<Elem = CrtValueT> + Data,
    {
        self.dcrt_sk.decrypt(ciphertext, params, table, context)
    }
    
    pub fn encrypt_zeros_inplace<R, M, Table, A>(
            &self,
            result: &mut DcrtGlweCiphertext<A>,
            params: &CrtGlweParameters<CrtValueT, M>,
            table: &Table,
            rng: &mut R,
        ) where
            R: rand::Rng + rand::CryptoRng,
            M: FieldContext<CrtValueT>,
            Table: DcrtTable<ValueT = CrtValueT> + Dcrt,
            A: RawData<Elem = CrtValueT> + DataMut, {
        self.dcrt_sk.encrypt_zeros_inplace(result, params, table, rng)
    }
}
