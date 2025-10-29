use std::sync::Arc;

use primus_fhe_core::{
    CrtGlweParameters, CrtGlweSecretKey, DcrtGlweCiphertext, DcrtGlweDecryptContext,
    DcrtGlweSecretKey,
};
use primus_ntt::{CrtConcrete64Table, Dcrt, DcrtTable};
use primus_poly::{Data, DataMut, Polynomial, RawData};
use primus_reduce::FieldContext;

use crate::{CrtValueT, SsleParameters};

pub struct MasterSecretKey {
    sk: CrtGlweSecretKey<CrtValueT>,
    dcrt_sk: DcrtGlweSecretKey<CrtValueT>,
    table: Arc<CrtConcrete64Table>,
    params: SsleParameters,
}

impl MasterSecretKey {
    /// Creates a new [`MasterSecretKey`].
    pub fn new(
        sk: CrtGlweSecretKey<CrtValueT>,
        dcrt_sk: DcrtGlweSecretKey<CrtValueT>,
        table: Arc<CrtConcrete64Table>,
        params: SsleParameters,
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

    pub fn table(&self) -> &CrtConcrete64Table {
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
}
