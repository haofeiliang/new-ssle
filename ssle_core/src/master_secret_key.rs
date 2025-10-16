use std::sync::Arc;

use primus_fhe_core::{CrtGlweSecretKey, DcrtGlweSecretKey};
use primus_ntt::CrtConcrete64Table;

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
}
