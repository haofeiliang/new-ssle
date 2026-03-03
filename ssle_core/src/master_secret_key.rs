use std::sync::Arc;

use num::{BigUint, Integer};
use primus_fhe_core::{
    CrtGlweParameters, CrtGlweSecretKey, DcrtGlweCiphertext, DcrtGlweDecryptContext,
    DcrtGlweSecretKey,
};
use primus_integer::{Data, DataMut, RawData, izip};
use primus_ntt::DcrtTable;
use primus_poly::{DcrtPolynomial, Polynomial};
use primus_reduce::FieldContext;
use rand::{
    RngExt,
    distr::{Distribution, Uniform},
};

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

    pub fn generate_shares<R>(&self, party_count: usize, rng: &mut R) -> Vec<MasterSecretKeyShare>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let ring_params = self.params().ring_params();
        let table = self.table.as_ref();
        let poly_length = ring_params.poly_length();
        let moduli = ring_params.cipher_moduli();

        let mut shares = Vec::with_capacity(party_count);
        for _ in 0..party_count - 1 {
            let sk = CrtGlweSecretKey::generate(ring_params, rng);
            let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, table);
            shares.push(MasterSecretKeyShare::new(
                sk,
                dcrt_sk,
                Arc::clone(&self.table),
                Arc::clone(&self.params),
            ));
        }

        let mut sk = self.sk.clone();
        for share in shares.iter() {
            sk.iter_crt_poly_mut()
                .zip(share.sk.iter_crt_poly())
                .for_each(|(mut a, b)| {
                    a.sub_assign(&b, poly_length, moduli);
                });
        }

        let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, table);
        shares.push(MasterSecretKeyShare::new(
            sk,
            dcrt_sk,
            Arc::clone(&self.table),
            Arc::clone(&self.params),
        ));

        shares
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
        Table: DcrtTable<ValueT = CrtValueT>,
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
        Table: DcrtTable<ValueT = CrtValueT>,
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
        Table: DcrtTable<ValueT = CrtValueT>,
        A: RawData<Elem = CrtValueT> + DataMut,
    {
        self.dcrt_sk
            .encrypt_zeros_inplace(result, params, table, rng)
    }
}

#[derive(Clone)]
pub struct MasterSecretKeyShare {
    sk: CrtGlweSecretKey<CrtValueT>,
    dcrt_sk: DcrtGlweSecretKey<CrtValueT>,
    table: Arc<CrtTable>,
    params: Arc<SsleParameters>,
}

impl MasterSecretKeyShare {
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

    pub fn table(&self) -> &CrtTable {
        &self.table
    }

    pub fn phase_inplace<A, B>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        msg_mod_q: &mut DcrtPolynomial<B>,
    ) where
        A: RawData<Elem = CrtValueT> + Data,
        B: RawData<Elem = CrtValueT> + DataMut,
    {
        self.dcrt_sk
            .phase_inplace(ciphertext, msg_mod_q, self.params.ring_params());
    }

    pub fn phase_a_inplace<A, B>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        msg_mod_q: &mut DcrtPolynomial<B>,
    ) where
        A: RawData<Elem = CrtValueT> + Data,
        B: RawData<Elem = CrtValueT> + DataMut,
    {
        self.dcrt_sk
            .phase_a_inplace(ciphertext, msg_mod_q, self.params.ring_params())
    }
}

pub fn generate_dd_random<R>(
    party_count: usize,
    length: usize,
    params: &SsleParameters,
    rng: &mut R,
) -> Vec<(Vec<CrtValueT>, Vec<CrtValueT>)>
where
    R: rand::Rng + rand::CryptoRng,
{
    let ring_params = params.ring_params();
    let big_uint_value_len = ring_params.big_uint_value_len();

    let p = num::BigUint::from(ring_params.plain_modulus_value());

    let q = ring_params.base_q().moduli_product();
    let q_big = BigUint::from_slice(bytemuck::cast_slice(q.digits()));

    let q_prime_big = q_big.next_multiple_of(&p);
    let q_prime: primus_integer::BigUint<Vec<CrtValueT>> =
        primus_integer::BigUint(q_prime_big.iter_u64_digits().collect());

    let delta_prime_big = q_prime_big / &p;
    let delta_prime: primus_integer::BigUint<Vec<CrtValueT>> =
        primus_integer::BigUint(delta_prime_big.iter_u64_digits().collect());

    let distr = Uniform::new(0, 1 << 30).unwrap();

    let mut r_mod_delta_prime: Vec<CrtValueT> = vec![0; big_uint_value_len * length];
    let mut r_mod_q_prime: Vec<CrtValueT> = vec![0; big_uint_value_len * length];

    r_mod_delta_prime
        .chunks_exact_mut(big_uint_value_len)
        .zip(r_mod_q_prime.chunks_exact_mut(big_uint_value_len))
        .for_each(|(x, y)| {
            let r = distr.sample(rng);
            if rng.random() {
                x[0] = r;
                y[0] = r;
            } else if r != 0 {
                let _ = delta_prime.sub_value_inplace(r, &mut primus_integer::BigUint(x));
                let _ = q_prime.sub_value_inplace(r, &mut primus_integer::BigUint(y));
            }
        });

    let mut results = Vec::with_capacity(party_count);

    for _i in 0..party_count - 1 {
        let mut temp_mod_delta_prime: Vec<CrtValueT> = vec![0; big_uint_value_len * length];
        let mut temp_mod_q_prime: Vec<CrtValueT> = vec![0; big_uint_value_len * length];

        izip!(
            temp_mod_delta_prime.chunks_exact_mut(big_uint_value_len),
            temp_mod_q_prime.chunks_exact_mut(big_uint_value_len),
            r_mod_delta_prime.chunks_exact_mut(big_uint_value_len),
            r_mod_q_prime.chunks_exact_mut(big_uint_value_len)
        )
        .for_each(|(x, y, a, b)| {
            let r = distr.sample(rng);
            if rng.random() {
                x[0] = r;
                y[0] = r;
            } else if r != 0 {
                let _ = delta_prime.sub_value_inplace(r, &mut primus_integer::BigUint(&mut *x));
                let _ = q_prime.sub_value_inplace(r, &mut primus_integer::BigUint(&mut *y));
            }
            primus_integer::BigUint(a).sub_modulo_assign(&primus_integer::BigUint(x), &delta_prime);
            primus_integer::BigUint(b).sub_modulo_assign(&primus_integer::BigUint(y), &q_prime);
        });

        results.push((temp_mod_delta_prime, temp_mod_q_prime));
    }

    results.push((r_mod_delta_prime, r_mod_q_prime));

    results
}
